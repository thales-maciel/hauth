module Hauth.Server.Admin (
    adminCreateUserHandler,
    adminDeleteUserHandler,
    adminGetUserHandler,
    adminInviteUserHandler,
    adminListIdentitiesHandler,
    adminListUsersHandler,
    adminUpdateUserHandler,
    adminUserNotFoundError,
    parseUserId,
) where

import Control.Monad.Except (throwError)
import Control.Monad.IO.Class (liftIO)
import Control.Monad.Reader (ReaderT, ask)
import qualified Crypto.Random as CR
import qualified Data.Aeson as Aeson
import qualified Data.ByteString.Base64.URL as B64URL
import Data.Maybe (fromMaybe, isJust)
import qualified Data.Text as T
import qualified Data.Text.Encoding as TE
import Data.Time.Clock (getCurrentTime)
import Data.UUID (UUID)
import qualified Data.UUID as UUID
import Database.PostgreSQL.Simple (withTransaction)
import Hauth.API.Auth (ServiceRolePrincipal)
import Hauth.API.Types (
    AdminCreateUserRequest (..),
    AdminUpdateUserRequest (..),
    DeletedUserResponse (..),
    Email (..),
    InviteUserRequest (..),
    ListIdentitiesResponse (..),
    ListUsersResponse (..),
    MessageResponse (..),
    Password (..),
    UserId (..),
    UserResponse,
    buildIdentityResponse,
    buildUserResponse,
 )
import Hauth.Auth.Admin (
    AdminError (..),
    Pagination (..),
    computeNextPage,
    parsePagination,
    validateAdminCreate,
    validateAdminUpdate,
    validateInvite,
 )
import Hauth.Config (Config (..), EmailConfig (..), SiteConfig (..))
import Hauth.Crypto.Password (defaultArgon2Settings, hashPassword)
import Hauth.Email (TemplateData (..), TemplateKind (..), renderEmailCached, sendEmail)
import Hauth.Env (AppEnv (..), LogLevel (..), logMessage, withDatabaseConnection)
import qualified Hauth.Identity as Identity
import Hauth.User (generateConfirmationToken)
import qualified Hauth.User as User
import qualified Hauth.Webhooks.Events as Events
import qualified Hauth.Webhooks.Outbox as Outbox
import Servant.Server (Handler, ServerError (errBody), err400, err404, err422)

type AppHandler = ReaderT AppEnv Handler

adminListUsersHandler :: ServiceRolePrincipal -> Maybe Int -> Maybe Int -> AppHandler ListUsersResponse
adminListUsersHandler _ mPage mPerPage = do
    env <- ask
    let pag = parsePagination mPage mPerPage
        lim = pagPerPage pag
        off = (pagPage pag - 1) * pagPerPage pag
    (users, total) <- liftIO $ withDatabaseConnection env \conn -> do
        us <- User.listUsers conn lim off
        n <- User.countUsers conn
        pure (us, n)
    let nextPage = computeNextPage pag total
    pure
        ListUsersResponse
            { listUsers = fmap buildUserResponse users
            , listUsersAud = "authenticated"
            , listUsersNextPage = nextPage
            }

adminCreateUserHandler :: ServiceRolePrincipal -> AdminCreateUserRequest -> AppHandler UserResponse
adminCreateUserHandler _ req = do
    case validateAdminCreate req of
        Left AdminEmailRequired ->
            throwError
                err400
                    { errBody =
                        Aeson.encode $
                            Aeson.object
                                [ "error" Aeson..= ("email_required" :: T.Text)
                                , "msg" Aeson..= ("Email is required" :: T.Text)
                                ]
                    }
        Left (AdminEmailInvalid e) ->
            throwError
                err422
                    { errBody =
                        Aeson.encode $
                            Aeson.object
                                [ "error" Aeson..= ("invalid_email" :: T.Text)
                                , "msg" Aeson..= ("Email address is invalid: " <> e)
                                ]
                    }
        Left (AdminPasswordPolicy minLen _) ->
            throwError
                err422
                    { errBody =
                        Aeson.encode $
                            Aeson.object
                                [ "error" Aeson..= ("weak_password" :: T.Text)
                                , "msg" Aeson..= ("Password must be at least " <> T.pack (show minLen) <> " characters")
                                ]
                    }
        Left AdminUserNotFound ->
            throwError err404
        Left (AdminRoleReserved _) ->
            -- Unreachable today: AdminCreateUserRequest has no role field.
            -- Guarded explicitly so future role-on-create stays consistent
            -- with the update-side wire shape.
            throwError err400
        Right () -> pure ()
    env <- ask
    let emailText = unEmail (adminCreateUserEmail req)
        mPassword = fmap unPassword (adminCreateUserPassword req)
        confirmEmail = adminCreateUserConfirmed req
        userMeta = fromMaybe (Aeson.object []) (adminCreateUserUserMetadata req)
        appMeta = adminCreateUserAppMetadata req
    passwordText <- case mPassword of
        Just pw -> pure pw
        Nothing -> do
            bytes <- liftIO (CR.getRandomBytes 24)
            pure $ TE.decodeUtf8 (B64URL.encodeUnpadded bytes)
    encrypted <- liftIO (hashPassword defaultArgon2Settings passwordText)
    let newUser =
            User.NewUser
                { User.newUserEmail = emailText
                , User.newUserEncryptedPassword = encrypted
                , User.newUserConfirmationToken = Nothing
                , User.newUserUserMetadata = userMeta
                , User.newUserAud = "authenticated"
                }
    user <- liftIO $
        withDatabaseConnection env \conn ->
            withTransaction conn do
                existing <- User.getUserByEmail conn emailText
                case existing of
                    Just _ -> pure (Left ())
                    Nothing -> Right <$> User.createUser conn newUser
    created <- case user of
        Left () ->
            throwError
                err422
                    { errBody =
                        Aeson.encode $
                            Aeson.object
                                [ "error" Aeson..= ("email_exists" :: T.Text)
                                , "msg" Aeson..= ("Email address already in use" :: T.Text)
                                ]
                    }
        Right u -> pure u
    let needsUpdate = confirmEmail || isJust appMeta
    nowCreate <- liftIO getCurrentTime
    finalUser <-
        if needsUpdate
            then do
                let upd =
                        User.emptyUserUpdate
                            { User.updateEmailConfirmedAt =
                                if confirmEmail
                                    then Just (Just nowCreate)
                                    else Nothing
                            , User.updateRawAppMetaData = appMeta
                            }
                mUpdated <- liftIO $ withDatabaseConnection env \conn ->
                    User.applyUserUpdate conn (User.userId created) upd
                pure (fromMaybe created mUpdated)
            else pure created
    liftIO $
        withDatabaseConnection env \conn ->
            Outbox.enqueue conn $
                Events.UserAdminCreated
                    Events.UserPayload
                        { Events.upUserId = User.unUserId (User.userId finalUser)
                        , Events.upEmail = User.userEmail finalUser
                        , Events.upCreatedAt = User.userCreatedAt finalUser
                        }
    pure (buildUserResponse finalUser)

adminGetUserHandler :: ServiceRolePrincipal -> UserId -> AppHandler UserResponse
adminGetUserHandler _ (UserId uidText) = do
    uid <- parseUserId uidText
    env <- ask
    mUser <- liftIO $ withDatabaseConnection env (`User.getUserById` User.UserId uid)
    case mUser of
        Nothing -> throwError adminUserNotFoundError
        Just u -> pure (buildUserResponse u)

adminUpdateUserHandler :: ServiceRolePrincipal -> UserId -> AdminUpdateUserRequest -> AppHandler UserResponse
adminUpdateUserHandler _ (UserId uidText) req = do
    case validateAdminUpdate req of
        Left AdminEmailRequired ->
            throwError
                err400
                    { errBody =
                        Aeson.encode $
                            Aeson.object
                                [ "error" Aeson..= ("email_required" :: T.Text)
                                , "msg" Aeson..= ("Email is required" :: T.Text)
                                ]
                    }
        Left (AdminEmailInvalid e) ->
            throwError
                err422
                    { errBody =
                        Aeson.encode $
                            Aeson.object
                                [ "error" Aeson..= ("invalid_email" :: T.Text)
                                , "msg" Aeson..= ("Email address is invalid: " <> e)
                                ]
                    }
        Left (AdminPasswordPolicy minLen _) ->
            throwError
                err422
                    { errBody =
                        Aeson.encode $
                            Aeson.object
                                [ "error" Aeson..= ("weak_password" :: T.Text)
                                , "msg" Aeson..= ("Password must be at least " <> T.pack (show minLen) <> " characters")
                                ]
                    }
        Left (AdminRoleReserved r) ->
            throwError
                err422
                    { errBody =
                        Aeson.encode $
                            Aeson.object
                                [ "error" Aeson..= ("role_not_allowed" :: T.Text)
                                , "msg" Aeson..= ("Role '" <> r <> "' is reserved and cannot be assigned to a user")
                                ]
                    }
        Left AdminUserNotFound ->
            throwError adminUserNotFoundError
        Right () -> pure ()
    uid <- parseUserId uidText
    env <- ask
    mEncrypted <- case adminUpdateUserPassword req of
        Nothing -> pure Nothing
        Just (Password pw) -> liftIO (Just <$> hashPassword defaultArgon2Settings pw)
    now <- liftIO getCurrentTime
    let resolvedEmailConfirmedAt = case adminUpdateUserEmailConfirm req of
            Nothing -> Nothing
            Just True -> Just (Just now)
            Just False -> Just Nothing
        upd =
            User.emptyUserUpdate
                { User.updateEmailChange = fmap unEmail (adminUpdateUserEmail req)
                , User.updateEncryptedPassword = mEncrypted
                , User.updateRawUserMetaData = adminUpdateUserUserMetadata req
                , User.updateRawAppMetaData = adminUpdateUserAppMetadata req
                , User.updateEmailConfirmedAt = resolvedEmailConfirmedAt
                , User.updateBannedUntil = fmap Just (adminUpdateUserBannedUntil req)
                , User.updateRole = adminUpdateUserRole req
                }
    mUser <- liftIO $ withDatabaseConnection env \conn ->
        User.applyUserUpdate conn (User.UserId uid) upd
    case mUser of
        Nothing -> throwError adminUserNotFoundError
        Just u -> do
            liftIO $
                withDatabaseConnection env \conn ->
                    Outbox.enqueue conn $
                        Events.UserAdminUpdated
                            Events.UserPayload
                                { Events.upUserId = User.unUserId (User.userId u)
                                , Events.upEmail = User.userEmail u
                                , Events.upCreatedAt = User.userCreatedAt u
                                }
            pure (buildUserResponse u)

adminDeleteUserHandler :: ServiceRolePrincipal -> UserId -> AppHandler DeletedUserResponse
adminDeleteUserHandler _ (UserId uidText) = do
    uid <- parseUserId uidText
    env <- ask
    mUser <- liftIO $ withDatabaseConnection env \conn ->
        User.softDeleteUser conn (User.UserId uid)
    case mUser of
        Nothing -> throwError adminUserNotFoundError
        Just u -> do
            liftIO $
                withDatabaseConnection env \conn ->
                    Outbox.enqueue conn $
                        Events.UserDeleted
                            Events.UserPayload
                                { Events.upUserId = User.unUserId (User.userId u)
                                , Events.upEmail = User.userEmail u
                                , Events.upCreatedAt = User.userCreatedAt u
                                }
            pure DeletedUserResponse{deletedUser = buildUserResponse u}

adminListIdentitiesHandler :: ServiceRolePrincipal -> UserId -> AppHandler ListIdentitiesResponse
adminListIdentitiesHandler _ (UserId uidText) = do
    uid <- parseUserId uidText
    env <- ask
    mUser <- liftIO $ withDatabaseConnection env (`User.getUserById` User.UserId uid)
    case mUser of
        Nothing -> throwError adminUserNotFoundError
        Just _ -> do
            identities <- liftIO $ withDatabaseConnection env (`Identity.listUserIdentities` uid)
            pure
                ListIdentitiesResponse
                    { listIdentities = fmap buildIdentityResponse identities
                    }

adminInviteUserHandler :: ServiceRolePrincipal -> InviteUserRequest -> AppHandler MessageResponse
adminInviteUserHandler _ req = do
    case validateInvite req of
        Left AdminEmailRequired ->
            throwError
                err400
                    { errBody =
                        Aeson.encode $
                            Aeson.object
                                [ "error" Aeson..= ("email_required" :: T.Text)
                                , "msg" Aeson..= ("Email is required" :: T.Text)
                                ]
                    }
        Left (AdminEmailInvalid e) ->
            throwError
                err422
                    { errBody =
                        Aeson.encode $
                            Aeson.object
                                [ "error" Aeson..= ("invalid_email" :: T.Text)
                                , "msg" Aeson..= ("Email address is invalid: " <> e)
                                ]
                    }
        Left _ -> throwError err400
        Right () -> pure ()
    env <- ask
    let AppEnv{appConfig, appLogger} = env
        Config{configEmail, configSite = SiteConfig{siteUrl}} = appConfig
        EmailConfig{emailFrom} = configEmail
        emailText = unEmail (inviteUserEmail req)
        userMeta = fromMaybe (Aeson.object []) (inviteUserData req)
    token <- liftIO generateConfirmationToken
    let newUser =
            User.NewUser
                { User.newUserEmail = emailText
                , User.newUserEncryptedPassword = ""
                , User.newUserConfirmationToken = Just token
                , User.newUserUserMetadata = userMeta
                , User.newUserAud = "authenticated"
                }
    _created <- liftIO $
        withDatabaseConnection env \conn ->
            withTransaction conn do
                existing <- User.getUserByEmail conn emailText
                case existing of
                    Just u -> pure u
                    Nothing -> User.createUser conn newUser
    let actionUrl = siteUrl <> "/auth/v1/verify?token=" <> token <> "&type=invite"
        tdata =
            TemplateData
                { templateRecipientEmail = emailText
                , templateActionUrl = actionUrl
                , templateSiteUrl = siteUrl
                , templateTokenHash = token
                }
    rendered <- liftIO (renderEmailCached (appTemplateCache env) Invite emailFrom tdata)
    case rendered of
        Left err ->
            liftIO $
                logMessage appLogger LogWarn $
                    "adminInviteUserHandler: renderEmail failed: " <> T.pack (show err)
        Right msg -> do
            result <- liftIO (sendEmail (appEmailSender env) msg)
            case result of
                Left err ->
                    liftIO $
                        logMessage appLogger LogWarn $
                            "adminInviteUserHandler: email send failed: " <> T.pack (show err)
                Right () -> pure ()
    pure MessageResponse{message = "Invite email sent"}

parseUserId :: T.Text -> AppHandler UUID
parseUserId uidText =
    case UUID.fromText uidText of
        Nothing ->
            throwError
                err400
                    { errBody =
                        Aeson.encode $
                            Aeson.object
                                [ "error" Aeson..= ("invalid_user_id" :: T.Text)
                                , "msg" Aeson..= ("malformed user id" :: T.Text)
                                ]
                    }
        Just uid -> pure uid

adminUserNotFoundError :: ServerError
adminUserNotFoundError =
    err404
        { errBody =
            Aeson.encode $
                Aeson.object
                    [ "error" Aeson..= ("user_not_found" :: T.Text)
                    , "msg" Aeson..= ("User not found" :: T.Text)
                    ]
        }
