{- | Handlers for @/user@ session-scoped endpoints: get, update, logout.

Also hosts 'userPayloadFromUser', shared with "Hauth.Server.Auth" for webhook
payload construction; kept here because the user-mutating handlers (signup,
verify, update) all need it and Session is the more stable owner.
-}
module Hauth.Server.Session (
    getUserHandler,
    updateUserHandler,
    logoutHandler,
    userPayloadFromUser,
) where

import Control.Monad.Except (throwError)
import Control.Monad.IO.Class (liftIO)
import Control.Monad.Reader (ReaderT, ask)
import qualified Data.Aeson as Aeson
import qualified Data.Text as T
import Data.Time.Clock.POSIX (posixSecondsToUTCTime)
import qualified Data.UUID as UUID
import Database.PostgreSQL.Simple (withTransaction)
import Hauth.API.Auth (SessionPrincipal (..))
import Hauth.API.Types
import Hauth.Auth.Jwt (AccessTokenClaims (..))
import Hauth.Auth.Logout (LogoutError (..), resolveLogoutSession)
import Hauth.Auth.UserUpdate (UpdateUserError (..), validateUpdateRequest)
import Hauth.Crypto.Password (defaultArgon2Settings, hashPassword)
import Hauth.Env (AppEnv, withDatabaseConnection)
import Hauth.Server.Errors (supabaseErrorBody)
import Hauth.Session (
    SessionId (..),
    revokeSession,
 )
import Hauth.User (generateConfirmationToken)
import qualified Hauth.User as User
import Hauth.Webhooks.Events (SessionPayload (..), UserPayload (..), WebhookEvent (..))
import qualified Hauth.Webhooks.Outbox as Outbox
import Servant.API (NoContent (..))
import Servant.Server (Handler, ServerError (errBody), err401, err404, err422)

type AppHandler = ReaderT AppEnv Handler

getUserHandler :: SessionPrincipal -> AppHandler UserResponse
getUserHandler principal = do
    env <- ask
    let uidText = sessionUserId principal
    uid <- case UUID.fromText uidText of
        Nothing ->
            throwError
                err401
                    { errBody = supabaseErrorBody "invalid_user_id" "malformed user id in token"
                    }
        Just u -> pure u
    mUser <- liftIO (withDatabaseConnection env (`User.getUserById` User.UserId uid))
    case mUser of
        Nothing ->
            throwError
                err404
                    { errBody = supabaseErrorBody "user_not_found" "user not found"
                    }
        Just u -> pure (buildUserResponse u)

updateUserHandler :: SessionPrincipal -> UpdateUserRequest -> AppHandler UserResponse
updateUserHandler principal req = do
    env <- ask
    let uidText = sessionUserId principal
    uid <- case UUID.fromText uidText of
        Nothing ->
            throwError
                err401
                    { errBody = supabaseErrorBody "invalid_user_id" "malformed user id in token"
                    }
        Just u -> pure u
    (mEmail, mPassword, mData) <- case validateUpdateRequest req of
        Left (UpdateUserEmailInvalid e) ->
            throwError
                err422
                    { errBody = supabaseErrorBody "invalid_email" ("Email address is invalid: " <> e)
                    }
        Left (UpdateUserPasswordTooShort minLen _) ->
            throwError
                err422
                    { errBody =
                        supabaseErrorBody
                            "weak_password"
                            ("Password must be at least " <> T.pack (show minLen) <> " characters")
                    }
        Right triple -> pure triple
    mEncrypted <- case mPassword of
        Nothing -> pure Nothing
        Just pw -> liftIO (Just <$> hashPassword defaultArgon2Settings pw)
    mToken <- case mEmail of
        Nothing -> pure Nothing
        Just _ -> liftIO (Just <$> generateConfirmationToken)
    let upd =
            User.emptyUserUpdate
                { User.updateEmailChange = mEmail
                , User.updateEncryptedPassword = mEncrypted
                , User.updateRawUserMetaData = mData
                , User.updateEmailChangeToken = mToken
                }
    mUser <- liftIO $ withDatabaseConnection env \conn -> withTransaction conn do
        updated <- User.applyUserUpdate conn (User.UserId uid) upd
        case (updated, mPassword) of
            (Just u, Just _) -> Outbox.enqueue conn (PasswordChanged (userPayloadFromUser u))
            _ -> pure ()
        pure updated
    case mUser of
        Nothing ->
            throwError
                err404
                    { errBody = supabaseErrorBody "user_not_found" "user not found"
                    }
        Just u -> pure (buildUserResponse u)

logoutHandler ::
    SessionPrincipal ->
    Maybe T.Text ->
    AppHandler NoContent
logoutHandler principal _scope = do
    env <- ask
    let sidText = sessionAccessTokenId principal
        dummyClaims =
            AccessTokenClaims
                { claimSub = sessionUserId principal
                , claimRole = sessionRole principal
                , claimEmail = Nothing
                , claimPhone = Nothing
                , claimAppMetadata = Aeson.object []
                , claimUserMetadata = Aeson.object []
                , claimAal = "aal1"
                , claimAmr = []
                , claimSessionId = sidText
                , claimIssuedAt = posixSecondsToUTCTime 0
                , claimExpiresAt = posixSecondsToUTCTime 0
                }
    sid <- case resolveLogoutSession (Right dummyClaims) of
        Left (LogoutBadSessionId msg) ->
            throwError
                err401
                    { errBody = supabaseErrorBody "invalid_session_id" msg
                    }
        Left other ->
            throwError
                err401
                    { errBody = supabaseErrorBody "no_authorization" (T.pack (show other))
                    }
        Right s -> pure s
    let mUid = UUID.fromText (sessionUserId principal)
    liftIO $ withDatabaseConnection env \conn -> withTransaction conn do
        revokeSession conn sid
        case mUid of
            Just uid ->
                Outbox.enqueue
                    conn
                    (SessionRevoked SessionPayload{spSessionId = unSessionId sid, spUserId = uid})
            Nothing -> pure ()
    pure NoContent

userPayloadFromUser :: User.User -> UserPayload
userPayloadFromUser u =
    UserPayload
        { upUserId = User.unUserId (User.userId u)
        , upEmail = User.userEmail u
        , upCreatedAt = User.userCreatedAt u
        }
