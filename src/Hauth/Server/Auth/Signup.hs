-- | @\/signup@ endpoint handler.
module Hauth.Server.Auth.Signup (
    signupHandler,
) where

import Control.Monad.Except (throwError)
import Control.Monad.IO.Class (liftIO)
import Control.Monad.Reader (ask)
import qualified Data.Aeson as Aeson
import qualified Data.Aeson.KeyMap as KeyMap
import Data.Maybe (fromMaybe)
import qualified Data.Text as T
import Database.PostgreSQL.Simple (withTransaction)
import Hauth.API.Auth (AnonymousPrincipal)
import Hauth.API.Types
import Hauth.Config (Config (..), EmailConfig (..), SiteConfig (..))
import Hauth.Crypto.Password (defaultArgon2Settings, hashPassword)
import Hauth.Email (EmailSender (..), TemplateData (..), TemplateKind (..), renderEmailCached, sendEmail)
import Hauth.Env (AppEnv (..), LogLevel (..), logMessage, withDatabaseConnection)
import Hauth.Hooks.Runner (HookDecision (..), runHook)
import Hauth.Hooks.Types (HookPoint (..), loadHookConfig)
import Hauth.Server.Auth.Session (AppHandler)
import Hauth.Server.Errors (supabaseErrorBody)
import Hauth.Server.Session (userPayloadFromUser)
import Hauth.User (
    SignupError (..),
    generateConfirmationToken,
    validateSignupEmail,
    validateSignupPassword,
 )
import qualified Hauth.User as User
import Hauth.Webhooks.Events (WebhookEvent (..))
import qualified Hauth.Webhooks.Outbox as Outbox
import Servant.Server (ServerError (errBody), err400, err422)

signupHandler :: AnonymousPrincipal -> SignupRequest -> AppHandler SignupResponse
signupHandler _ SignupRequest{signupEmail, signupPassword, signupData} = do
    env <- ask
    let emailText = unEmail signupEmail
        passwordText = unPassword signupPassword
    validatedEmail <- case validateSignupEmail emailText of
        Left _ ->
            throwError
                err400
                    { errBody = supabaseErrorBody "invalid_email" "Email address is invalid"
                    }
        Right e -> pure e
    validatedPassword <- case validateSignupPassword passwordText of
        Left (SignupPasswordTooShort minLen _) ->
            throwError
                err422
                    { errBody =
                        supabaseErrorBody
                            "weak_password"
                            ("Password must be at least " <> T.pack (show minLen) <> " characters")
                    }
        Left _ ->
            throwError err422{errBody = supabaseErrorBody "weak_password" "Password is too weak"}
        Right p -> pure p
    let proposedMetadata = fromMaybe (Aeson.object []) signupData
    -- Run before-user-created hook outside the transaction (hook can't see the new row).
    effectiveMetadata <- do
        mHookCfg <- liftIO $ withDatabaseConnection env (`loadHookConfig` HookBeforeUserCreated)
        case mHookCfg of
            Nothing -> pure proposedMetadata
            Just hookCfg -> do
                let hookPayload =
                        Aeson.object
                            [ "email" Aeson..= emailText
                            , "phone" Aeson..= (Nothing :: Maybe T.Text)
                            , "user_metadata" Aeson..= proposedMetadata
                            , "ip" Aeson..= (Nothing :: Maybe T.Text)
                            ]
                decision <- liftIO (runHook (appHookHttpManager env) hookCfg hookPayload)
                case decision of
                    HookAllow -> pure proposedMetadata
                    HookAllowWith (Aeson.Object overlay) ->
                        -- Merge overlay.user_metadata into proposed metadata; ignore other fields.
                        case KeyMap.lookup "user_metadata" overlay of
                            Just (Aeson.Object extra) ->
                                case proposedMetadata of
                                    Aeson.Object base -> pure (Aeson.Object (KeyMap.union extra base))
                                    _ -> pure (Aeson.Object extra)
                            _ -> pure proposedMetadata
                    HookAllowWith _ -> pure proposedMetadata
                    HookReject reason ->
                        -- One-off wire shape: {"error", "message"}. Documented
                        -- as inconsistency follow-up; left inline because no
                        -- other site emits it.
                        throwError
                            err400
                                { errBody =
                                    Aeson.encode $
                                        Aeson.object
                                            [ "error" Aeson..= ("hook_rejected" :: T.Text)
                                            , "message" Aeson..= reason
                                            ]
                                }
    user <- liftIO $
        withDatabaseConnection env \conn ->
            withTransaction conn do
                existing <- User.getUserByEmail conn validatedEmail
                case existing of
                    Just _ ->
                        pure (Left SignupEmailExists)
                    Nothing -> do
                        encrypted <- hashPassword defaultArgon2Settings validatedPassword
                        token <- generateConfirmationToken
                        let newUser =
                                User.NewUser
                                    { User.newUserEmail = validatedEmail
                                    , User.newUserEncryptedPassword = encrypted
                                    , User.newUserConfirmationToken = Just token
                                    , User.newUserUserMetadata = effectiveMetadata
                                    , User.newUserAud = "authenticated"
                                    }
                        created <- User.createUser conn newUser
                        Outbox.enqueue conn (UserSignedUp (userPayloadFromUser created))
                        pure (Right created)
    case user of
        Left SignupEmailExists ->
            throwError
                err422
                    { errBody = supabaseErrorBody "email_exists" "Email address already in use"
                    }
        Left _ ->
            throwError err400{errBody = supabaseErrorBody "signup_failed" "Signup failed"}
        Right created -> do
            liftIO (sendConfirmationEmail env created)
            pure (buildSignupResponse created)

{- | Send the signup confirmation email after user creation.
Failures are logged at WARN; signup still succeeds so the user can use /resend.
-}
sendConfirmationEmail :: AppEnv -> User.User -> IO ()
sendConfirmationEmail env user = do
    let AppEnv{appConfig, appLogger} = env
        Config{configEmail, configSite = SiteConfig{siteUrl}} = appConfig
        EmailConfig{emailFrom} = configEmail
        mToken = User.userConfirmationToken user
    case (User.userEmail user, mToken) of
        (Just recipientEmail, Just token) -> do
            let actionUrl = siteUrl <> "/auth/confirm?token=" <> token
                tdata =
                    TemplateData
                        { templateRecipientEmail = recipientEmail
                        , templateActionUrl = actionUrl
                        , templateSiteUrl = siteUrl
                        , templateTokenHash = token
                        }
            rendered <- renderEmailCached (appTemplateCache env) Confirmation emailFrom tdata
            case rendered of
                Left err ->
                    logMessage appLogger LogWarn $
                        "signupHandler: failed to render confirmation email: " <> T.pack (show err)
                Right msg -> do
                    result <- sendEmail (appEmailSender env) msg
                    case result of
                        Left err ->
                            logMessage appLogger LogWarn $
                                "signupHandler: confirmation email delivery failed for "
                                    <> recipientEmail
                                    <> ": "
                                    <> T.pack (show err)
                        Right () -> pure ()
        _ -> pure ()
