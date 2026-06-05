{- | @\/resend@ endpoint handler.

Re-issues the signup confirmation email for unconfirmed users. Always
returns the same anti-enumeration message so callers can't probe for
registered accounts or confirmation status.
-}
module Hauth.Server.Auth.Resend (
    resendHandler,
) where

import Control.Monad.Except (throwError)
import Control.Monad.IO.Class (liftIO)
import Control.Monad.Reader (ask)
import qualified Data.Aeson as Aeson
import Data.Maybe (isJust)
import qualified Data.Text as T
import Hauth.API.Auth (AnonymousPrincipal)
import Hauth.API.Types
import Hauth.Auth.Verify (OtpType (..), VerifyError (..), parseOtpType)
import Hauth.Config (Config (..), EmailConfig (..), SiteConfig (..))
import Hauth.Email (EmailSender (..), TemplateData (..), TemplateKind (..), renderEmailCached, sendEmail)
import Hauth.Env (AppEnv (..), LogLevel (..), logMessage, withDatabaseConnection)
import Hauth.Server.Auth.Session (AppHandler)
import Hauth.Server.Auth.VerifyError (verifyErrorBody)
import Hauth.Server.Errors (oauth2ErrorOnly)
import Hauth.User (
    generateConfirmationToken,
 )
import qualified Hauth.User as User
import Servant.Server (ServerError (errBody), err400)

resendHandler :: AnonymousPrincipal -> ResendRequest -> AppHandler MessageResponse
resendHandler _ ResendRequest{resendEmail, resendType} =
    case parseOtpType resendType of
        Left (VerifyUnsupportedOtpType t) ->
            throwError
                err400
                    { errBody = Aeson.encode (verifyErrorBody "unsupported_otp_type" ("Unsupported OTP type: " <> t))
                    }
        Left _ ->
            throwError err400{errBody = oauth2ErrorOnly "unsupported_otp_type"}
        Right OtpSignup ->
            handleSignupResend (unEmail resendEmail)
        Right _ ->
            throwError
                err400
                    { errBody = Aeson.encode (verifyErrorBody "unsupported_otp_type" "OTP type not yet implemented")
                    }

handleSignupResend :: T.Text -> AppHandler MessageResponse
handleSignupResend emailText = do
    env <- ask
    let AppEnv{appConfig, appLogger} = env
        Config{configEmail, configSite} = appConfig
        antiEnumMsg = MessageResponse "Verification email sent if needed"
    mUser <- liftIO (withDatabaseConnection env (`User.getUserByEmail` emailText))
    case mUser of
        Nothing ->
            pure antiEnumMsg
        Just user
            | isJust (User.userEmailConfirmedAt user) ->
                pure antiEnumMsg
            | otherwise -> do
                newToken <- liftIO generateConfirmationToken
                liftIO $
                    withDatabaseConnection env \conn ->
                        User.setConfirmationToken conn (User.userId user) newToken
                let tdata =
                        TemplateData
                            { templateRecipientEmail = emailText
                            , templateActionUrl =
                                siteUrl configSite
                                    <> "/auth/confirm?token="
                                    <> newToken
                            , templateSiteUrl = siteUrl configSite
                            , templateTokenHash = newToken
                            }
                rendered <- liftIO (renderEmailCached (appTemplateCache env) Confirmation (emailFrom configEmail) tdata)
                case rendered of
                    Left _ ->
                        liftIO (logMessage appLogger LogWarn "resend: failed to render confirmation email")
                    Right msg -> do
                        sendResult <- liftIO (sendEmail (appEmailSender env) msg)
                        case sendResult of
                            Left err ->
                                liftIO $
                                    logMessage
                                        appLogger
                                        LogWarn
                                        ("resend: email delivery failed: " <> T.pack (show err))
                            Right () -> pure ()
                pure antiEnumMsg
