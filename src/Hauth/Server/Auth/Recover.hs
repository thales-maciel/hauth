{- | @\/recover@ endpoint handler.

Sends a password-reset email if the address belongs to a user with a
password set. Always returns the same anti-enumeration message so callers
can't probe for registered accounts.
-}
module Hauth.Server.Auth.Recover (
    recoverHandler,
) where

import Control.Monad (unless)
import Control.Monad.IO.Class (liftIO)
import Control.Monad.Reader (ask)
import qualified Data.Text as T
import Hauth.API.Auth (AnonymousPrincipal)
import Hauth.API.Types
import Hauth.Auth.Recovery (recoverySentMessage, validateRecoverRequest)
import Hauth.Config (Config (..), EmailConfig (..), SiteConfig (..))
import Hauth.Email (EmailSender (..), TemplateData (..), TemplateKind (..), renderEmailCached, sendEmail, stubSender)
import Hauth.Env (AppEnv (..), LogLevel (..), logMessage, withDatabaseConnection)
import Hauth.Server.Auth.Session (AppHandler)
import Hauth.Session (
    generateOpaqueToken,
 )
import qualified Hauth.User as User

recoverHandler :: AnonymousPrincipal -> RecoverRequest -> AppHandler MessageResponse
recoverHandler _ req = do
    env <- ask
    let AppEnv{appConfig, appLogger} = env
        Config{configEmail, configSite = SiteConfig{siteUrl}} = appConfig
        EmailConfig{emailFrom} = configEmail
    emailText <- case validateRecoverRequest req of
        Left _ ->
            pure ""
        Right e -> pure e
    unless (T.null emailText) $ do
        mUser <- liftIO (withDatabaseConnection env (`User.getUserByEmail` emailText))
        case mUser of
            Nothing -> pure ()
            Just user ->
                case User.userEncryptedPassword user of
                    Nothing -> pure ()
                    Just _ -> do
                        token <- liftIO generateOpaqueToken
                        liftIO $ withDatabaseConnection env \conn ->
                            User.setRecoveryToken conn (User.userId user) token
                        let actionUrl = siteUrl <> "/auth/v1/verify?token=" <> token <> "&type=recovery"
                            tdata =
                                TemplateData
                                    { templateRecipientEmail = emailText
                                    , templateActionUrl = actionUrl
                                    , templateSiteUrl = siteUrl
                                    , templateTokenHash = token
                                    }
                        rendered <- liftIO (renderEmailCached (appTemplateCache env) Recovery emailFrom tdata)
                        case rendered of
                            Left err ->
                                liftIO $
                                    logMessage appLogger LogWarn $
                                        "recoverHandler: renderEmail failed: " <> T.pack (show err)
                            Right msg -> do
                                result <- liftIO (sendEmail stubSender msg)
                                case result of
                                    Left err ->
                                        liftIO $
                                            logMessage appLogger LogWarn $
                                                "recoverHandler: email send failed: " <> T.pack (show err)
                                    Right () -> pure ()
    pure MessageResponse{message = recoverySentMessage}
