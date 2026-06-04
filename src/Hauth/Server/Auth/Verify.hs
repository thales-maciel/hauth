{- | @\/verify@ endpoint handler.

Dispatches between signup and recovery confirmation flows based on the
@type@ field; both terminate by issuing a fresh session for the verified
user via 'issueSessionForUser'.
-}
module Hauth.Server.Auth.Verify (
    verifyHandler,
    handleSignupVerify,
    handleRecoveryVerify,
) where

import Control.Monad.Except (throwError)
import Control.Monad.IO.Class (liftIO)
import Control.Monad.Reader (ask)
import qualified Data.Aeson as Aeson
import qualified Data.Text as T
import Database.PostgreSQL.Simple (withTransaction)
import Hauth.API.Auth (AnonymousPrincipal)
import Hauth.API.Types
import Hauth.Auth.Recovery (RecoveryError (..), validateRecoveryVerify)
import Hauth.Auth.Verify (OtpType (..), VerifyError (..), classifyVerifyRequest)
import Hauth.Crypto.Password (defaultArgon2Settings, hashPassword)
import Hauth.Env (withDatabaseConnection)
import Hauth.Server.Auth.Session (AppHandler, issueSessionForUser)
import Hauth.Server.Auth.VerifyError (verifyErrorBody)
import Hauth.Server.Errors (oauth2ErrorBody)
import Hauth.Server.Session (userPayloadFromUser)
import qualified Hauth.User as User
import Hauth.Webhooks.Events (WebhookEvent (..))
import qualified Hauth.Webhooks.Outbox as Outbox
import Servant.Server (ServerError (errBody), err400, err401, err422)

verifyHandler :: AnonymousPrincipal -> VerifyRequest -> AppHandler SessionResponse
verifyHandler _ req =
    case classifyVerifyRequest req of
        Left VerifyMissingToken ->
            throwError
                err400
                    { errBody = Aeson.encode (verifyErrorBody "otp_expired" "Token has expired or is invalid")
                    }
        Left (VerifyUnsupportedOtpType t) ->
            throwError
                err400
                    { errBody = Aeson.encode (verifyErrorBody "unsupported_otp_type" ("Unsupported OTP type: " <> t))
                    }
        Left VerifyOtpExpired ->
            throwError
                err401
                    { errBody = Aeson.encode (verifyErrorBody "otp_expired" "Token has expired or is invalid")
                    }
        Right OtpSignup ->
            handleSignupVerify req
        Right OtpRecovery ->
            handleRecoveryVerify req
        Right _ ->
            throwError
                err400
                    { errBody = Aeson.encode (verifyErrorBody "unsupported_otp_type" "OTP type not yet implemented")
                    }

handleSignupVerify :: VerifyRequest -> AppHandler SessionResponse
handleSignupVerify VerifyRequest{verifyToken} = do
    env <- ask
    mUser <- liftIO (withDatabaseConnection env (`User.getUserByConfirmationToken` verifyToken))
    user <- case mUser of
        Nothing ->
            throwError
                err401
                    { errBody = Aeson.encode (verifyErrorBody "otp_expired" "Token has expired or is invalid")
                    }
        Just u -> pure u
    liftIO $ withDatabaseConnection env \conn -> withTransaction conn do
        User.markEmailConfirmed conn (User.userId user)
        Outbox.enqueue conn (UserEmailConfirmed (userPayloadFromUser user))
    issueSessionForUser user "otp"

handleRecoveryVerify :: VerifyRequest -> AppHandler SessionResponse
handleRecoveryVerify req = do
    (token, password) <- case validateRecoveryVerify req of
        Left RecoveryMissingToken ->
            throwError
                err401
                    { errBody = oauth2ErrorBody "otp_expired" "Token is missing"
                    }
        Left (RecoveryPasswordTooShort minLen _) ->
            throwError
                err422
                    { errBody =
                        oauth2ErrorBody
                            "weak_password"
                            ("Password must be at least " <> T.pack (show minLen) <> " characters")
                    }
        Left RecoveryMissingEmail ->
            throwError
                err400
                    { errBody = oauth2ErrorBody "invalid_request" "Invalid request"
                    }
        Right pair -> pure pair
    env <- ask
    mUser <- liftIO (withDatabaseConnection env (`User.getUserByRecoveryToken` token))
    user <- case mUser of
        Nothing ->
            throwError
                err401
                    { errBody = oauth2ErrorBody "otp_expired" "Token has expired or is invalid"
                    }
        Just u -> pure u
    phc <- liftIO (hashPassword defaultArgon2Settings password)
    liftIO $ withDatabaseConnection env \conn -> withTransaction conn do
        User.applyPasswordReset conn (User.userId user) phc
        Outbox.enqueue conn (UserRecovered (userPayloadFromUser user))
    issueSessionForUser user "recovery"
