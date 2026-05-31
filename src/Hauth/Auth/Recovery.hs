{- | Pure helpers for the password-recovery flow.

These functions are intentionally pure so they can be unit-tested without a
live database or HTTP server.
-}
module Hauth.Auth.Recovery (
    RecoveryError (..),
    recoverySentMessage,
    validateRecoverRequest,
    validateRecoveryVerify,
) where

import Data.Text (Text)
import qualified Data.Text as T
import Hauth.API.Types (Email (..), RecoverRequest (..), VerifyRequest (..))
import Hauth.Crypto.Password (
    PasswordPolicyError (..),
    checkPasswordPolicy,
    defaultPasswordPolicy,
 )

-- | Errors that can occur during recovery request validation.
data RecoveryError
    = RecoveryMissingEmail
    | RecoveryPasswordTooShort Int Int
    | RecoveryMissingToken
    deriving stock (Eq, Show)

{- | The anti-enumeration message returned by @POST \/recover@ regardless of
whether an account exists for the supplied email address.
-}
recoverySentMessage :: Text
recoverySentMessage =
    "If an account exists for this email, a recovery email has been sent."

{- | Validate the @POST \/recover@ request body.

Returns the email address on success, or 'RecoveryMissingEmail' when the
email field is empty.
-}
validateRecoverRequest :: RecoverRequest -> Either RecoveryError Text
validateRecoverRequest RecoverRequest{recoverEmail} =
    let emailText = unEmail recoverEmail
     in if T.null (T.strip emailText)
            then Left RecoveryMissingEmail
            else Right emailText

{- | Validate the @POST \/verify@ body when @type=recovery@.

Checks that:

1. The token field is non-empty.
2. The password field is non-empty and satisfies 'defaultPasswordPolicy'.

Returns @(token, password)@ on success.
-}
validateRecoveryVerify :: VerifyRequest -> Either RecoveryError (Text, Text)
validateRecoveryVerify VerifyRequest{verifyToken, verifyPassword} =
    if T.null verifyToken
        then Left RecoveryMissingToken
        else case verifyPassword of
            Nothing ->
                Left (RecoveryPasswordTooShort minLen 0)
            Just pw ->
                case checkPasswordPolicy defaultPasswordPolicy pw of
                    Left (PasswordTooShort policyMin actual) ->
                        Left (RecoveryPasswordTooShort policyMin actual)
                    Right () ->
                        Right (verifyToken, pw)
  where
    minLen = 8
