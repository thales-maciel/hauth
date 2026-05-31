{- | Pure dispatch helpers for the @\/verify@ and @\/resend@ endpoints.

Provides OTP type classification and request validation without any IO,
so the logic is fully unit-testable.
-}
module Hauth.Auth.Verify (
    OtpType (..),
    VerifyError (..),
    classifyVerifyRequest,
    parseOtpType,
) where

import Data.Text (Text)
import Hauth.API.Types (VerifyRequest (..))

-- | The set of OTP types recognised by the @\/verify@ endpoint.
data OtpType
    = OtpSignup
    | OtpRecovery
    | OtpMagicLink
    | OtpInvite
    | OtpEmailChange
    deriving stock (Eq, Show)

-- | Errors that can arise during verify request classification.
data VerifyError
    = -- | The @type@ field names an unrecognised OTP kind.
      VerifyUnsupportedOtpType Text
    | -- | The @token@ field is empty or absent.
      VerifyMissingToken
    | -- | No user was found for the supplied token.
      VerifyOtpExpired
    deriving stock (Eq, Show)

-- | Parse the @type@ string from a verify request.
parseOtpType :: Text -> Either VerifyError OtpType
parseOtpType "signup" = Right OtpSignup
parseOtpType "recovery" = Right OtpRecovery
parseOtpType "magiclink" = Right OtpMagicLink
parseOtpType "invite" = Right OtpInvite
parseOtpType "email_change" = Right OtpEmailChange
parseOtpType other = Left (VerifyUnsupportedOtpType other)

{- | Validate the shape of a 'VerifyRequest' and return the 'OtpType'.

Checks:
1. The @token@ field is non-empty.
2. The @type@ field is a known OTP kind.
-}
classifyVerifyRequest :: VerifyRequest -> Either VerifyError OtpType
classifyVerifyRequest VerifyRequest{verifyToken, verifyType}
    | verifyToken == "" = Left VerifyMissingToken
    | otherwise = parseOtpType verifyType
