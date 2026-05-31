module Spec.Auth.VerifySpec (runSpec) where

import Data.Aeson (Object, Value (..))
import qualified Data.Aeson as Aeson
import qualified Data.Aeson.KeyMap as KeyMap
import Hauth.API.Types (
    MessageResponse (..),
    VerifyRequest (..),
 )
import Hauth.Auth.Verify (
    OtpType (..),
    VerifyError (..),
    classifyVerifyRequest,
    parseOtpType,
 )
import Spec.TestUtils (assertEqual)

runSpec :: IO ()
runSpec = do
    assertEqual
        "parseOtpType signup"
        (Right OtpSignup)
        (parseOtpType "signup")
    assertEqual
        "parseOtpType recovery"
        (Right OtpRecovery)
        (parseOtpType "recovery")
    assertEqual
        "parseOtpType magiclink"
        (Right OtpMagicLink)
        (parseOtpType "magiclink")
    assertEqual
        "parseOtpType invite"
        (Right OtpInvite)
        (parseOtpType "invite")
    assertEqual
        "parseOtpType email_change"
        (Right OtpEmailChange)
        (parseOtpType "email_change")
    assertEqual
        "parseOtpType bogus"
        (Left (VerifyUnsupportedOtpType "bogus"))
        (parseOtpType "bogus")

    -- classifyVerifyRequest
    let emptyTokenReq =
            VerifyRequest
                { verifyToken = ""
                , verifyType = "signup"
                , verifyEmail = Nothing
                , verifyPassword = Nothing
                }
    assertEqual
        "classifyVerifyRequest empty token"
        (Left VerifyMissingToken)
        (classifyVerifyRequest emptyTokenReq)

    let unsupportedTypeReq =
            VerifyRequest
                { verifyToken = "some-token"
                , verifyType = "unknown_type"
                , verifyEmail = Nothing
                , verifyPassword = Nothing
                }
    case classifyVerifyRequest unsupportedTypeReq of
        Left (VerifyUnsupportedOtpType _) -> pure ()
        other ->
            fail
                ( "classifyVerifyRequest unsupported type: expected Left VerifyUnsupportedOtpType, got "
                    <> show other
                )

    let validSignupReq =
            VerifyRequest
                { verifyToken = "valid-token-abc"
                , verifyType = "signup"
                , verifyEmail = Nothing
                , verifyPassword = Nothing
                }
    assertEqual
        "classifyVerifyRequest valid signup"
        (Right OtpSignup)
        (classifyVerifyRequest validSignupReq)

    -- MessageResponse JSON shape
    let msgResp = MessageResponse "Verification email sent if needed"
    case Aeson.decode (Aeson.encode msgResp) of
        Nothing ->
            fail "MessageResponse: JSON decode failed"
        Just (obj :: Object) -> do
            if KeyMap.member "message" obj
                then pure ()
                else fail "MessageResponse JSON: missing 'message' key"
            assertEqual
                "MessageResponse message value"
                (Just (String "Verification email sent if needed"))
                (KeyMap.lookup "message" obj)
