module Spec.Auth.VerifySpec (spec) where

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
import Test.Hspec (Spec, describe, expectationFailure, it, shouldBe)

spec :: Spec
spec = do
    describe "parseOtpType" $ do
        it "parses signup" $
            parseOtpType "signup" `shouldBe` Right OtpSignup
        it "parses recovery" $
            parseOtpType "recovery" `shouldBe` Right OtpRecovery
        it "parses magiclink" $
            parseOtpType "magiclink" `shouldBe` Right OtpMagicLink
        it "parses invite" $
            parseOtpType "invite" `shouldBe` Right OtpInvite
        it "parses email_change" $
            parseOtpType "email_change" `shouldBe` Right OtpEmailChange
        it "rejects bogus" $
            parseOtpType "bogus" `shouldBe` Left (VerifyUnsupportedOtpType "bogus")

    describe "classifyVerifyRequest" $ do
        it "rejects empty token" $ do
            let emptyTokenReq =
                    VerifyRequest
                        { verifyToken = ""
                        , verifyType = "signup"
                        , verifyEmail = Nothing
                        , verifyPassword = Nothing
                        }
            classifyVerifyRequest emptyTokenReq `shouldBe` Left VerifyMissingToken

        it "rejects unsupported type" $ do
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
                    expectationFailure
                        ( "expected Left VerifyUnsupportedOtpType, got "
                            <> show other
                        )

        it "accepts valid signup" $ do
            let validSignupReq =
                    VerifyRequest
                        { verifyToken = "valid-token-abc"
                        , verifyType = "signup"
                        , verifyEmail = Nothing
                        , verifyPassword = Nothing
                        }
            classifyVerifyRequest validSignupReq `shouldBe` Right OtpSignup

    describe "MessageResponse JSON shape" $
        it "encodes a message field" $ do
            let msgResp = MessageResponse "Verification email sent if needed"
            case Aeson.decode (Aeson.encode msgResp) of
                Nothing ->
                    expectationFailure "JSON decode failed"
                Just (obj :: Object) -> do
                    KeyMap.member "message" obj `shouldBe` True
                    KeyMap.lookup "message" obj
                        `shouldBe` Just (String "Verification email sent if needed")
