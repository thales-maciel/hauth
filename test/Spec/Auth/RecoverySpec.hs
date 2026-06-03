module Spec.Auth.RecoverySpec (spec) where

import Data.Aeson (Object)
import qualified Data.Aeson as Aeson
import qualified Data.Aeson.KeyMap as KeyMap
import Hauth.API.Types (
    Email (..),
    MessageResponse (..),
    RecoverRequest (..),
    VerifyRequest (..),
 )
import Hauth.Auth.Recovery (
    RecoveryError (..),
    recoverySentMessage,
    validateRecoverRequest,
    validateRecoveryVerify,
 )
import Test.Hspec (Spec, describe, expectationFailure, it, shouldBe)

spec :: Spec
spec = do
    describe "validateRecoverRequest" $ do
        it "rejects an empty email" $
            validateRecoverRequest (RecoverRequest (Email ""))
                `shouldBe` Left RecoveryMissingEmail
        it "rejects a whitespace-only email" $
            validateRecoverRequest (RecoverRequest (Email "   "))
                `shouldBe` Left RecoveryMissingEmail
        it "accepts a valid email" $
            validateRecoverRequest (RecoverRequest (Email "user@example.com"))
                `shouldBe` Right "user@example.com"

    describe "validateRecoveryVerify" $ do
        it "rejects an empty token" $
            validateRecoveryVerify
                VerifyRequest
                    { verifyToken = ""
                    , verifyType = "recovery"
                    , verifyEmail = Nothing
                    , verifyPassword = Just "abcdefgh"
                    }
                `shouldBe` Left RecoveryMissingToken
        it "rejects a missing password" $
            case validateRecoveryVerify
                VerifyRequest
                    { verifyToken = "sometoken"
                    , verifyType = "recovery"
                    , verifyEmail = Nothing
                    , verifyPassword = Nothing
                    } of
                Left (RecoveryPasswordTooShort _ _) -> pure ()
                other ->
                    expectationFailure
                        ("expected RecoveryPasswordTooShort, got " <> show other)
        it "rejects a too-short password" $
            case validateRecoveryVerify
                VerifyRequest
                    { verifyToken = "sometoken"
                    , verifyType = "recovery"
                    , verifyEmail = Nothing
                    , verifyPassword = Just "short"
                    } of
                Left (RecoveryPasswordTooShort _ _) -> pure ()
                other ->
                    expectationFailure
                        ("expected RecoveryPasswordTooShort, got " <> show other)
        it "accepts a valid token and password" $
            validateRecoveryVerify
                VerifyRequest
                    { verifyToken = "sometoken"
                    , verifyType = "recovery"
                    , verifyEmail = Nothing
                    , verifyPassword = Just "abcdefgh"
                    }
                `shouldBe` Right ("sometoken", "abcdefgh")

    describe "recoverySentMessage" $ do
        it "has the exact public-facing text" $
            recoverySentMessage
                `shouldBe` "If an account exists for this email, a recovery email has been sent."
        it "round-trips through JSON with a 'message' key" $ do
            let recoveryMsgResp = MessageResponse{message = recoverySentMessage}
            case Aeson.decode (Aeson.encode recoveryMsgResp) of
                Nothing -> expectationFailure "MessageResponse: JSON decode failed"
                Just (obj :: Object) ->
                    KeyMap.member "message" obj `shouldBe` True
