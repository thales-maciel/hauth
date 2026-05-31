module Spec.Auth.RecoverySpec (runSpec) where

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
import Spec.TestUtils (assertEqual)

runSpec :: IO ()
runSpec = do
    assertEqual
        "validateRecoverRequest empty email"
        (Left RecoveryMissingEmail)
        (validateRecoverRequest (RecoverRequest (Email "")))
    assertEqual
        "validateRecoverRequest whitespace email"
        (Left RecoveryMissingEmail)
        (validateRecoverRequest (RecoverRequest (Email "   ")))
    assertEqual
        "validateRecoverRequest valid email"
        (Right "user@example.com")
        (validateRecoverRequest (RecoverRequest (Email "user@example.com")))
    assertEqual
        "validateRecoveryVerify empty token"
        (Left RecoveryMissingToken)
        ( validateRecoveryVerify
            VerifyRequest{verifyToken = "", verifyType = "recovery", verifyEmail = Nothing, verifyPassword = Just "abcdefgh"}
        )
    case validateRecoveryVerify
        VerifyRequest{verifyToken = "sometoken", verifyType = "recovery", verifyEmail = Nothing, verifyPassword = Nothing} of
        Left (RecoveryPasswordTooShort _ _) -> pure ()
        other -> fail ("validateRecoveryVerify no password: expected RecoveryPasswordTooShort, got " <> show other)
    case validateRecoveryVerify
        VerifyRequest{verifyToken = "sometoken", verifyType = "recovery", verifyEmail = Nothing, verifyPassword = Just "short"} of
        Left (RecoveryPasswordTooShort _ _) -> pure ()
        other -> fail ("validateRecoveryVerify short password: expected RecoveryPasswordTooShort, got " <> show other)
    assertEqual
        "validateRecoveryVerify valid token + password"
        (Right ("sometoken", "abcdefgh"))
        ( validateRecoveryVerify
            VerifyRequest{verifyToken = "sometoken", verifyType = "recovery", verifyEmail = Nothing, verifyPassword = Just "abcdefgh"}
        )
    assertEqual
        "recoverySentMessage exact text"
        "If an account exists for this email, a recovery email has been sent."
        recoverySentMessage
    let recoveryMsgResp = MessageResponse{message = recoverySentMessage}
    case Aeson.decode (Aeson.encode recoveryMsgResp) of
        Nothing -> fail "MessageResponse: JSON decode failed"
        Just (obj :: Object) ->
            if KeyMap.member "message" obj
                then pure ()
                else fail "MessageResponse JSON: missing 'message' key"
