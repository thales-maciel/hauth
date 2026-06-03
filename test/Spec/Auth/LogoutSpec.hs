module Spec.Auth.LogoutSpec (spec) where

import Data.Time.Clock (getCurrentTime)
import qualified Data.UUID as UUID
import Hauth.Auth.Jwt (
    AccessTokenClaims (..),
    JwtError (..),
    signAccessToken,
    validateAccessToken,
 )
import Hauth.Auth.Logout (
    LogoutError (..),
    resolveLogoutSession,
    sessionIdFromClaims,
 )
import Hauth.Session (SessionId (..))
import Spec.TestUtils (makeTestClaims, testCfg)
import Test.Hspec (Spec, describe, expectationFailure, it, shouldBe)

spec :: Spec
spec = do
    describe "sessionIdFromClaims" $ do
        it "parses a valid UUID string" $ do
            now <- getCurrentTime
            let validSidText = "11111111-2222-3333-4444-555555555555"
                claimsWithValidSid = (makeTestClaims now){claimSessionId = validSidText}
            case sessionIdFromClaims claimsWithValidSid of
                Right (SessionId uuid) -> UUID.toText uuid `shouldBe` validSidText
                Left err ->
                    expectationFailure ("unexpected Left: " <> show err)
        it "rejects a non-UUID string with LogoutBadSessionId" $ do
            now <- getCurrentTime
            let badSidClaims = (makeTestClaims now){claimSessionId = "not-a-uuid"}
            case sessionIdFromClaims badSidClaims of
                Left (LogoutBadSessionId _) -> pure ()
                Left other ->
                    expectationFailure ("unexpected LogoutError: " <> show other)
                Right _ ->
                    expectationFailure "expected Left, got Right"

    describe "resolveLogoutSession" $ do
        it "maps a JwtVerifyError to LogoutInvalidJwt" $
            case resolveLogoutSession (Left (JwtVerifyError "bad sig")) of
                Left (LogoutInvalidJwt _) -> pure ()
                Left other ->
                    expectationFailure ("unexpected error: " <> show other)
                Right _ ->
                    expectationFailure "expected Left"
        it "returns a SessionId for valid Right claims" $ do
            now <- getCurrentTime
            let validSidText = "11111111-2222-3333-4444-555555555555"
                goodSidClaims = (makeTestClaims now){claimSessionId = validSidText}
            case resolveLogoutSession (Right goodSidClaims) of
                Right (SessionId uuid) -> UUID.toText uuid `shouldBe` validSidText
                Left err ->
                    expectationFailure ("unexpected Left: " <> show err)
        it "maps a bad session_id in Right claims to LogoutBadSessionId" $ do
            now <- getCurrentTime
            let badSidClaims2 = (makeTestClaims now){claimSessionId = "not-a-uuid-either"}
            case resolveLogoutSession (Right badSidClaims2) of
                Left (LogoutBadSessionId _) -> pure ()
                Left other ->
                    expectationFailure ("unexpected error: " <> show other)
                Right _ ->
                    expectationFailure "expected Left, got Right"

    describe "end-to-end logout" $
        it "signs, validates, and resolves a session id from a JWT" $ do
            now <- getCurrentTime
            let e2eSidText = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
                e2eClaims = (makeTestClaims now){claimSessionId = e2eSidText}
            e2eSignOut <- signAccessToken testCfg e2eClaims
            case e2eSignOut of
                Left err -> expectationFailure ("logout e2e sign failed: " <> show err)
                Right outToken -> do
                    e2eValidate <- validateAccessToken testCfg outToken
                    case resolveLogoutSession e2eValidate of
                        Right (SessionId uuid) ->
                            UUID.toText uuid `shouldBe` e2eSidText
                        Left err ->
                            expectationFailure
                                ("logout e2e resolveLogoutSession: unexpected Left: " <> show err)
