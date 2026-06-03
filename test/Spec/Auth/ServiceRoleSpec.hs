module Spec.Auth.ServiceRoleSpec (spec) where

import qualified Data.Text as T
import Data.Time.Clock (getCurrentTime)
import Hauth.API.Auth (
    ServiceRolePrincipal (..),
    checkServiceRole,
    extractBearerToken,
 )
import Hauth.Auth.Jwt (
    AccessTokenClaims (..),
    JwtError (..),
    signAccessToken,
    validateAccessToken,
 )
import Spec.TestUtils (makeTestClaims, testCfg)
import Test.Hspec (Spec, describe, expectationFailure, it, shouldBe)

spec :: Spec
spec = do
    describe "extractBearerToken" $ do
        it "rejects a missing Authorization header" $
            extractBearerToken [] `shouldBe` Left "Missing Authorization header"
        it "extracts a Bearer token" $
            extractBearerToken [("Authorization", "Bearer foo")] `shouldBe` Right "foo"
        it "rejects a non-Bearer scheme" $
            extractBearerToken [("Authorization", "Basic xxx")]
                `shouldBe` Left "Authorization header is not a Bearer token"
        it "rejects an empty Bearer token" $
            extractBearerToken [("Authorization", "Bearer ")]
                `shouldBe` Left "Bearer token is empty"

    describe "checkServiceRole" $ do
        it "accepts claims with role service_role" $ do
            now <- getCurrentTime
            let serviceRoleClaims = (makeTestClaims now){claimRole = "service_role"}
            checkServiceRole (Right serviceRoleClaims)
                `shouldBe` Right ServiceRolePrincipal{serviceRoleName = "service_role"}
        it "rejects claims with role authenticated" $ do
            now <- getCurrentTime
            let authenticatedClaims = (makeTestClaims now){claimRole = "authenticated"}
            case checkServiceRole (Right authenticatedClaims) of
                Left _ -> pure ()
                Right _ -> expectationFailure "expected Left"
        it "propagates a JwtVerifyError as Left" $
            case checkServiceRole (Left (JwtVerifyError "bad sig")) of
                Left _ -> pure ()
                Right _ -> expectationFailure "expected Left"

    describe "end-to-end service-role JWT" $
        it "signs, validates, and resolves a service_role token" $ do
            now <- getCurrentTime
            let serviceRoleClaims = (makeTestClaims now){claimRole = "service_role"}
            e2eSignResult <- signAccessToken testCfg serviceRoleClaims
            case e2eSignResult of
                Left err -> expectationFailure ("service-role e2e sign failed: " <> show err)
                Right srToken -> do
                    srValidateResult <- validateAccessToken testCfg srToken
                    case checkServiceRole srValidateResult of
                        Right ServiceRolePrincipal{serviceRoleName} ->
                            serviceRoleName `shouldBe` "service_role"
                        Left msg ->
                            expectationFailure
                                ("service-role e2e: expected Right, got Left: " <> T.unpack msg)
