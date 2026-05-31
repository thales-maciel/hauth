module Spec.Auth.ServiceRoleSpec (runSpec) where

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
import Spec.TestUtils (assertEqual, makeTestClaims, testCfg)

runSpec :: IO ()
runSpec = do
    now <- getCurrentTime
    let testClaims = makeTestClaims now
        serviceRoleClaims = testClaims{claimRole = "service_role"}
        authenticatedClaims = testClaims{claimRole = "authenticated"}
    assertEqual
        "extractBearerToken missing header"
        (Left "Missing Authorization header")
        (extractBearerToken [])
    assertEqual
        "extractBearerToken bearer token"
        (Right "foo")
        (extractBearerToken [("Authorization", "Bearer foo")])
    assertEqual
        "extractBearerToken basic scheme"
        (Left "Authorization header is not a Bearer token")
        (extractBearerToken [("Authorization", "Basic xxx")])
    assertEqual
        "extractBearerToken empty bearer"
        (Left "Bearer token is empty")
        (extractBearerToken [("Authorization", "Bearer ")])
    assertEqual
        "checkServiceRole service_role claims"
        (Right ServiceRolePrincipal{serviceRoleName = "service_role"})
        (checkServiceRole (Right serviceRoleClaims))
    case checkServiceRole (Right authenticatedClaims) of
        Left _ -> pure ()
        Right _ -> fail "checkServiceRole authenticated: expected Left"
    case checkServiceRole (Left (JwtVerifyError "bad sig")) of
        Left _ -> pure ()
        Right _ -> fail "checkServiceRole JwtVerifyError: expected Left"
    e2eSignResult <- signAccessToken testCfg serviceRoleClaims
    case e2eSignResult of
        Left err -> fail ("service-role e2e sign failed: " <> show err)
        Right srToken -> do
            srValidateResult <- validateAccessToken testCfg srToken
            case checkServiceRole srValidateResult of
                Right ServiceRolePrincipal{serviceRoleName} ->
                    assertEqual "service-role e2e role name" "service_role" serviceRoleName
                Left msg ->
                    fail ("service-role e2e: expected Right, got Left: " <> T.unpack msg)
