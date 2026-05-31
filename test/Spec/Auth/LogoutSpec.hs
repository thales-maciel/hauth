module Spec.Auth.LogoutSpec (runSpec) where

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
import Spec.TestUtils (assertEqual, makeTestClaims, testCfg)

runSpec :: IO ()
runSpec = do
    now <- getCurrentTime
    let testClaims = makeTestClaims now
        validSidText = "11111111-2222-3333-4444-555555555555"
        claimsWithValidSid = testClaims{claimSessionId = validSidText}

    -- sessionIdFromClaims: valid UUID string → Right SessionId
    case sessionIdFromClaims claimsWithValidSid of
        Right (SessionId uuid) ->
            assertEqual
                "sessionIdFromClaims valid uuid text"
                validSidText
                (UUID.toText uuid)
        Left err ->
            fail ("sessionIdFromClaims valid uuid: unexpected Left: " <> show err)

    -- sessionIdFromClaims: non-UUID string → Left (LogoutBadSessionId _)
    let badSidClaims = testClaims{claimSessionId = "not-a-uuid"}
    case sessionIdFromClaims badSidClaims of
        Left (LogoutBadSessionId _) -> pure ()
        Left other -> fail ("sessionIdFromClaims bad uuid: unexpected LogoutError: " <> show other)
        Right _ -> fail "sessionIdFromClaims bad uuid: expected Left, got Right"

    -- resolveLogoutSession (Left JwtVerifyError) → Left (LogoutInvalidJwt _)
    case resolveLogoutSession (Left (JwtVerifyError "bad sig")) of
        Left (LogoutInvalidJwt _) -> pure ()
        Left other -> fail ("resolveLogoutSession JwtVerifyError: unexpected error: " <> show other)
        Right _ -> fail "resolveLogoutSession JwtVerifyError: expected Left"

    -- resolveLogoutSession (Right validClaims) → Right SessionId
    let goodSidClaims = testClaims{claimSessionId = validSidText}
    case resolveLogoutSession (Right goodSidClaims) of
        Right (SessionId uuid) ->
            assertEqual
                "resolveLogoutSession Right valid uuid"
                validSidText
                (UUID.toText uuid)
        Left err ->
            fail ("resolveLogoutSession Right valid uuid: unexpected Left: " <> show err)

    -- resolveLogoutSession (Right claims with bad session_id) → Left (LogoutBadSessionId _)
    let badSidClaims2 = testClaims{claimSessionId = "not-a-uuid-either"}
    case resolveLogoutSession (Right badSidClaims2) of
        Left (LogoutBadSessionId _) -> pure ()
        Left other -> fail ("resolveLogoutSession bad session_id: unexpected error: " <> show other)
        Right _ -> fail "resolveLogoutSession bad session_id: expected Left, got Right"

    -- End-to-end: sign → validate → resolveLogoutSession → Right SessionId
    let e2eSidText = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
        e2eClaims = testClaims{claimSessionId = e2eSidText}
    e2eSignOut <- signAccessToken testCfg e2eClaims
    case e2eSignOut of
        Left err -> fail ("logout e2e sign failed: " <> show err)
        Right outToken -> do
            e2eValidate <- validateAccessToken testCfg outToken
            case resolveLogoutSession e2eValidate of
                Right (SessionId uuid) ->
                    assertEqual
                        "logout e2e resolved session id"
                        e2eSidText
                        (UUID.toText uuid)
                Left err ->
                    fail ("logout e2e resolveLogoutSession: unexpected Left: " <> show err)
