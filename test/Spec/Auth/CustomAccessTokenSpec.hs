module Spec.Auth.CustomAccessTokenSpec (runSpec) where

import Data.Aeson (Value (..))
import qualified Data.Aeson.KeyMap as KeyMap
import Data.Time.Clock (getCurrentTime)
import Hauth.Auth.Jwt (
    AccessTokenClaims (..),
    applyOverlay,
    issueAccessToken,
    signAccessToken,
 )
import Hauth.Config (Config (..), decodeConfigBytes)
import Hauth.Env (AppEnv (..), createAppEnvWithLogger, destroyAppEnv)
import Spec.TestUtils (assertEqual, makeTestClaims, testCfg, testLogger, validConfigBytes)

-- ---------------------------------------------------------------------------
-- Helpers
-- ---------------------------------------------------------------------------

withTestEnv :: (AppEnv -> IO a) -> IO a
withTestEnv action =
    case decodeConfigBytes "test" validConfigBytes of
        Left err -> fail ("withTestEnv: config parse failed: " <> show err)
        Right cfg -> do
            env <- createAppEnvWithLogger testLogger cfg
            result <- action env
            destroyAppEnv env
            pure result

-- ---------------------------------------------------------------------------
-- Tests
-- ---------------------------------------------------------------------------

runSpec :: IO ()
runSpec = do
    testNoHookFallsBackToSign
    testApplyOverlayAppMetadata
    testApplyOverlayUserMetadata
    testApplyOverlayIgnoresSub
    testApplyOverlayIgnoresExp
    testApplyOverlayRecursiveMerge
    testApplyOverlayNonObjectIgnored
    testIssueNoHookConfigured

-- No hook in DB → issueAccessToken produces the same token as signAccessToken.
testIssueNoHookConfigured :: IO ()
testIssueNoHookConfigured =
    withTestEnv \env -> do
        now <- getCurrentTime
        let claims = makeTestClaims now
            cfg = appConfig env
        expectedResult <- signAccessToken (configJwt cfg) claims
        actualResult <- issueAccessToken env claims
        case (expectedResult, actualResult) of
            (Right expected, Right actual) ->
                assertEqual "no-hook token matches direct sign" expected actual
            (Left e, _) -> fail ("testIssueNoHookConfigured: sign failed: " <> show e)
            (_, Left e) -> fail ("testIssueNoHookConfigured: issue failed: " <> show e)

-- No hook configured → signAccessToken is deterministic.
testNoHookFallsBackToSign :: IO ()
testNoHookFallsBackToSign = do
    now <- getCurrentTime
    let claims = makeTestClaims now
    r1 <- signAccessToken testCfg claims
    r2 <- signAccessToken testCfg claims
    case (r1, r2) of
        (Right t1, Right t2) ->
            assertEqual "identical inputs produce identical tokens" t1 t2
        _ -> fail "testNoHookFallsBackToSign: signing failed"

-- Hook overlay with app_metadata merges into the existing object.
testApplyOverlayAppMetadata :: IO ()
testApplyOverlayAppMetadata = do
    now <- getCurrentTime
    let claims =
            (makeTestClaims now)
                { claimAppMetadata =
                    Object (KeyMap.fromList [("tenant", String "old"), ("plan", String "free")])
                }
        overlay =
            Object
                ( KeyMap.fromList
                    [ ("app_metadata", Object (KeyMap.fromList [("plan", String "pro"), ("extra", String "yes")]))
                    ]
                )
        result = applyOverlay claims overlay
    case claimAppMetadata result of
        Object km -> do
            assertEqual "plan overridden by overlay" (Just (String "pro")) (KeyMap.lookup "plan" km)
            assertEqual "tenant preserved from base" (Just (String "old")) (KeyMap.lookup "tenant" km)
            assertEqual "extra added from overlay" (Just (String "yes")) (KeyMap.lookup "extra" km)
        _ -> fail "testApplyOverlayAppMetadata: expected Object"

-- Hook overlay with user_metadata merges into the existing object.
testApplyOverlayUserMetadata :: IO ()
testApplyOverlayUserMetadata = do
    now <- getCurrentTime
    let claims =
            (makeTestClaims now)
                { claimUserMetadata =
                    Object (KeyMap.fromList [("nickname", String "alice")])
                }
        overlay =
            Object
                ( KeyMap.fromList
                    [ ("user_metadata", Object (KeyMap.fromList [("nickname", String "bob"), ("lang", String "en")]))
                    ]
                )
        result = applyOverlay claims overlay
    case claimUserMetadata result of
        Object km -> do
            assertEqual "nickname overridden" (Just (String "bob")) (KeyMap.lookup "nickname" km)
            assertEqual "lang added" (Just (String "en")) (KeyMap.lookup "lang" km)
        _ -> fail "testApplyOverlayUserMetadata: expected Object"

-- Overlay attempting to set sub is silently ignored.
testApplyOverlayIgnoresSub :: IO ()
testApplyOverlayIgnoresSub = do
    now <- getCurrentTime
    let claims = makeTestClaims now
        overlay =
            Object
                ( KeyMap.fromList
                    [ ("sub", String "attacker-uuid")
                    , ("app_metadata", Object (KeyMap.fromList []))
                    ]
                )
        result = applyOverlay claims overlay
    assertEqual "sub unchanged after overlay" (claimSub claims) (claimSub result)

-- Overlay attempting to set exp is silently ignored.
testApplyOverlayIgnoresExp :: IO ()
testApplyOverlayIgnoresExp = do
    now <- getCurrentTime
    let claims = makeTestClaims now
        overlay =
            Object
                ( KeyMap.fromList
                    [ ("exp", Number 0)
                    , ("app_metadata", Object (KeyMap.fromList []))
                    ]
                )
        result = applyOverlay claims overlay
    assertEqual "exp unchanged after overlay" (claimExpiresAt claims) (claimExpiresAt result)

-- Nested objects in overlay are recursively merged.
testApplyOverlayRecursiveMerge :: IO ()
testApplyOverlayRecursiveMerge = do
    now <- getCurrentTime
    let claims =
            (makeTestClaims now)
                { claimAppMetadata =
                    Object
                        ( KeyMap.fromList
                            [ ("nested", Object (KeyMap.fromList [("a", String "1"), ("b", String "2")]))
                            ]
                        )
                }
        overlay =
            Object
                ( KeyMap.fromList
                    [
                        ( "app_metadata"
                        , Object
                            ( KeyMap.fromList
                                [ ("nested", Object (KeyMap.fromList [("b", String "overridden"), ("c", String "3")]))
                                ]
                            )
                        )
                    ]
                )
        result = applyOverlay claims overlay
    case claimAppMetadata result of
        Object km ->
            case KeyMap.lookup "nested" km of
                Just (Object nested) -> do
                    assertEqual "a preserved" (Just (String "1")) (KeyMap.lookup "a" nested)
                    assertEqual "b overridden" (Just (String "overridden")) (KeyMap.lookup "b" nested)
                    assertEqual "c added" (Just (String "3")) (KeyMap.lookup "c" nested)
                _ -> fail "testApplyOverlayRecursiveMerge: missing nested object"
        _ -> fail "testApplyOverlayRecursiveMerge: expected Object"

-- Non-object overlay value leaves claims unchanged.
testApplyOverlayNonObjectIgnored :: IO ()
testApplyOverlayNonObjectIgnored = do
    now <- getCurrentTime
    let claims = makeTestClaims now
        result = applyOverlay claims (String "not an object")
    assertEqual "non-object overlay: app_metadata unchanged" (claimAppMetadata claims) (claimAppMetadata result)
    assertEqual "non-object overlay: user_metadata unchanged" (claimUserMetadata claims) (claimUserMetadata result)
