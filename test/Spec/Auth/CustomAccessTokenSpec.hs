{-# LANGUAGE BlockArguments #-}

module Spec.Auth.CustomAccessTokenSpec (spec) where

import Control.Exception (bracket)
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
import Spec.TestUtils (makeTestClaims, testCfg, testLogger, validConfigBytes)
import Test.Hspec (Spec, describe, expectationFailure, it, shouldBe)

-- ---------------------------------------------------------------------------
-- Helpers
-- ---------------------------------------------------------------------------

withTestEnv :: (AppEnv -> IO a) -> IO a
withTestEnv action =
    case decodeConfigBytes "test" validConfigBytes of
        Left err -> error ("withTestEnv: config parse failed: " <> show err)
        Right cfg ->
            bracket (createAppEnvWithLogger testLogger cfg) destroyAppEnv action

-- ---------------------------------------------------------------------------
-- Tests
-- ---------------------------------------------------------------------------

spec :: Spec
spec = do
    describe "signAccessToken without hook" $
        it "identical inputs produce identical tokens" $ do
            now <- getCurrentTime
            let claims = makeTestClaims now
            r1 <- signAccessToken testCfg claims
            r2 <- signAccessToken testCfg claims
            case (r1, r2) of
                (Right t1, Right t2) -> t1 `shouldBe` t2
                _ -> expectationFailure "testNoHookFallsBackToSign: signing failed"

    describe "applyOverlay app_metadata" $
        it "merges overlay into existing app_metadata object" $ do
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
                    KeyMap.lookup "plan" km `shouldBe` Just (String "pro")
                    KeyMap.lookup "tenant" km `shouldBe` Just (String "old")
                    KeyMap.lookup "extra" km `shouldBe` Just (String "yes")
                _ -> expectationFailure "testApplyOverlayAppMetadata: expected Object"

    describe "applyOverlay user_metadata" $
        it "merges overlay into existing user_metadata object" $ do
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
                    KeyMap.lookup "nickname" km `shouldBe` Just (String "bob")
                    KeyMap.lookup "lang" km `shouldBe` Just (String "en")
                _ -> expectationFailure "testApplyOverlayUserMetadata: expected Object"

    describe "applyOverlay ignores protected claims" $ do
        it "ignores attempts to overwrite sub" $ do
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
            claimSub result `shouldBe` claimSub claims
        it "ignores attempts to overwrite exp" $ do
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
            claimExpiresAt result `shouldBe` claimExpiresAt claims

    describe "applyOverlay recursive merge" $
        it "recursively merges nested objects in overlay" $ do
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
                            KeyMap.lookup "a" nested `shouldBe` Just (String "1")
                            KeyMap.lookup "b" nested `shouldBe` Just (String "overridden")
                            KeyMap.lookup "c" nested `shouldBe` Just (String "3")
                        _ -> expectationFailure "testApplyOverlayRecursiveMerge: missing nested object"
                _ -> expectationFailure "testApplyOverlayRecursiveMerge: expected Object"

    describe "applyOverlay non-object" $ do
        it "non-object overlay leaves app_metadata unchanged" $ do
            now <- getCurrentTime
            let claims = makeTestClaims now
                result = applyOverlay claims (String "not an object")
            claimAppMetadata result `shouldBe` claimAppMetadata claims
        it "non-object overlay leaves user_metadata unchanged" $ do
            now <- getCurrentTime
            let claims = makeTestClaims now
                result = applyOverlay claims (String "not an object")
            claimUserMetadata result `shouldBe` claimUserMetadata claims

    describe "issueAccessToken without hook" $
        it "produces the same token as direct signAccessToken" $
            withTestEnv \env -> do
                now <- getCurrentTime
                let claims = makeTestClaims now
                    cfg = appConfig env
                expectedResult <- signAccessToken (configJwt cfg) claims
                actualResult <- issueAccessToken env claims
                case (expectedResult, actualResult) of
                    (Right expected, Right actual) -> actual `shouldBe` expected
                    (Left e, _) -> expectationFailure ("testIssueNoHookConfigured: sign failed: " <> show e)
                    (_, Left e) -> expectationFailure ("testIssueNoHookConfigured: issue failed: " <> show e)
