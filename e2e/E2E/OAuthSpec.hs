{-# LANGUAGE OverloadedStrings #-}

module E2E.OAuthSpec (spec) where

import qualified Data.Aeson as Aeson
import qualified Data.Aeson.KeyMap as KeyMap
import E2E.Helpers (TestEnv, decodeBody, expectStatus, jsonGet, runApp)
import Test.Hspec (SpecWith, describe, it, shouldBe)

-- v0.1 OAuth e2e coverage is intentionally limited — the real Google/GitHub
-- provider HTTP exchange isn't mockable today (would need to refactor
-- Hauth.OAuth.* to take an injectable HTTP client). We cover only:
--   - /authorize redirect-shape happy path is wired (returns 400 because the
--     test config has no providers configured, but that's the right contract
--     for an unconfigured provider — a happier test would need a fake provider).
--   - /callback rejects unknown state.
-- Full provider integration tests are deferred to v0.2.
spec :: SpecWith TestEnv
spec = do
    describe "GET /authorize with unconfigured provider" $
        it "rejects with 400 unsupported_provider" \env -> do
            resp <-
                runApp env $
                    jsonGet "/authorize?provider=google&redirect_to=https://app.example.com/auth/callback" Nothing
            expectStatus 400 resp
            (obj :: Aeson.Object) <- decodeBody resp
            KeyMap.lookup "error" obj `shouldBe` Just (Aeson.String "unsupported_provider")

    describe "GET /callback with unknown state" $
        it "rejects with 400 invalid_state" \env -> do
            resp <-
                runApp env $
                    jsonGet "/callback?code=ignored&state=never-issued" Nothing
            expectStatus 400 resp
            (obj :: Aeson.Object) <- decodeBody resp
            case KeyMap.lookup "error" obj of
                Just (Aeson.String e) ->
                    (e `elem` ["invalid_state", "state_expired"]) `shouldBe` True
                other -> error ("expected error string; got " <> show other)
