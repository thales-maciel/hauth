{-# LANGUAGE OverloadedStrings #-}

module E2E.OAuthSpec (spec) where

import qualified Data.Aeson as Aeson
import qualified Data.Aeson.KeyMap as KeyMap
import qualified Data.ByteString as BS
import Data.Text (Text)
import qualified Data.Text as T
import qualified Data.Text.Encoding as TE
import Database.PostgreSQL.Simple (Only (..), query)
import E2E.Helpers (
    TestEnv (..),
    decodeBody,
    expectStatus,
    jsonGet,
    runApp,
 )
import E2E.OAuthFake (
    failingExchange,
    fakeGoogleClaims,
    happyExchange,
    withFakeProviders,
 )
import Hauth.Env (withDatabaseConnection)
import Hauth.OAuth (IdentityClaims (..))
import Test.Hspec (SpecWith, describe, it, shouldBe, shouldSatisfy)

redirectTo :: BS.ByteString
redirectTo = "https://app.example.com/auth/callback"

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

    describe "OAuth happy path with injected fake (google)" $
        it "authorize creates state, callback consumes it, identity persisted, session returned" \env -> do
            let fakeEnv = withFakeProviders happyExchange env
            -- Step 1: /authorize creates a flow state row and returns the authorize URL + state token.
            authResp <-
                runApp fakeEnv $
                    jsonGet
                        ("/authorize?provider=google&redirect_to=" <> redirectTo)
                        Nothing
            expectStatus 200 authResp
            (authObj :: Aeson.Object) <- decodeBody authResp
            stateToken <- case KeyMap.lookup "state" authObj of
                Just (Aeson.String s) -> pure s
                other -> error ("expected state string; got " <> show other)
            -- Step 2: /callback with a fake code and the real state token.
            callbackResp <-
                runApp fakeEnv $
                    jsonGet
                        ("/callback?code=fake-auth-code&state=" <> TE.encodeUtf8 stateToken)
                        Nothing
            expectStatus 200 callbackResp
            (sessObj :: Aeson.Object) <- decodeBody callbackResp
            -- Session response must contain non-empty access_token and refresh_token.
            KeyMap.lookup "access_token" sessObj `shouldSatisfy` \case
                Just (Aeson.String t) -> not (T.null t)
                _ -> False
            KeyMap.lookup "refresh_token" sessObj `shouldSatisfy` \case
                Just (Aeson.String t) -> not (T.null t)
                _ -> False
            -- Step 3: identity row must exist in auth.identities.
            rows <-
                withDatabaseConnection (testAppEnv fakeEnv) \conn ->
                    query
                        conn
                        "SELECT provider_id FROM auth.identities WHERE provider = ?"
                        (Only ("google" :: Text))
            let pids = map (\(Only pid) -> pid :: Text) rows
            pids `shouldBe` [identityProviderId fakeGoogleClaims]

    describe "OAuth callback with failing exchange" $
        it "returns 401 oauth_exchange_failed" \env -> do
            let fakeEnv = withFakeProviders happyExchange env
                failEnv = withFakeProviders failingExchange env
            -- Create a valid flow state using the happy env (authorize still works there).
            authResp <-
                runApp fakeEnv $
                    jsonGet
                        ("/authorize?provider=google&redirect_to=" <> redirectTo)
                        Nothing
            expectStatus 200 authResp
            (authObj :: Aeson.Object) <- decodeBody authResp
            stateToken <- case KeyMap.lookup "state" authObj of
                Just (Aeson.String s) -> pure s
                other -> error ("expected state string; got " <> show other)
            -- Call /callback through the failing exchange env.
            callbackResp <-
                runApp failEnv $
                    jsonGet
                        ("/callback?code=fake-auth-code&state=" <> TE.encodeUtf8 stateToken)
                        Nothing
            expectStatus 401 callbackResp
            (errObj :: Aeson.Object) <- decodeBody callbackResp
            KeyMap.lookup "error" errObj `shouldBe` Just (Aeson.String "oauth_exchange_failed")
