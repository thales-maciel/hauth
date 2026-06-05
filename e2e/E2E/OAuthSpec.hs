{-# LANGUAGE OverloadedStrings #-}

module E2E.OAuthSpec (spec) where

import Control.Concurrent.Async (concurrently)
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
import Hauth.OAuth (IdentityClaims (..), findOrCreateIdentity)
import Hauth.User (unUserId)
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

    describe "findOrCreateIdentity: no-email path" $
        it "links identity to the exact user returned by createUser, not latest-created" \env -> do
            -- Use a no-email identity so the code takes the no-email branch.
            let noEmailClaims =
                    IdentityClaims
                        { identityProvider = "github"
                        , identityProviderId = "no-email-sub-999"
                        , identityEmail = Nothing
                        , identityData = Aeson.object ["id" Aeson..= (999 :: Int)]
                        }
            (uid, isNew) <-
                withDatabaseConnection (testAppEnv env) (`findOrCreateIdentity` noEmailClaims)
            -- Must be a new user.
            isNew `shouldBe` True
            -- The identity row must reference the same user.
            rows <-
                withDatabaseConnection (testAppEnv env) \conn ->
                    query
                        conn
                        "SELECT user_id FROM auth.identities WHERE provider = ? AND provider_id = ?"
                        ("github" :: Text, "no-email-sub-999" :: Text)
            let identityUserIds = map (\(Only i) -> i) (rows :: [Only T.Text])
            identityUserIds `shouldBe` [T.pack (show (unUserId uid))]

    describe "findOrCreateIdentity: concurrent first-login race" $
        it "resolves both callers to the same user even under concurrent insert" \env -> do
            -- Two concurrent callers with identical (provider, provider_id).
            let raceClaims =
                    IdentityClaims
                        { identityProvider = "google"
                        , identityProviderId = "race-sub-777"
                        , identityEmail = Nothing
                        , identityData = Aeson.object ["sub" Aeson..= ("race-sub-777" :: Text)]
                        }
            (uid1, uid2) <-
                concurrently
                    (withDatabaseConnection (testAppEnv env) \conn -> fst <$> findOrCreateIdentity conn raceClaims)
                    (withDatabaseConnection (testAppEnv env) \conn -> fst <$> findOrCreateIdentity conn raceClaims)
            -- Both callers must resolve to the same user.
            uid1 `shouldBe` uid2
            -- Exactly one identity row must exist.
            identityRows <-
                withDatabaseConnection (testAppEnv env) \conn ->
                    query
                        conn
                        "SELECT provider_id FROM auth.identities WHERE provider = ? AND provider_id = ?"
                        ("google" :: Text, "race-sub-777" :: Text)
            length (identityRows :: [Only Text]) `shouldBe` 1
            -- Exactly one auth.users row must exist for the two resolved user-ids.
            -- Before the SAVEPOINT fix the race loser's createUser was committed but
            -- never linked to an identity, leaving an orphan row; this assertion
            -- would have caught that leak.
            userRows <-
                withDatabaseConnection (testAppEnv env) \conn ->
                    query
                        conn
                        "SELECT COUNT(*) FROM auth.users WHERE id IN (?, ?)"
                        (unUserId uid1, unUserId uid2)
            head (map (\(Only n) -> n :: Int) userRows) `shouldBe` 1
