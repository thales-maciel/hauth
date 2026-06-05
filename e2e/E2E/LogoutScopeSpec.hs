{-# LANGUAGE OverloadedStrings #-}

module E2E.LogoutScopeSpec (spec) where

import qualified Data.Aeson as Aeson
import qualified Data.Aeson.KeyMap as KeyMap
import qualified Data.Text as T
import Data.UUID (UUID)
import Database.PostgreSQL.Simple (Only (..), execute)
import E2E.Helpers (
    TestEnv (..),
    decodeBody,
    expectStatus,
    jsonGet,
    jsonPost,
    runApp,
 )
import Hauth.Env (withDatabaseConnection)
import Hauth.Session (listUserSessions)
import Hauth.User (User (..), UserId (..), getUserByEmail)
import Test.Hspec (SpecWith, describe, it, shouldBe)

spec :: SpecWith TestEnv
spec = do
    describe "POST /logout?scope=local" $
        it "revokes only the bearer session; other sessions remain active" \env -> do
            (uid, access1, refresh1, access2, _refresh2) <- bootstrapTwoSessions env "local-scope@example.com"
            -- Logout with scope=local using the first access token
            logoutResp <- runApp env $ jsonPost "/logout?scope=local" (Aeson.object []) (Just access1)
            expectStatus 204 logoutResp
            -- Session 1 refresh token is now dead
            rotateResp1 <- runApp env $ jsonPost "/token?grant_type=refresh_token" (Aeson.object ["refresh_token" Aeson..= refresh1]) Nothing
            expectStatus 401 rotateResp1
            -- Session 2 is still alive
            userResp <- runApp env $ jsonGet "/user" (Just access2)
            expectStatus 200 userResp
            -- DB: one session remains
            sessions <- withDatabaseConnection (testAppEnv env) (`listUserSessions` uid)
            length sessions `shouldBe` 1

    describe "POST /logout?scope=global" $
        it "revokes all sessions for the user" \env -> do
            (uid, access1, refresh1, _access2, refresh2) <- bootstrapTwoSessions env "global-scope@example.com"
            logoutResp <- runApp env $ jsonPost "/logout?scope=global" (Aeson.object []) (Just access1)
            expectStatus 204 logoutResp
            -- Both refresh tokens are dead
            rotateResp1 <- runApp env $ jsonPost "/token?grant_type=refresh_token" (Aeson.object ["refresh_token" Aeson..= refresh1]) Nothing
            expectStatus 401 rotateResp1
            rotateResp2 <- runApp env $ jsonPost "/token?grant_type=refresh_token" (Aeson.object ["refresh_token" Aeson..= refresh2]) Nothing
            expectStatus 401 rotateResp2
            -- DB: no sessions remain
            sessions <- withDatabaseConnection (testAppEnv env) (`listUserSessions` uid)
            length sessions `shouldBe` 0

    describe "POST /logout (no scope)" $
        it "defaults to global: revokes all sessions" \env -> do
            (uid, access1, refresh1, _access2, refresh2) <- bootstrapTwoSessions env "default-scope@example.com"
            logoutResp <- runApp env $ jsonPost "/logout" (Aeson.object []) (Just access1)
            expectStatus 204 logoutResp
            rotateResp1 <- runApp env $ jsonPost "/token?grant_type=refresh_token" (Aeson.object ["refresh_token" Aeson..= refresh1]) Nothing
            expectStatus 401 rotateResp1
            rotateResp2 <- runApp env $ jsonPost "/token?grant_type=refresh_token" (Aeson.object ["refresh_token" Aeson..= refresh2]) Nothing
            expectStatus 401 rotateResp2
            sessions <- withDatabaseConnection (testAppEnv env) (`listUserSessions` uid)
            length sessions `shouldBe` 0

    describe "POST /logout?scope=others" $
        it "revokes other sessions; bearer session stays alive" \env -> do
            (uid, access1, refresh1, _access2, refresh2) <- bootstrapTwoSessions env "others-scope@example.com"
            logoutResp <- runApp env $ jsonPost "/logout?scope=others" (Aeson.object []) (Just access1)
            expectStatus 204 logoutResp
            -- Bearer session (access1) is still usable
            userResp <- runApp env $ jsonGet "/user" (Just access1)
            expectStatus 200 userResp
            -- Other session's refresh token is dead
            rotateResp2 <- runApp env $ jsonPost "/token?grant_type=refresh_token" (Aeson.object ["refresh_token" Aeson..= refresh2]) Nothing
            expectStatus 401 rotateResp2
            -- Bearer session's refresh token is still alive
            rotateResp1 <- runApp env $ jsonPost "/token?grant_type=refresh_token" (Aeson.object ["refresh_token" Aeson..= refresh1]) Nothing
            expectStatus 200 rotateResp1
            -- Bearer's access token still authenticates after the refresh rotate
            bearerResp <- runApp env $ jsonGet "/user" (Just access1)
            expectStatus 200 bearerResp
            -- DB: only the bearer session remains
            sessions <- withDatabaseConnection (testAppEnv env) (`listUserSessions` uid)
            length sessions `shouldBe` 1

    describe "POST /logout?scope=invalid" $
        it "returns 400 with supabase error shape" \env -> do
            access <- bootstrapVerifiedUserAccess env "invalid-scope@example.com"
            resp <- runApp env $ jsonPost "/logout?scope=badvalue" (Aeson.object []) (Just access)
            expectStatus 400 resp
            (obj :: Aeson.Object) <- decodeBody resp
            KeyMap.member "code" obj `shouldBe` True

-- ---------------------------------------------------------------------------
-- Helpers
-- ---------------------------------------------------------------------------

-- | Sign up, confirm, and log in twice. Returns (userId, access1, refresh1, access2, refresh2).
bootstrapTwoSessions :: TestEnv -> T.Text -> IO (UUID, T.Text, T.Text, T.Text, T.Text)
bootstrapTwoSessions env email = do
    _ <- bootstrapVerifiedUserAccess env email
    -- Resolve the user UUID from DB, then drop the session /verify created
    -- so the two logins below are the only sessions in play.
    mUser <- withDatabaseConnection (testAppEnv env) (`getUserByEmail` email)
    user <- case mUser of
        Nothing -> error "bootstrapTwoSessions: user not found"
        Just u -> pure u
    let uid = unUserId (userId user)
    _ <-
        withDatabaseConnection (testAppEnv env) \conn ->
            execute conn "DELETE FROM auth.sessions WHERE user_id = ?" (Only uid)
    -- Log in twice to create two distinct sessions.
    sess1 <- login env email
    sess2 <- login env email
    (access1, refresh1) <- extractSession sess1
    (access2, refresh2) <- extractSession sess2
    pure (uid, access1, refresh1, access2, refresh2)

login :: TestEnv -> T.Text -> IO Aeson.Object
login env email = do
    resp <-
        runApp env $
            jsonPost
                "/token?grant_type=password"
                (Aeson.object ["email" Aeson..= email, "password" Aeson..= ("correct horse" :: T.Text)])
                Nothing
    decodeBody resp

extractSession :: Aeson.Object -> IO (T.Text, T.Text)
extractSession obj = do
    access <- extractString "access_token" obj
    refresh <- extractString "refresh_token" obj
    pure (access, refresh)

extractString :: Aeson.Key -> Aeson.Object -> IO T.Text
extractString k obj =
    case KeyMap.lookup k obj of
        Just (Aeson.String t) -> pure t
        Just other -> error ("key " <> show k <> " was not a string: " <> show other)
        Nothing -> error ("missing key " <> show k <> " in " <> show obj)

-- | Signup + verify; return the verify-step access token (not used for multi-session).
bootstrapVerifiedUserAccess :: TestEnv -> T.Text -> IO T.Text
bootstrapVerifiedUserAccess env email = do
    _ <-
        runApp env $
            jsonPost
                "/signup"
                (Aeson.object ["email" Aeson..= email, "password" Aeson..= ("correct horse" :: T.Text)])
                Nothing
    mUser <- withDatabaseConnection (testAppEnv env) (`getUserByEmail` email)
    user <- case mUser of
        Nothing -> error "bootstrapVerifiedUserAccess: user not found after signup"
        Just u -> pure u
    token <- case userConfirmationToken user of
        Nothing -> error "bootstrapVerifiedUserAccess: no confirmation_token"
        Just t -> pure t
    verifyResp <-
        runApp env $
            jsonPost
                "/verify"
                (Aeson.object ["type" Aeson..= ("signup" :: T.Text), "token" Aeson..= token])
                Nothing
    (obj :: Aeson.Object) <- decodeBody verifyResp
    extractString "access_token" obj
