{-# LANGUAGE OverloadedStrings #-}

module E2E.AuthSpec (spec) where

import Control.Concurrent (forkIO, threadDelay)
import Control.Concurrent.MVar (newEmptyMVar, putMVar, takeMVar)
import Control.Exception (bracket_)
import qualified Data.Aeson as Aeson
import qualified Data.Aeson.KeyMap as KeyMap
import qualified Data.Text as T
import Database.PostgreSQL.Simple (Only (..), execute, execute_)
import E2E.Helpers (
    TestEnv (..),
    decodeBody,
    expectStatus,
    jsonGet,
    jsonPost,
    runApp,
 )
import Hauth.Env (withDatabaseConnection)
import Hauth.Hooks.Types (HookPoint (..), hookPointName)
import Hauth.User (User (..), getUserByEmail)
import Network.HTTP.Types (status200)
import Network.Socket (
    Family (..),
    SockAddr (..),
    Socket,
    SocketOption (..),
    SocketType (..),
    bind,
    close,
    listen,
    maxListenQueue,
    setSocketOption,
    socket,
    socketPort,
 )
import Network.Wai (Application, responseLBS)
import qualified Network.Wai.Handler.Warp as Warp
import Test.Hspec (SpecWith, describe, it, shouldBe)

spec :: SpecWith TestEnv
spec = do
    describe "signup → verify → login → refresh → logout" $
        it "completes the happy path" \env -> do
            -- 1. Signup
            signupResp <- runApp env $ do
                jsonPost
                    "/signup"
                    (Aeson.object ["email" Aeson..= ("alice@example.com" :: T.Text), "password" Aeson..= ("correct horse" :: T.Text)])
                    Nothing
            expectStatus 200 signupResp
            (signupObj :: Aeson.Object) <- decodeBody signupResp
            KeyMap.member "id" signupObj `shouldBe` True
            KeyMap.member "confirmation_sent_at" signupObj `shouldBe` True

            -- 2. Fetch the confirmation_token directly from DB (no real email delivery in e2e)
            mUser <-
                withDatabaseConnection (testAppEnv env) (`getUserByEmail` "alice@example.com")
            user <- case mUser of
                Nothing -> error "expected user after signup"
                Just u -> pure u
            confirmationToken <- case userConfirmationToken user of
                Nothing -> error "expected confirmation_token after signup"
                Just t -> pure t

            -- 3. Verify the email
            verifyResp <- runApp env $ do
                jsonPost
                    "/verify"
                    ( Aeson.object
                        [ "type" Aeson..= ("signup" :: T.Text)
                        , "token" Aeson..= confirmationToken
                        ]
                    )
                    Nothing
            expectStatus 200 verifyResp
            (verifyObj :: Aeson.Object) <- decodeBody verifyResp
            KeyMap.member "access_token" verifyObj `shouldBe` True
            KeyMap.member "refresh_token" verifyObj `shouldBe` True

            -- 4. Login via password grant
            loginResp <- runApp env $ do
                jsonPost
                    "/token?grant_type=password"
                    ( Aeson.object
                        [ "email" Aeson..= ("alice@example.com" :: T.Text)
                        , "password" Aeson..= ("correct horse" :: T.Text)
                        ]
                    )
                    Nothing
            expectStatus 200 loginResp
            (loginObj :: Aeson.Object) <- decodeBody loginResp
            accessToken <- extractStringKey "access_token" loginObj
            refreshToken <- extractStringKey "refresh_token" loginObj
            KeyMap.member "user" loginObj `shouldBe` True

            -- Sanity: hit /user with the access token
            userResp <- runApp env $ jsonGet "/user" (Just accessToken)
            expectStatus 200 userResp

            -- 5. Refresh-token rotation
            refreshResp <- runApp env $ do
                jsonPost
                    "/token?grant_type=refresh_token"
                    (Aeson.object ["refresh_token" Aeson..= refreshToken])
                    Nothing
            expectStatus 200 refreshResp
            (refreshObj :: Aeson.Object) <- decodeBody refreshResp
            newAccess <- extractStringKey "access_token" refreshObj
            _ <- extractStringKey "refresh_token" refreshObj

            -- 6. Logout (revokes the session)
            logoutResp <- runApp env $ jsonPost "/logout" (Aeson.object []) (Just newAccess)
            expectStatus 204 logoutResp

    describe "login with unconfirmed email" $
        it "returns email_not_confirmed" \env -> do
            -- Signup but skip verify.
            _ <- runApp env $ do
                jsonPost
                    "/signup"
                    (Aeson.object ["email" Aeson..= ("bob@example.com" :: T.Text), "password" Aeson..= ("correct horse" :: T.Text)])
                    Nothing
            loginResp <- runApp env $ do
                jsonPost
                    "/token?grant_type=password"
                    ( Aeson.object
                        [ "email" Aeson..= ("bob@example.com" :: T.Text)
                        , "password" Aeson..= ("correct horse" :: T.Text)
                        ]
                    )
                    Nothing
            expectStatus 400 loginResp
            (errObj :: Aeson.Object) <- decodeBody loginResp
            KeyMap.lookup "error" errObj `shouldBe` Just (Aeson.String "email_not_confirmed")

    describe "login with wrong password" $
        it "returns invalid_grant" \env -> do
            _ <- runApp env $ do
                jsonPost
                    "/signup"
                    (Aeson.object ["email" Aeson..= ("carol@example.com" :: T.Text), "password" Aeson..= ("correct horse" :: T.Text)])
                    Nothing
            loginResp <- runApp env $ do
                jsonPost
                    "/token?grant_type=password"
                    ( Aeson.object
                        [ "email" Aeson..= ("carol@example.com" :: T.Text)
                        , "password" Aeson..= ("wrong" :: T.Text)
                        ]
                    )
                    Nothing
            expectStatus 400 loginResp
            (errObj :: Aeson.Object) <- decodeBody loginResp
            KeyMap.lookup "error" errObj `shouldBe` Just (Aeson.String "invalid_grant")

    describe "before-user-created hook" $ do
        it "no hook → signup succeeds as today" \env ->
            -- No hook row seeded; regression guard.
            withHookCleanup env $ do
                resp <-
                    runApp env $
                        jsonPost
                            "/signup"
                            ( Aeson.object
                                [ "email" Aeson..= ("hook-none@example.com" :: T.Text)
                                , "password" Aeson..= ("correct horse" :: T.Text)
                                ]
                            )
                            Nothing
                expectStatus 200 resp

        it "hook allow → signup succeeds" \env ->
            withHookCleanup env $
                withDecisionServer allowDecision \port -> do
                    seedHook env port 2000 False
                    resp <-
                        runApp env $
                            jsonPost
                                "/signup"
                                ( Aeson.object
                                    [ "email" Aeson..= ("hook-allow@example.com" :: T.Text)
                                    , "password" Aeson..= ("correct horse" :: T.Text)
                                    ]
                                )
                                Nothing
                    expectStatus 200 resp
                    mUser <- withDatabaseConnection (testAppEnv env) (`getUserByEmail` "hook-allow@example.com")
                    case mUser of
                        Nothing -> error "expected user row after hook-allow signup"
                        Just _ -> pure ()

        it "hook allow_with merges user_metadata overlay" \env ->
            withHookCleanup env $
                withDecisionServer overlayDecision \port -> do
                    seedHook env port 2000 False
                    resp <-
                        runApp env $
                            jsonPost
                                "/signup"
                                ( Aeson.object
                                    [ "email" Aeson..= ("hook-overlay@example.com" :: T.Text)
                                    , "password" Aeson..= ("correct horse" :: T.Text)
                                    ]
                                )
                                Nothing
                    expectStatus 200 resp
                    mUser <- withDatabaseConnection (testAppEnv env) (`getUserByEmail` "hook-overlay@example.com")
                    user <- case mUser of
                        Nothing -> error "expected user row after hook-overlay signup"
                        Just u -> pure u
                    -- "injected" key should be present in user_metadata
                    case userRawUserMetaData user of
                        Aeson.Object m ->
                            KeyMap.lookup "injected" m `shouldBe` Just (Aeson.String "by-hook")
                        other -> error ("expected object user_metadata; got " <> show other)

        it "hook reject → 400 hook_rejected; no user row" \env ->
            withHookCleanup env $
                withDecisionServer rejectDecisionBody \port -> do
                    seedHook env port 2000 False
                    resp <-
                        runApp env $
                            jsonPost
                                "/signup"
                                ( Aeson.object
                                    [ "email" Aeson..= ("hook-reject@example.com" :: T.Text)
                                    , "password" Aeson..= ("correct horse" :: T.Text)
                                    ]
                                )
                                Nothing
                    expectStatus 400 resp
                    (errObj :: Aeson.Object) <- decodeBody resp
                    KeyMap.lookup "error" errObj `shouldBe` Just (Aeson.String "hook_rejected")
                    mUser <- withDatabaseConnection (testAppEnv env) (`getUserByEmail` "hook-reject@example.com")
                    mUser `shouldBe` Nothing

        it "hook timeout fail_open=false → 400; no user row" \env ->
            withHookCleanup env $
                withDecisionServer slowServer \port -> do
                    seedHook env port 100 False -- 100 ms timeout (minimum allowed)
                    resp <-
                        runApp env $
                            jsonPost
                                "/signup"
                                ( Aeson.object
                                    [ "email" Aeson..= ("hook-timeout-closed@example.com" :: T.Text)
                                    , "password" Aeson..= ("correct horse" :: T.Text)
                                    ]
                                )
                                Nothing
                    expectStatus 400 resp
                    mUser <- withDatabaseConnection (testAppEnv env) (`getUserByEmail` "hook-timeout-closed@example.com")
                    mUser `shouldBe` Nothing

        it "hook timeout fail_open=true → signup succeeds" \env ->
            withHookCleanup env $
                withDecisionServer slowServer \port -> do
                    seedHook env port 100 True -- 100 ms timeout (minimum allowed), fail open
                    resp <-
                        runApp env $
                            jsonPost
                                "/signup"
                                ( Aeson.object
                                    [ "email" Aeson..= ("hook-timeout-open@example.com" :: T.Text)
                                    , "password" Aeson..= ("correct horse" :: T.Text)
                                    ]
                                )
                                Nothing
                    expectStatus 200 resp
                    mUser <- withDatabaseConnection (testAppEnv env) (`getUserByEmail` "hook-timeout-open@example.com")
                    case mUser of
                        Nothing -> error "expected user row after fail-open timeout"
                        Just _ -> pure ()

    describe "password-verification-attempt hook" $ do
        it "no hook → login succeeds with correct credentials" \env ->
            withHookCleanupFor env HookPasswordVerificationAttempt $ do
                signupAndConfirmFor env "login-no-hook@example.com"
                loginResp <-
                    runApp env $
                        jsonPost
                            "/token?grant_type=password"
                            (Aeson.object ["email" Aeson..= ("login-no-hook@example.com" :: T.Text), "password" Aeson..= ("correct horse" :: T.Text)])
                            Nothing
                expectStatus 200 loginResp

        it "hook allow → login succeeds with correct password" \env ->
            withHookCleanupFor env HookPasswordVerificationAttempt $
                withDecisionServer allowDecision \port -> do
                    seedHookFor env HookPasswordVerificationAttempt port 2000 False
                    signupAndConfirmFor env "login-hook-allow@example.com"
                    loginResp <-
                        runApp env $
                            jsonPost
                                "/token?grant_type=password"
                                (Aeson.object ["email" Aeson..= ("login-hook-allow@example.com" :: T.Text), "password" Aeson..= ("correct horse" :: T.Text)])
                                Nothing
                    expectStatus 200 loginResp

        it "hook allow → wrong password still returns invalid_grant" \env ->
            withHookCleanupFor env HookPasswordVerificationAttempt $
                withDecisionServer allowDecision \port -> do
                    seedHookFor env HookPasswordVerificationAttempt port 2000 False
                    signupAndConfirmFor env "login-hook-wrong@example.com"
                    loginResp <-
                        runApp env $
                            jsonPost
                                "/token?grant_type=password"
                                (Aeson.object ["email" Aeson..= ("login-hook-wrong@example.com" :: T.Text), "password" Aeson..= ("wrong" :: T.Text)])
                                Nothing
                    expectStatus 400 loginResp
                    (errObj :: Aeson.Object) <- decodeBody loginResp
                    KeyMap.lookup "error" errObj `shouldBe` Just (Aeson.String "invalid_grant")

        it "hook reject → 400 mfa_or_password_blocked (opaque)" \env ->
            withHookCleanupFor env HookPasswordVerificationAttempt $
                withDecisionServer rejectDecisionBody \port -> do
                    seedHookFor env HookPasswordVerificationAttempt port 2000 False
                    signupAndConfirmFor env "login-hook-reject@example.com"
                    loginResp <-
                        runApp env $
                            jsonPost
                                "/token?grant_type=password"
                                (Aeson.object ["email" Aeson..= ("login-hook-reject@example.com" :: T.Text), "password" Aeson..= ("correct horse" :: T.Text)])
                                Nothing
                    expectStatus 400 loginResp
                    (errObj :: Aeson.Object) <- decodeBody loginResp
                    KeyMap.lookup "error" errObj `shouldBe` Just (Aeson.String "mfa_or_password_blocked")

        it "hook timeout fail_open=false → 400" \env ->
            withHookCleanupFor env HookPasswordVerificationAttempt $
                withDecisionServer slowServer \port -> do
                    seedHookFor env HookPasswordVerificationAttempt port 100 False
                    signupAndConfirmFor env "login-timeout-closed@example.com"
                    loginResp <-
                        runApp env $
                            jsonPost
                                "/token?grant_type=password"
                                (Aeson.object ["email" Aeson..= ("login-timeout-closed@example.com" :: T.Text), "password" Aeson..= ("correct horse" :: T.Text)])
                                Nothing
                    expectStatus 400 loginResp
                    (errObj :: Aeson.Object) <- decodeBody loginResp
                    KeyMap.lookup "error" errObj `shouldBe` Just (Aeson.String "mfa_or_password_blocked")

        it "hook timeout fail_open=true → password check proceeds" \env ->
            withHookCleanupFor env HookPasswordVerificationAttempt $
                withDecisionServer slowServer \port -> do
                    seedHookFor env HookPasswordVerificationAttempt port 100 True
                    signupAndConfirmFor env "login-timeout-open@example.com"
                    loginResp <-
                        runApp env $
                            jsonPost
                                "/token?grant_type=password"
                                (Aeson.object ["email" Aeson..= ("login-timeout-open@example.com" :: T.Text), "password" Aeson..= ("correct horse" :: T.Text)])
                                Nothing
                    expectStatus 200 loginResp

-- ---------------------------------------------------------------------------
-- Hook test helpers
-- ---------------------------------------------------------------------------

withHookCleanup :: TestEnv -> IO a -> IO a
withHookCleanup env =
    bracket_
        (pure ())
        ( withDatabaseConnection
            (testAppEnv env)
            (`execute_` "DELETE FROM auth.hooks WHERE hook_point = 'before-user-created'")
        )

-- | Seed a before-user-created hook row pointing at 127.0.0.1:port.
seedHook :: TestEnv -> Int -> Int -> Bool -> IO ()
seedHook env port timeoutMs failOpen =
    withDatabaseConnection (testAppEnv env) \conn -> do
        let url = ("http://127.0.0.1:" :: String) <> show port <> "/"
        _ <-
            execute
                conn
                "INSERT INTO auth.hooks (hook_point, url, secret, timeout_ms, fail_open, enabled) \
                \VALUES (?, ?, ?, ?, ?, true)"
                ( hookPointName HookBeforeUserCreated
                , url
                , "test-secret" :: String
                , timeoutMs :: Int
                , failOpen
                )
        pure ()

-- | Spin up a WAI application on a free port, run the action, then close the socket.
withDecisionServer :: Application -> (Int -> IO a) -> IO a
withDecisionServer waiApp action = do
    ready <- newEmptyMVar
    sock <- openFreeSocket
    port <- fromIntegral <$> socketPort sock
    _ <- forkIO $ do
        putMVar ready ()
        Warp.runSettingsSocket
            (Warp.setPort port Warp.defaultSettings)
            sock
            waiApp
    takeMVar ready
    threadDelay 10000 -- 10 ms for the server to start accepting
    result <- action port
    close sock
    pure result

openFreeSocket :: IO Socket
openFreeSocket = do
    sock <- socket AF_INET Stream 0
    setSocketOption sock ReuseAddr 1
    bind sock (SockAddrInet 0 0)
    listen sock maxListenQueue
    pure sock

respondJSON :: Aeson.Value -> Application
respondJSON v _req respond =
    respond (responseLBS status200 [("Content-Type", "application/json")] (Aeson.encode v))

allowDecision :: Application
allowDecision = respondJSON (Aeson.object [("decision", Aeson.String "allow")])

rejectDecisionBody :: Application
rejectDecisionBody =
    respondJSON $
        Aeson.object
            [ ("decision", Aeson.String "reject")
            , ("reason", Aeson.String "blocked by operator rule")
            ]

overlayDecision :: Application
overlayDecision =
    respondJSON $
        Aeson.object
            [ ("decision", Aeson.String "allow_with")
            ,
                ( "overlay"
                , Aeson.object
                    [
                        ( "user_metadata"
                        , Aeson.object [("injected", Aeson.String "by-hook")]
                        )
                    ]
                )
            ]

slowServer :: Application
slowServer _req respond = do
    threadDelay 500000 -- 500 ms
    respond (responseLBS status200 [] (Aeson.encode (Aeson.object [("decision", Aeson.String "allow")])))

{- | Sign up a user, fetch the confirmation token from the DB, and verify it.
After return, the user can log in with "correct horse".
-}
signupAndConfirmFor :: TestEnv -> T.Text -> IO ()
signupAndConfirmFor env email = do
    _ <-
        runApp env $
            jsonPost
                "/signup"
                (Aeson.object ["email" Aeson..= email, "password" Aeson..= ("correct horse" :: T.Text)])
                Nothing
    mUser <- withDatabaseConnection (testAppEnv env) (`getUserByEmail` email)
    user <- case mUser of
        Nothing -> error ("signupAndConfirmFor: no user for " <> T.unpack email)
        Just u -> pure u
    token <- case userConfirmationToken user of
        Nothing -> error ("signupAndConfirmFor: no confirmation_token for " <> T.unpack email)
        Just t -> pure t
    _ <-
        runApp env $
            jsonPost
                "/verify"
                (Aeson.object ["type" Aeson..= ("signup" :: T.Text), "token" Aeson..= token])
                Nothing
    pure ()

{- | Seed an arbitrary hook row by HookPoint (the other helpers hard-code
before-user-created).
-}
seedHookFor :: TestEnv -> HookPoint -> Int -> Int -> Bool -> IO ()
seedHookFor env hp port timeoutMs failOpen =
    withDatabaseConnection (testAppEnv env) \conn -> do
        let url = ("http://127.0.0.1:" :: String) <> show port <> "/"
        _ <-
            execute
                conn
                "INSERT INTO auth.hooks (hook_point, url, secret, timeout_ms, fail_open, enabled) \
                \VALUES (?, ?, ?, ?, ?, true)"
                ( hookPointName hp
                , url
                , "test-secret" :: String
                , timeoutMs :: Int
                , failOpen
                )
        pure ()

withHookCleanupFor :: TestEnv -> HookPoint -> IO a -> IO a
withHookCleanupFor env hp =
    bracket_
        (pure ())
        ( withDatabaseConnection (testAppEnv env) \conn -> do
            _ <- execute conn "DELETE FROM auth.hooks WHERE hook_point = ?" (Only (hookPointName hp))
            pure ()
        )

-- ---------------------------------------------------------------------------
-- Utilities
-- ---------------------------------------------------------------------------

extractStringKey :: Aeson.Key -> Aeson.Object -> IO T.Text
extractStringKey k obj =
    case KeyMap.lookup k obj of
        Just (Aeson.String t) -> pure t
        Just other -> error ("key " <> show k <> " was not a string: " <> show other)
        Nothing -> error ("missing key " <> show k <> " in " <> show obj)
