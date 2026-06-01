{-# LANGUAGE OverloadedStrings #-}

module E2E.AuthSpec (spec) where

import Control.Concurrent (forkIO, threadDelay)
import Control.Concurrent.MVar (newEmptyMVar, putMVar, takeMVar)
import Control.Exception (bracket_)
import qualified Data.Aeson as Aeson
import qualified Data.Aeson.KeyMap as KeyMap
import qualified Data.ByteString.Lazy as BSL
import qualified Data.Text as T
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

    describe "password-verification-attempt hook" $ do
        it "no hook: login succeeds with correct credentials" \env -> do
            _ <-
                runApp env $
                    jsonPost
                        "/signup"
                        (Aeson.object ["email" Aeson..= ("dave@example.com" :: T.Text), "password" Aeson..= ("correct horse" :: T.Text)])
                        Nothing
            confirmAndVerify env "dave@example.com"
            loginResp <-
                runApp env $
                    jsonPost
                        "/token?grant_type=password"
                        (Aeson.object ["email" Aeson..= ("dave@example.com" :: T.Text), "password" Aeson..= ("correct horse" :: T.Text)])
                        Nothing
            expectStatus 200 loginResp

        it "hook allow: login succeeds with correct password" \env ->
            withHookServer (allowApp env) env HookPasswordVerificationAttempt \port -> do
                seedHook env HookPasswordVerificationAttempt port
                _ <-
                    runApp env $
                        jsonPost
                            "/signup"
                            (Aeson.object ["email" Aeson..= ("eve@example.com" :: T.Text), "password" Aeson..= ("correct horse" :: T.Text)])
                            Nothing
                confirmAndVerify env "eve@example.com"
                loginResp <-
                    runApp env $
                        jsonPost
                            "/token?grant_type=password"
                            (Aeson.object ["email" Aeson..= ("eve@example.com" :: T.Text), "password" Aeson..= ("correct horse" :: T.Text)])
                            Nothing
                expectStatus 200 loginResp

        it "hook allow: login fails with wrong password (hook doesn't override)" \env ->
            withHookServer (allowApp env) env HookPasswordVerificationAttempt \port -> do
                seedHook env HookPasswordVerificationAttempt port
                _ <-
                    runApp env $
                        jsonPost
                            "/signup"
                            (Aeson.object ["email" Aeson..= ("frank@example.com" :: T.Text), "password" Aeson..= ("correct horse" :: T.Text)])
                            Nothing
                confirmAndVerify env "frank@example.com"
                loginResp <-
                    runApp env $
                        jsonPost
                            "/token?grant_type=password"
                            (Aeson.object ["email" Aeson..= ("frank@example.com" :: T.Text), "password" Aeson..= ("wrong" :: T.Text)])
                            Nothing
                expectStatus 400 loginResp
                (errObj :: Aeson.Object) <- decodeBody loginResp
                KeyMap.lookup "error" errObj `shouldBe` Just (Aeson.String "invalid_grant")

        it "hook reject: 400 even with correct password (opaque error)" \env ->
            withHookServer (rejectApp env) env HookPasswordVerificationAttempt \port -> do
                seedHook env HookPasswordVerificationAttempt port
                _ <-
                    runApp env $
                        jsonPost
                            "/signup"
                            (Aeson.object ["email" Aeson..= ("grace@example.com" :: T.Text), "password" Aeson..= ("correct horse" :: T.Text)])
                            Nothing
                confirmAndVerify env "grace@example.com"
                loginResp <-
                    runApp env $
                        jsonPost
                            "/token?grant_type=password"
                            (Aeson.object ["email" Aeson..= ("grace@example.com" :: T.Text), "password" Aeson..= ("correct horse" :: T.Text)])
                            Nothing
                expectStatus 400 loginResp
                (errObj :: Aeson.Object) <- decodeBody loginResp
                -- Error must not reveal whether credentials were correct.
                KeyMap.lookup "error" errObj `shouldBe` Just (Aeson.String "mfa_or_password_blocked")

        it "hook timeout fail_open=false: rejects login" \env ->
            withHookServer (slowApp env) env HookPasswordVerificationAttempt \port -> do
                seedHookWithOpts env HookPasswordVerificationAttempt port 100 False
                _ <-
                    runApp env $
                        jsonPost
                            "/signup"
                            (Aeson.object ["email" Aeson..= ("hank@example.com" :: T.Text), "password" Aeson..= ("correct horse" :: T.Text)])
                            Nothing
                confirmAndVerify env "hank@example.com"
                loginResp <-
                    runApp env $
                        jsonPost
                            "/token?grant_type=password"
                            (Aeson.object ["email" Aeson..= ("hank@example.com" :: T.Text), "password" Aeson..= ("correct horse" :: T.Text)])
                            Nothing
                expectStatus 400 loginResp
                (errObj :: Aeson.Object) <- decodeBody loginResp
                KeyMap.lookup "error" errObj `shouldBe` Just (Aeson.String "mfa_or_password_blocked")

        it "hook timeout fail_open=true: password check proceeds" \env ->
            withHookServer (slowApp env) env HookPasswordVerificationAttempt \port -> do
                seedHookWithOpts env HookPasswordVerificationAttempt port 100 True
                _ <-
                    runApp env $
                        jsonPost
                            "/signup"
                            (Aeson.object ["email" Aeson..= ("iris@example.com" :: T.Text), "password" Aeson..= ("correct horse" :: T.Text)])
                            Nothing
                confirmAndVerify env "iris@example.com"
                loginResp <-
                    runApp env $
                        jsonPost
                            "/token?grant_type=password"
                            (Aeson.object ["email" Aeson..= ("iris@example.com" :: T.Text), "password" Aeson..= ("correct horse" :: T.Text)])
                            Nothing
                expectStatus 200 loginResp

-- ---------------------------------------------------------------------------
-- Hook test helpers
-- ---------------------------------------------------------------------------

-- | Confirm a signed-up user's email via the DB token, returning the access token.
confirmAndVerify :: TestEnv -> T.Text -> IO ()
confirmAndVerify env email = do
    mUser <- withDatabaseConnection (testAppEnv env) (`getUserByEmail` email)
    user <- case mUser of
        Nothing -> error ("confirmAndVerify: no user for " <> T.unpack email)
        Just u -> pure u
    token <- case userConfirmationToken user of
        Nothing -> error ("confirmAndVerify: no confirmation_token for " <> T.unpack email)
        Just t -> pure t
    _ <-
        runApp env $
            jsonPost
                "/verify"
                (Aeson.object ["type" Aeson..= ("signup" :: T.Text), "token" Aeson..= token])
                Nothing
    pure ()

allowResponse :: BSL.ByteString
allowResponse = Aeson.encode (Aeson.object [("decision", Aeson.String "allow")])

rejectResponse :: BSL.ByteString
rejectResponse =
    Aeson.encode
        ( Aeson.object
            [ ("decision", Aeson.String "reject")
            , ("reason", Aeson.String "blocked by operator policy")
            ]
        )

allowApp :: TestEnv -> Application
allowApp _ _req respond =
    respond (responseLBS status200 [("Content-Type", "application/json")] allowResponse)

rejectApp :: TestEnv -> Application
rejectApp _ _req respond =
    respond (responseLBS status200 [("Content-Type", "application/json")] rejectResponse)

slowApp :: TestEnv -> Application
slowApp _ _req respond = do
    threadDelay 500000
    respond (responseLBS status200 [("Content-Type", "application/json")] allowResponse)

-- | Run a Wai app on a free port, invoke action with that port, close after.
withHookServer :: Application -> TestEnv -> HookPoint -> (Int -> IO a) -> IO a
withHookServer hookApp env hp action = do
    ready <- newEmptyMVar
    sock <- openFreeSocket
    port <- fromIntegral <$> socketPort sock
    _ <- forkIO $ do
        putMVar ready ()
        Warp.runSettingsSocket
            (Warp.setPort port Warp.defaultSettings)
            sock
            hookApp
    takeMVar ready
    threadDelay 10000
    result <-
        bracket_
            (pure ())
            ( withDatabaseConnection (testAppEnv env) \conn ->
                execute conn "DELETE FROM auth.hooks WHERE hook_point = ?" (Only (hookPointName hp))
            )
            (action port)
    close sock
    pure result

seedHook :: TestEnv -> HookPoint -> Int -> IO ()
seedHook env hp port = seedHookWithOpts env hp port 2000 False

seedHookWithOpts :: TestEnv -> HookPoint -> Int -> Int -> Bool -> IO ()
seedHookWithOpts env hp port timeoutMs failOpen =
    withDatabaseConnection (testAppEnv env) \conn -> do
        _ <-
            execute
                conn
                "INSERT INTO auth.hooks (hook_point, url, secret, timeout_ms, fail_open, enabled) \
                \VALUES (?, ?, ?, ?, ?, true)"
                ( hookPointName hp
                , "http://127.0.0.1:" <> T.pack (show port) <> "/" :: T.Text
                , "test-secret" :: T.Text
                , timeoutMs :: Int
                , failOpen
                )
        pure ()

openFreeSocket :: IO Socket
openFreeSocket = do
    sock <- socket AF_INET Stream 0
    setSocketOption sock ReuseAddr 1
    bind sock (SockAddrInet 0 0)
    listen sock maxListenQueue
    pure sock

extractStringKey :: Aeson.Key -> Aeson.Object -> IO T.Text
extractStringKey k obj =
    case KeyMap.lookup k obj of
        Just (Aeson.String t) -> pure t
        Just other -> error ("key " <> show k <> " was not a string: " <> show other)
        Nothing -> error ("missing key " <> show k <> " in " <> show obj)
