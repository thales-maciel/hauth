{-# LANGUAGE OverloadedStrings #-}

{- | Theme-closing integration spec: one scenario per hook point.
Each test configures the hook via POST /admin/hooks, fires the auth action,
and asserts that the decision is honoured and the signature is verified by
the in-test receiver.
-}
module E2E.HooksSpec (spec) where

import Control.Concurrent (forkIO, threadDelay)
import Control.Concurrent.MVar (newEmptyMVar, putMVar, takeMVar)
import Control.Exception (bracket_)
import qualified Data.Aeson as Aeson
import qualified Data.Aeson.KeyMap as KeyMap
import Data.IORef (IORef, newIORef, readIORef, writeIORef)
import Data.Maybe (fromMaybe)
import qualified Data.Text as T
import qualified Data.Text.Encoding as TE
import Data.Time.Clock.POSIX (getPOSIXTime)
import Database.PostgreSQL.Simple (execute_)
import E2E.Helpers (
    TestEnv (..),
    decodeBody,
    expectStatus,
    jsonPost,
    mintServiceRoleJwt,
    runApp,
 )
import Hauth.Env (withDatabaseConnection)
import Hauth.Hooks.Runner (verifyHookSignature)
import Hauth.Mfa.Totp (TotpSecret (..), decodeBase32)
import Hauth.Mfa.TotpVerify (currentTimeStep, totpCodeAtStep)
import Hauth.User (User (..), getUserByEmail)
import Network.HTTP.Types (status200)
import Network.Socket (
    Family (..),
    SockAddr (..),
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
import qualified Network.Socket as Sock
import Network.Wai (Application, getRequestBodyChunk, requestHeaders, responseLBS)
import qualified Network.Wai.Handler.Warp as Warp
import Test.Hspec (SpecWith, describe, it, shouldBe)

-- The shared signing secret used in every test — kept simple so we can verify
-- signatures from the receiver side without pulling in a key-generation step.
testSecret :: T.Text
testSecret = "integration-test-secret"

spec :: SpecWith TestEnv
spec = do
    describe "before-user-created: allow → signup succeeds (full flow)" $
        it "creates hook via admin API, fires signup, receiver is called with valid sig" \env ->
            withAllHooksCleanup env $ do
                svcJwt <- mintServiceRoleJwt env
                sigRef <- newIORef False
                withCapturingServer testSecret allowBody sigRef \port -> do
                    let hookUrl = "http://127.0.0.1:" <> T.pack (show port) <> "/"
                    createResp <-
                        runApp env $
                            jsonPost
                                "/admin/hooks"
                                ( Aeson.object
                                    [ "hook_point" Aeson..= ("before-user-created" :: T.Text)
                                    , "url" Aeson..= hookUrl
                                    , "secret" Aeson..= testSecret
                                    , "timeout_ms" Aeson..= (2000 :: Int)
                                    ]
                                )
                                (Just svcJwt)
                    expectStatus 200 createResp
                    signupResp <-
                        runApp env $
                            jsonPost
                                "/signup"
                                ( Aeson.object
                                    [ "email" Aeson..= ("hooks-buc-allow@example.com" :: T.Text)
                                    , "password" Aeson..= ("correct horse" :: T.Text)
                                    ]
                                )
                                Nothing
                    -- Hook returned allow → signup succeeds.
                    expectStatus 200 signupResp
                sigOk <- readIORef sigRef
                sigOk `shouldBe` True

    describe "before-user-created: reject → signup returns 400 (full flow)" $
        it "creates hook via admin API, fires signup, receiver rejects" \env ->
            withAllHooksCleanup env $ do
                svcJwt <- mintServiceRoleJwt env
                sigRef <- newIORef False
                withCapturingServer testSecret rejectBody sigRef \port -> do
                    let hookUrl = "http://127.0.0.1:" <> T.pack (show port) <> "/"
                    createResp <-
                        runApp env $
                            jsonPost
                                "/admin/hooks"
                                ( Aeson.object
                                    [ "hook_point" Aeson..= ("before-user-created" :: T.Text)
                                    , "url" Aeson..= hookUrl
                                    , "secret" Aeson..= testSecret
                                    , "timeout_ms" Aeson..= (2000 :: Int)
                                    ]
                                )
                                (Just svcJwt)
                    expectStatus 200 createResp
                    signupResp <-
                        runApp env $
                            jsonPost
                                "/signup"
                                ( Aeson.object
                                    [ "email" Aeson..= ("hooks-buc-reject@example.com" :: T.Text)
                                    , "password" Aeson..= ("correct horse" :: T.Text)
                                    ]
                                )
                                Nothing
                    expectStatus 400 signupResp
                    (errObj :: Aeson.Object) <- decodeBody signupResp
                    KeyMap.lookup "error" errObj `shouldBe` Just (Aeson.String "hook_rejected")
                    mUser <- withDatabaseConnection (testAppEnv env) (`getUserByEmail` "hooks-buc-reject@example.com")
                    mUser `shouldBe` Nothing
                sigOk <- readIORef sigRef
                sigOk `shouldBe` True

    describe "custom-access-token: allow_with → access token issued with overlay (full flow)" $
        it "creates hook via admin API, fires login, token issuance proceeds" \env ->
            withAllHooksCleanup env $ do
                svcJwt <- mintServiceRoleJwt env
                sigRef <- newIORef False
                withCapturingServer testSecret customAccessTokenAllowWithBody sigRef \port -> do
                    let hookUrl = "http://127.0.0.1:" <> T.pack (show port) <> "/"
                    createResp <-
                        runApp env $
                            jsonPost
                                "/admin/hooks"
                                ( Aeson.object
                                    [ "hook_point" Aeson..= ("custom-access-token" :: T.Text)
                                    , "url" Aeson..= hookUrl
                                    , "secret" Aeson..= testSecret
                                    , "timeout_ms" Aeson..= (2000 :: Int)
                                    ]
                                )
                                (Just svcJwt)
                    expectStatus 200 createResp
                    signupAndConfirm env "hooks-cat@example.com"
                    loginResp <-
                        runApp env $
                            jsonPost
                                "/token?grant_type=password"
                                ( Aeson.object
                                    [ "email" Aeson..= ("hooks-cat@example.com" :: T.Text)
                                    , "password" Aeson..= ("correct horse" :: T.Text)
                                    ]
                                )
                                Nothing
                    -- Hook returned allow_with → token still issued (overlay merged).
                    expectStatus 200 loginResp
                    (loginObj :: Aeson.Object) <- decodeBody loginResp
                    KeyMap.member "access_token" loginObj `shouldBe` True
                sigOk <- readIORef sigRef
                sigOk `shouldBe` True

    describe "mfa-verification-attempt: reject → MFA verify returns 400 (full flow)" $
        it "creates hook via admin API, fires MFA verify, receiver rejects" \env ->
            withAllHooksCleanup env $ do
                svcJwt <- mintServiceRoleJwt env
                sigRef <- newIORef False
                withCapturingServer testSecret rejectBody sigRef \port -> do
                    let hookUrl = "http://127.0.0.1:" <> T.pack (show port) <> "/"
                    createResp <-
                        runApp env $
                            jsonPost
                                "/admin/hooks"
                                ( Aeson.object
                                    [ "hook_point" Aeson..= ("mfa-verification-attempt" :: T.Text)
                                    , "url" Aeson..= hookUrl
                                    , "secret" Aeson..= testSecret
                                    , "timeout_ms" Aeson..= (2000 :: Int)
                                    ]
                                )
                                (Just svcJwt)
                    expectStatus 200 createResp
                    (access, factorId, challengeId, code) <- bootstrapMfaFlow env "hooks-mfa-reject@example.com"
                    verifyResp <-
                        runApp env $
                            jsonPost
                                ("/factors/" <> TE.encodeUtf8 factorId <> "/verify")
                                (Aeson.object ["challenge_id" Aeson..= challengeId, "code" Aeson..= code])
                                (Just access)
                    expectStatus 400 verifyResp
                    (errObj :: Aeson.Object) <- decodeBody verifyResp
                    KeyMap.lookup "error" errObj `shouldBe` Just (Aeson.String "mfa_or_password_blocked")
                sigOk <- readIORef sigRef
                sigOk `shouldBe` True

    describe "password-verification-attempt: reject → login returns 400 (full flow)" $
        it "creates hook via admin API, fires login, receiver rejects" \env ->
            withAllHooksCleanup env $ do
                svcJwt <- mintServiceRoleJwt env
                sigRef <- newIORef False
                withCapturingServer testSecret rejectBody sigRef \port -> do
                    let hookUrl = "http://127.0.0.1:" <> T.pack (show port) <> "/"
                    createResp <-
                        runApp env $
                            jsonPost
                                "/admin/hooks"
                                ( Aeson.object
                                    [ "hook_point" Aeson..= ("password-verification-attempt" :: T.Text)
                                    , "url" Aeson..= hookUrl
                                    , "secret" Aeson..= testSecret
                                    , "timeout_ms" Aeson..= (2000 :: Int)
                                    ]
                                )
                                (Just svcJwt)
                    expectStatus 200 createResp
                    signupAndConfirm env "hooks-pva-reject@example.com"
                    loginResp <-
                        runApp env $
                            jsonPost
                                "/token?grant_type=password"
                                ( Aeson.object
                                    [ "email" Aeson..= ("hooks-pva-reject@example.com" :: T.Text)
                                    , "password" Aeson..= ("correct horse" :: T.Text)
                                    ]
                                )
                                Nothing
                    expectStatus 400 loginResp
                    (errObj :: Aeson.Object) <- decodeBody loginResp
                    KeyMap.lookup "error" errObj `shouldBe` Just (Aeson.String "mfa_or_password_blocked")
                sigOk <- readIORef sigRef
                sigOk `shouldBe` True

-- ---------------------------------------------------------------------------
-- Receiver helpers
-- ---------------------------------------------------------------------------

{- | Spin up a WAI server on a free port.

The server verifies the Standard Webhooks signature using @secret@, writes the
result into @sigRef@, and responds with @responseBody@ for every request.
The server thread is left running until the OS reclaims it; Warp shuts down
when the test process exits.
-}
withCapturingServer ::
    T.Text ->
    Aeson.Value ->
    IORef Bool ->
    (Int -> IO a) ->
    IO a
withCapturingServer secret respBody sigRef action = do
    ready <- newEmptyMVar
    sock <- openFreeSocket
    port <- fromIntegral <$> socketPort sock
    close sock
    let settings =
            Warp.setPort port
                . Warp.setHost "127.0.0.1"
                . Warp.setBeforeMainLoop (putMVar ready ())
                $ Warp.defaultSettings
    _ <- forkIO (Warp.runSettings settings (receiverApp secret respBody sigRef))
    takeMVar ready
    threadDelay 5000 -- 5 ms: let the listener socket become ready
    action port

receiverApp :: T.Text -> Aeson.Value -> IORef Bool -> Application
receiverApp secret respBody sigRef req respond = do
    body <- getRequestBodyChunk req
    let hdrs = requestHeaders req
        lookupHdr name = fromMaybe "" (lookup name hdrs)
        wid = lookupHdr "webhook-id"
        wts = lookupHdr "webhook-timestamp"
        wsig = lookupHdr "webhook-signature"
        secretBs = TE.encodeUtf8 secret
        valid = verifyHookSignature secretBs wid wts wsig body
    writeIORef sigRef valid
    respond (responseLBS status200 [("Content-Type", "application/json")] (Aeson.encode respBody))

openFreeSocket :: IO Sock.Socket
openFreeSocket = do
    sock <- socket AF_INET Stream 0
    setSocketOption sock ReuseAddr 1
    bind sock (SockAddrInet 0 0)
    listen sock maxListenQueue
    pure sock

-- ---------------------------------------------------------------------------
-- Decision bodies
-- ---------------------------------------------------------------------------

allowBody :: Aeson.Value
allowBody = Aeson.object [("decision", Aeson.String "allow")]

rejectBody :: Aeson.Value
rejectBody =
    Aeson.object
        [ ("decision", Aeson.String "reject")
        , ("reason", Aeson.String "blocked by integration test")
        ]

customAccessTokenAllowWithBody :: Aeson.Value
customAccessTokenAllowWithBody =
    Aeson.object
        [ ("decision", Aeson.String "allow_with")
        ,
            ( "overlay"
            , Aeson.object
                [ ("app_metadata", Aeson.object [("hook_injected", Aeson.Bool True)])
                ]
            )
        ]

-- ---------------------------------------------------------------------------
-- Test setup helpers
-- ---------------------------------------------------------------------------

-- | Remove all hook rows after each test.
withAllHooksCleanup :: TestEnv -> IO a -> IO a
withAllHooksCleanup env =
    bracket_
        (pure ())
        (withDatabaseConnection (testAppEnv env) (`execute_` "DELETE FROM auth.hooks"))

-- | Signup + email-confirm so a user can log in.
signupAndConfirm :: TestEnv -> T.Text -> IO ()
signupAndConfirm env email = do
    _ <-
        runApp env $
            jsonPost
                "/signup"
                (Aeson.object ["email" Aeson..= email, "password" Aeson..= ("correct horse" :: T.Text)])
                Nothing
    mUser <- withDatabaseConnection (testAppEnv env) (`getUserByEmail` email)
    user <- case mUser of
        Nothing -> error ("signupAndConfirm: no user for " <> T.unpack email)
        Just u -> pure u
    token <- case userConfirmationToken user of
        Nothing -> error ("signupAndConfirm: no confirmation_token for " <> T.unpack email)
        Just t -> pure t
    _ <-
        runApp env $
            jsonPost
                "/verify"
                (Aeson.object ["type" Aeson..= ("signup" :: T.Text), "token" Aeson..= token])
                Nothing
    pure ()

-- | Full MFA bootstrap: signup → confirm → login → enroll → challenge → compute code.
bootstrapMfaFlow :: TestEnv -> T.Text -> IO (T.Text, T.Text, T.Text, T.Text)
bootstrapMfaFlow env email = do
    signupAndConfirm env email
    loginResp <-
        runApp env $
            jsonPost
                "/token?grant_type=password"
                (Aeson.object ["email" Aeson..= email, "password" Aeson..= ("correct horse" :: T.Text)])
                Nothing
    (loginObj :: Aeson.Object) <- decodeBody loginResp
    access <- extractString "access_token" loginObj

    enrollResp <-
        runApp env $
            jsonPost
                "/factors"
                (Aeson.object ["factor_type" Aeson..= ("totp" :: T.Text)])
                (Just access)
    (enrollObj :: Aeson.Object) <- decodeBody enrollResp
    factorId <- extractString "id" enrollObj
    totpObj <- case KeyMap.lookup "totp" enrollObj of
        Just (Aeson.Object t) -> pure t
        other -> error ("bootstrapMfaFlow: expected totp object; got " <> show other)
    secretB32 <- extractString "secret" totpObj
    secretBytes <- case decodeBase32 secretB32 of
        Just bs -> pure bs
        Nothing -> error ("bootstrapMfaFlow: could not decode TOTP secret: " <> T.unpack secretB32)

    challengeResp <-
        runApp env $
            jsonPost
                ("/factors/" <> TE.encodeUtf8 factorId <> "/challenge")
                (Aeson.object [])
                (Just access)
    (challengeObj :: Aeson.Object) <- decodeBody challengeResp
    challengeId <- extractString "id" challengeObj

    now <- getPOSIXTime
    let code = totpCodeAtStep (TotpSecret secretBytes) (currentTimeStep now)
    pure (access, factorId, challengeId, code)

extractString :: Aeson.Key -> Aeson.Object -> IO T.Text
extractString k obj = case KeyMap.lookup k obj of
    Just (Aeson.String t) -> pure t
    other -> error ("expected string at " <> show k <> "; got " <> show other)
