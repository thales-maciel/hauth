module Spec.Hooks.RunnerSpec (spec) where

import Control.Concurrent (forkIO, threadDelay)
import Control.Concurrent.MVar (newEmptyMVar, putMVar, takeMVar)
import Data.Aeson (Value)
import qualified Data.Aeson as Aeson
import qualified Data.ByteString.Char8 as BSC
import Data.Text (Text)
import qualified Data.Text as T
import Data.Time.Clock.POSIX (getPOSIXTime)
import Data.UUID (nil)
import Hauth.Hooks.Runner (
    HookDecision (..),
    SignedHeaders (..),
    runHook,
    signHookRequest,
    verifyHookSignature,
 )
import Hauth.Hooks.Types (HookConfig (..), HookPoint (..))
import Network.HTTP.Client (defaultManagerSettings, newManager)
import Network.HTTP.Types (status200, status500)
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
import Network.Wai (
    Application,
    requestHeaders,
    responseLBS,
 )
import qualified Network.Wai.Handler.Warp as Warp
import Test.Hspec (Spec, describe, expectationFailure, it, runIO, shouldBe)

-- ---------------------------------------------------------------------------
-- Helpers
-- ---------------------------------------------------------------------------

testSecret :: BSC.ByteString
testSecret = "0123456789abcdef0123456789abcdef"

testConfig :: Text -> Int -> Bool -> HookConfig
testConfig url timeoutMs failOpen =
    HookConfig
        { hookConfigId = nil
        , hookConfigPoint = HookBeforeUserCreated
        , hookConfigUrl = url
        , hookConfigSecret = testSecret
        , hookConfigTimeoutMs = timeoutMs
        , hookConfigFailOpen = failOpen
        }

testPayload :: Value
testPayload = Aeson.object ["user_id" Aeson..= ("test-user" :: Text)]

{- | Run a WAI application on a free port, invoke the action with that port,
then clean up the server.
-}
withTestServer :: Application -> (Int -> IO a) -> IO a
withTestServer app action = do
    ready <- newEmptyMVar
    sock <- openFreeSocket
    port <- fromIntegral <$> socketPort sock
    _ <- forkIO $ do
        putMVar ready ()
        Warp.runSettingsSocket
            (Warp.setPort port Warp.defaultSettings)
            sock
            app
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

hookUrl :: Int -> Text
hookUrl port = "http://127.0.0.1:" <> T.pack (show port) <> "/"

respondWith :: Value -> Application
respondWith v _req respond =
    respond (responseLBS status200 [("Content-Type", "application/json")] (Aeson.encode v))

respondWithStatus500 :: Application
respondWithStatus500 _req respond =
    respond (responseLBS status500 [] "internal error")

respondWithMalformed :: Application
respondWithMalformed _req respond =
    respond (responseLBS status200 [] "not json at all {{")

slowServer :: Application
slowServer _req respond = do
    threadDelay 500000 -- 500 ms
    respond (responseLBS status200 [] (Aeson.encode allowDecision))

allowDecision :: Value
allowDecision = Aeson.object [("decision", Aeson.String "allow")]

rejectDecision :: Text -> Value
rejectDecision reason =
    Aeson.object
        [ ("decision", Aeson.String "reject")
        , ("reason", Aeson.String reason)
        ]

allowWithDecision :: Value -> Value
allowWithDecision overlay =
    Aeson.object
        [ ("decision", Aeson.String "allow_with")
        , ("overlay", overlay)
        ]

-- ---------------------------------------------------------------------------
-- Tests
-- ---------------------------------------------------------------------------

spec :: Spec
spec = do
    -- One shared HTTP manager for the whole spec — mirrors the production
    -- pattern where the manager lives on 'AppEnv' and is reused across hooks.
    mgr <- runIO (newManager defaultManagerSettings)
    describe "decisions" $ do
        it "allow decision" $
            withTestServer (respondWith allowDecision) $ \port -> do
                let cfg = testConfig (hookUrl port) 5000 False
                d <- runHook mgr cfg testPayload
                d `shouldBe` HookAllow

        it "reject decision" $
            withTestServer (respondWith (rejectDecision "not allowed")) $ \port -> do
                let cfg = testConfig (hookUrl port) 5000 False
                d <- runHook mgr cfg testPayload
                d `shouldBe` HookReject "not allowed"

        it "allow_with decision" $ do
            let overlay = Aeson.object [("extra_claim", Aeson.String "foo")]
            withTestServer (respondWith (allowWithDecision overlay)) $ \port -> do
                let cfg = testConfig (hookUrl port) 5000 False
                d <- runHook mgr cfg testPayload
                d `shouldBe` HookAllowWith overlay

    describe "timeouts and failures" $ do
        it "timeout fail-closed rejects" $
            withTestServer slowServer $ \port -> do
                let cfg = testConfig (hookUrl port) 50 False -- 50 ms timeout
                d <- runHook mgr cfg testPayload
                case d of
                    HookReject _ -> pure ()
                    other -> expectationFailure ("expected HookReject, got " <> show other)

        it "timeout fail-open allows" $
            withTestServer slowServer $ \port -> do
                let cfg = testConfig (hookUrl port) 50 True -- 50 ms timeout, fail open
                d <- runHook mgr cfg testPayload
                d `shouldBe` HookAllow

        it "500 fail-closed rejects" $
            withTestServer respondWithStatus500 $ \port -> do
                let cfg = testConfig (hookUrl port) 5000 False
                d <- runHook mgr cfg testPayload
                case d of
                    HookReject _ -> pure ()
                    other -> expectationFailure ("expected HookReject, got " <> show other)

        it "malformed body always rejects" $
            withTestServer respondWithMalformed $ \port -> do
                -- failOpen=true should NOT help for malformed body
                let cfg = testConfig (hookUrl port) 5000 True
                d <- runHook mgr cfg testPayload
                d `shouldBe` HookReject "invalid hook response"

    describe "signatures" $ do
        it "sends valid webhook signature headers" $ do
            -- Capture the request headers sent by runHook and verify the signature.
            capturedHeaders <- newEmptyMVar
            let capturingApp req respond = do
                    putMVar capturedHeaders (requestHeaders req)
                    respond (responseLBS status200 [("Content-Type", "application/json")] (Aeson.encode allowDecision))
            withTestServer capturingApp $ \port -> do
                let cfg = testConfig (hookUrl port) 5000 False
                _ <- runHook mgr cfg testPayload
                hdrs <- takeMVar capturedHeaders
                let lookupHdr name = lookup name hdrs
                case (lookupHdr "webhook-id", lookupHdr "webhook-timestamp", lookupHdr "webhook-signature") of
                    (Just _wid, Just _wts, Just wsig) -> do
                        let validFormat = BSC.isPrefixOf "v1," wsig
                        if validFormat
                            then pure ()
                            else expectationFailure ("unexpected sig format: " <> show wsig)
                    _ -> expectationFailure "missing webhook headers"

        it "signing roundtrip verifies" $ do
            now <- getPOSIXTime
            let body = "{\"hook_point\":\"before-user-created\"}"
                hdrs' = signHookRequest testSecret nil now (BSC.pack body)
                ok =
                    verifyHookSignature
                        testSecret
                        (sigWebhookId hdrs')
                        (sigWebhookTimestamp hdrs')
                        (sigWebhookSignature hdrs')
                        (BSC.pack body)
            ok `shouldBe` True

        it "valid signature verifies" $ do
            now <- getPOSIXTime
            let body = "test body"
                hdrs' = signHookRequest testSecret nil now body
                ok =
                    verifyHookSignature
                        testSecret
                        (sigWebhookId hdrs')
                        (sigWebhookTimestamp hdrs')
                        (sigWebhookSignature hdrs')
                        body
            ok `shouldBe` True

        it "wrong secret fails verification" $ do
            now <- getPOSIXTime
            let body = "test body"
                hdrs' = signHookRequest testSecret nil now body
                ok =
                    verifyHookSignature
                        "wrong-secret"
                        (sigWebhookId hdrs')
                        (sigWebhookTimestamp hdrs')
                        (sigWebhookSignature hdrs')
                        body
            ok `shouldBe` False

        it "multi-candidate header with one valid passes" $ do
            now <- getPOSIXTime
            let body = "test body"
                hdrs' = signHookRequest testSecret nil now body
                validSig = sigWebhookSignature hdrs'
                -- Space-separated candidates: one garbage, one valid.
                multiSig = "v1,aGVsbG8= " <> validSig
                ok =
                    verifyHookSignature
                        testSecret
                        (sigWebhookId hdrs')
                        (sigWebhookTimestamp hdrs')
                        multiSig
                        body
            ok `shouldBe` True

        it "malformed candidate returns False" $ do
            now <- getPOSIXTime
            let body = "test body"
                hdrs' = signHookRequest testSecret nil now body
                ok =
                    verifyHookSignature
                        testSecret
                        (sigWebhookId hdrs')
                        (sigWebhookTimestamp hdrs')
                        "not-a-valid-sig-at-all"
                        body
            ok `shouldBe` False
