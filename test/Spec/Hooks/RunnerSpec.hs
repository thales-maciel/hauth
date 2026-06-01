module Spec.Hooks.RunnerSpec (runSpec) where

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
import Spec.TestUtils (assertEqual)

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

runSpec :: IO ()
runSpec = do
    testAllowDecision
    testRejectDecision
    testAllowWithDecision
    testTimeoutFailClosed
    testTimeoutFailOpen
    test500FailClosed
    testMalformedResponseFailOpen
    testSignatureIsValid

testAllowDecision :: IO ()
testAllowDecision =
    withTestServer (respondWith allowDecision) \port -> do
        let cfg = testConfig (hookUrl port) 5000 False
        d <- runHook cfg testPayload
        assertEqual "allow decision" HookAllow d

testRejectDecision :: IO ()
testRejectDecision =
    withTestServer (respondWith (rejectDecision "not allowed")) \port -> do
        let cfg = testConfig (hookUrl port) 5000 False
        d <- runHook cfg testPayload
        assertEqual "reject decision" (HookReject "not allowed") d

testAllowWithDecision :: IO ()
testAllowWithDecision = do
    let overlay = Aeson.object [("extra_claim", Aeson.String "foo")]
    withTestServer (respondWith (allowWithDecision overlay)) \port -> do
        let cfg = testConfig (hookUrl port) 5000 False
        d <- runHook cfg testPayload
        assertEqual "allow_with decision" (HookAllowWith overlay) d

testTimeoutFailClosed :: IO ()
testTimeoutFailClosed =
    withTestServer slowServer \port -> do
        let cfg = testConfig (hookUrl port) 50 False -- 50 ms timeout
        d <- runHook cfg testPayload
        case d of
            HookReject _ -> pure ()
            other -> fail ("testTimeoutFailClosed: expected HookReject, got " <> show other)

testTimeoutFailOpen :: IO ()
testTimeoutFailOpen =
    withTestServer slowServer \port -> do
        let cfg = testConfig (hookUrl port) 50 True -- 50 ms timeout, fail open
        d <- runHook cfg testPayload
        assertEqual "timeout fail-open" HookAllow d

test500FailClosed :: IO ()
test500FailClosed =
    withTestServer respondWithStatus500 \port -> do
        let cfg = testConfig (hookUrl port) 5000 False
        d <- runHook cfg testPayload
        case d of
            HookReject _ -> pure ()
            other -> fail ("test500FailClosed: expected HookReject, got " <> show other)

testMalformedResponseFailOpen :: IO ()
testMalformedResponseFailOpen =
    withTestServer respondWithMalformed \port -> do
        -- failOpen=true should NOT help for malformed body
        let cfg = testConfig (hookUrl port) 5000 True
        d <- runHook cfg testPayload
        assertEqual "malformed body always rejects" (HookReject "invalid hook response") d

testSignatureIsValid :: IO ()
testSignatureIsValid = do
    -- Capture the request headers sent by runHook and verify the signature.
    capturedHeaders <- newEmptyMVar
    let capturingApp req respond = do
            putMVar capturedHeaders (requestHeaders req)
            respond (responseLBS status200 [("Content-Type", "application/json")] (Aeson.encode allowDecision))
    withTestServer capturingApp \port -> do
        let cfg = testConfig (hookUrl port) 5000 False
        _ <- runHook cfg testPayload
        hdrs <- takeMVar capturedHeaders
        let lookupHdr name = lookup name hdrs
        case (lookupHdr "webhook-id", lookupHdr "webhook-timestamp", lookupHdr "webhook-signature") of
            (Just _wid, Just _wts, Just wsig) -> do
                -- We don't have the body here, but we can verify the signing roundtrip
                -- by re-signing with the same inputs and checking the sig format.
                let validFormat = BSC.isPrefixOf "v1," wsig
                if validFormat
                    then pure ()
                    else fail ("testSignatureIsValid: unexpected sig format: " <> show wsig)
            _ -> fail "testSignatureIsValid: missing webhook headers"

    -- Also verify the signing roundtrip directly.
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
    if ok
        then pure ()
        else fail "testSignatureIsValid: roundtrip verify failed"
