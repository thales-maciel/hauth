{-# LANGUAGE NumericUnderscores #-}
{-# LANGUAGE OverloadedStrings #-}

module E2E.WebhookWorkerSpec (spec) where

import Control.Concurrent (threadDelay)
import Control.Concurrent.Async (withAsync)
import Control.Exception (bracket, bracket_)
import qualified Data.ByteString as BS
import Data.IORef (atomicWriteIORef, newIORef, readIORef)
import Data.Maybe (fromMaybe)
import qualified Data.Text as T
import Data.UUID (UUID)
import qualified Data.UUID.V4 as UUID4
import Database.PostgreSQL.Simple (Connection, Only (..), execute, query)
import Database.PostgreSQL.Simple.Types (PGArray (..))
import E2E.Helpers (TestEnv (..))
import Hauth.Env (withDatabaseConnection)
import Hauth.Webhooks.Signing (verifySignature)
import Hauth.Webhooks.Worker (startWorker, stopWorker)
import Network.HTTP.Types (status200, status500)
import Network.Wai (Application, Request, getRequestBodyChunk, requestHeaders, responseLBS)
import Network.Wai.Handler.Warp (run)
import Test.Hspec (SpecWith, describe, it, shouldBe, shouldSatisfy)

spec :: SpecWith TestEnv
spec = do
    describe "WebhookWorker" $ do
        it "delivers a pending row to a 200 endpoint → status becomes 'sent'" $ \env ->
            withDatabaseConnection (testAppEnv env) \conn ->
                withSubscription conn (testUrl 18_741) "test-secret-ok" \subId ->
                    withDelivery conn subId \delId -> do
                        resultRef <- newIORef (Nothing :: Maybe (BS.ByteString, BS.ByteString, BS.ByteString, BS.ByteString))
                        let app req respond = do
                                body <- strictBody req
                                let (wId, wTs, wSig) = lookupSigningHeaders req
                                atomicWriteIORef resultRef (Just (wId, wTs, wSig, body))
                                respond (responseLBS status200 [] "ok")
                        withTestServer 18_741 app $
                            withWorker env $ do
                                waitForStatus conn delId "sent" 5_000_000
                                st <- deliveryStatus conn delId
                                st `shouldBe` "sent"
                                -- Verify signature header round-trips through verifySignature.
                                mHdrs <- readIORef resultRef
                                case mHdrs of
                                    Nothing -> fail "server never received a request"
                                    Just (wId, wTs, wSig, reqBody) -> do
                                        ok <-
                                            verifySignature
                                                "test-secret-ok"
                                                wId
                                                wTs
                                                wSig
                                                reqBody
                                        ok `shouldBe` True

        it "500 response triggers retry → attempts increments, status stays 'pending'" $ \env ->
            withDatabaseConnection (testAppEnv env) \conn ->
                withSubscription conn (testUrl 18_742) "test-secret-5xx" \subId ->
                    withDelivery conn subId \delId -> do
                        let app _ respond = respond (responseLBS status500 [] "error")
                        withTestServer 18_742 app $
                            withWorker env $ do
                                waitForAttempts conn delId 1 5_000_000
                                st <- deliveryStatus conn delId
                                st `shouldBe` "pending"
                                att <- deliveryAttempts conn delId
                                att `shouldSatisfy` (>= 1)

        it "exhausts after 6 attempts → status becomes 'exhausted'" $ \env ->
            withDatabaseConnection (testAppEnv env) \conn ->
                withSubscription conn (testUrl 18_743) "test-secret-exhaust" \subId -> do
                    -- Pre-seed with 5 attempts already done and next_attempt_at in the past.
                    delId <- insertDeliveryWithAttempts conn subId 5
                    let app _ respond = respond (responseLBS status500 [] "fail")
                    withTestServer 18_743 app $
                        withWorker env $ do
                            waitForStatus conn delId "exhausted" 5_000_000
                            st <- deliveryStatus conn delId
                            st `shouldBe` "exhausted"
                            _ <-
                                execute
                                    conn
                                    "DELETE FROM auth.webhook_deliveries WHERE id = ?"
                                    (Only delId)
                            pure ()

-- ---------------------------------------------------------------------------
-- Helpers
-- ---------------------------------------------------------------------------

testUrl :: Int -> T.Text
testUrl port = "http://127.0.0.1:" <> T.pack (show port) <> "/webhook"

-- Start a Warp server on the given port, run the action, then stop.
withTestServer :: Int -> Application -> IO a -> IO a
withTestServer port app action =
    withAsync (run port app) \_ -> do
        threadDelay 50_000 -- let the socket bind
        action

-- Start a worker using the given connection function, run action, then stop.
withWorker :: TestEnv -> IO a -> IO a
withWorker env action =
    bracket
        (startWorker (withDatabaseConnection (testAppEnv env)))
        stopWorker
        (const action)

-- Insert an enabled subscription for the given URL + secret.
withSubscription :: Connection -> T.Text -> T.Text -> (UUID -> IO a) -> IO a
withSubscription conn url secret action = do
    subId <- UUID4.nextRandom
    bracket_
        ( execute
            conn
            "INSERT INTO auth.webhook_subscriptions (id, url, secret, events) VALUES (?, ?, ?, ?)"
            (subId, url, secret, PGArray ([] :: [String]))
        )
        ( execute
            conn
            "DELETE FROM auth.webhook_subscriptions WHERE id = ?"
            (Only subId)
        )
        (action subId)

-- Insert a fresh pending delivery with next_attempt_at = now().
withDelivery :: Connection -> UUID -> (UUID -> IO a) -> IO a
withDelivery conn subId action = do
    rows <-
        query
            conn
            "INSERT INTO auth.webhook_deliveries (subscription_id, event_type, payload) \
            \VALUES (?, 'user.signed_up', '{\"user_id\":\"00000000-0000-0000-0000-000000000001\"}') \
            \RETURNING id"
            (Only subId)
    case rows of
        [Only delId] ->
            bracket_
                (pure ())
                ( execute
                    conn
                    "DELETE FROM auth.webhook_deliveries WHERE id = ?"
                    (Only (delId :: UUID))
                )
                (action delId)
        _ -> error "insertDelivery: unexpected result"

-- Insert a delivery pre-set to N attempts with next_attempt_at = now().
insertDeliveryWithAttempts :: Connection -> UUID -> Int -> IO UUID
insertDeliveryWithAttempts conn subId attempts = do
    rows <-
        query
            conn
            "INSERT INTO auth.webhook_deliveries \
            \    (subscription_id, event_type, payload, attempts, next_attempt_at) \
            \VALUES (?, 'user.signed_up', '{\"user_id\":\"00000000-0000-0000-0000-000000000001\"}', ?, now()) \
            \RETURNING id"
            (subId, attempts)
    case rows of
        [Only delId] -> pure delId
        _ -> error "insertDeliveryWithAttempts: unexpected result"

deliveryStatus :: Connection -> UUID -> IO T.Text
deliveryStatus conn delId = do
    rows <-
        query
            conn
            "SELECT status FROM auth.webhook_deliveries WHERE id = ?"
            (Only delId)
    case rows of
        [Only s] -> pure s
        _ -> error "deliveryStatus: row not found"

deliveryAttempts :: Connection -> UUID -> IO Int
deliveryAttempts conn delId = do
    rows <-
        query
            conn
            "SELECT attempts FROM auth.webhook_deliveries WHERE id = ?"
            (Only delId)
    case rows of
        [Only n] -> pure n
        _ -> error "deliveryAttempts: row not found"

-- Poll until the delivery has the expected status, up to maxMicros.
waitForStatus :: Connection -> UUID -> T.Text -> Int -> IO ()
waitForStatus conn delId expected maxMicros
    | maxMicros <= 0 = pure ()
    | otherwise = do
        st <- deliveryStatus conn delId
        if st == expected
            then pure ()
            else do
                threadDelay 100_000
                waitForStatus conn delId expected (maxMicros - 100_000)

-- Poll until attempts >= n.
waitForAttempts :: Connection -> UUID -> Int -> Int -> IO ()
waitForAttempts conn delId minAtt maxMicros
    | maxMicros <= 0 = pure ()
    | otherwise = do
        att <- deliveryAttempts conn delId
        if att >= minAtt
            then pure ()
            else do
                threadDelay 100_000
                waitForAttempts conn delId minAtt (maxMicros - 100_000)

-- Read the entire request body strictly.
strictBody :: Request -> IO BS.ByteString
strictBody req = go mempty
  where
    go acc = do
        chunk <- getRequestBodyChunk req
        if BS.null chunk
            then pure acc
            else go (acc <> chunk)

-- Extract the three signing headers from a request.
lookupSigningHeaders :: Request -> (BS.ByteString, BS.ByteString, BS.ByteString)
lookupSigningHeaders req =
    let hdrs = requestHeaders req
        look k = fromMaybe "" (lookup k hdrs)
     in (look "webhook-id", look "webhook-timestamp", look "webhook-signature")
