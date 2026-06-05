{-# LANGUAGE NumericUnderscores #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RankNTypes #-}

module Hauth.Webhooks.Worker (
    WorkerHandle,
    startWorker,
    stopWorker,
    dispatchPending,
    runOnce,
) where

import Control.Concurrent (MVar, newEmptyMVar, putMVar, threadDelay, tryTakeMVar)
import Control.Concurrent.Async (Async, async, cancel)
import Control.Exception (SomeException, catch, try)
import Control.Monad (when)
import Data.Aeson (Value)
import qualified Data.Aeson as Aeson
import qualified Data.ByteString as BS
import qualified Data.ByteString.Char8 as BSC
import qualified Data.ByteString.Lazy as BSL
import Data.Text (Text)
import qualified Data.Text as T
import qualified Data.Text.Encoding as TE
import Data.Time.Clock.POSIX (getPOSIXTime)
import Data.UUID (UUID)
import Database.PostgreSQL.Simple (Connection, Only (..), execute, query, query_)
import Hauth.Webhooks.Signing (SignedHeaders (..), signRequest)
import Network.HTTP.Client (
    Manager,
    RequestBody (..),
    httpLbs,
    method,
    parseRequest,
    requestBody,
    requestHeaders,
    responseBody,
    responseStatus,
 )
import qualified Network.HTTP.Client as HTTP
import Network.HTTP.Types (statusCode)

-- | Opaque handle; pass to 'stopWorker' to terminate cleanly.
data WorkerHandle = WorkerHandle
    { workerAsync :: Async ()
    , workerStop :: MVar ()
    }

-- | Backoff in seconds, indexed by the attempt count before this attempt.
backoffSeconds :: [Int]
backoffSeconds = [60, 300, 900, 3600, 21_600, 86_400]

backoffForAttempt :: Int -> Int
backoffForAttempt n =
    case drop n backoffSeconds of
        (s : _) -> s
        [] -> 86_400

maxAttempts :: Int
maxAttempts = 6

pollIntervalMicros :: Int
pollIntervalMicros = 1_000_000

{- | Spawn the background delivery worker.

Takes a connection-borrow function to avoid a circular import with Hauth.Env,
and a pre-built HTTP 'Manager'.  In production, pass
'Hauth.Security.OutboundDestination.newOutboundManager' (or a Manager built
from 'Hauth.Security.OutboundDestination.hardenedManagerSettings'); in test
harnesses that target loopback servers, pass a plain
@'newManager' 'defaultManagerSettings'@.

Safe when the DB schema is absent — transient failures are caught and retried.
-}
startWorker :: Manager -> (forall a. (Connection -> IO a) -> IO a) -> IO WorkerHandle
startWorker mgr withConn = do
    stopMVar <- newEmptyMVar
    handle <- async (workerLoop withConn mgr stopMVar)
    pure (WorkerHandle handle stopMVar)

-- | Signal the worker to stop and cancel its thread.
stopWorker :: WorkerHandle -> IO ()
stopWorker WorkerHandle{..} = do
    putMVar workerStop ()
    cancel workerAsync

workerLoop :: (forall a. (Connection -> IO a) -> IO a) -> Manager -> MVar () -> IO ()
workerLoop withConn mgr stopMVar = do
    shouldStop <- tryTakeMVar stopMVar
    case shouldStop of
        Just () -> pure ()
        Nothing -> do
            drainReady withConn mgr
            threadDelay pollIntervalMicros
            workerLoop withConn mgr stopMVar

drainReady :: (forall a. (Connection -> IO a) -> IO a) -> Manager -> IO ()
drainReady withConn mgr = do
    more <- runOnce withConn mgr `catch` (\(_ :: SomeException) -> pure False)
    when more (drainReady withConn mgr)

{- | Drain all currently-pending deliveries on a single connection. Spins
through 'runOnce' until no more rows are claimable. Exposed so e2e tests
can dispatch deterministically without starting/stopping the background
worker thread.

Pass the same 'Manager' as 'startWorker' — in production the caller should
use a manager from 'Hauth.Security.OutboundDestination.newOutboundManager'.
-}
dispatchPending :: Manager -> Connection -> IO ()
dispatchPending mgr conn = do
    let loop = do
            more <- runOnce (\k -> k conn) mgr
            when more loop
    loop

-- | Claim and process one pending delivery. Returns True if a row was found.
runOnce :: (forall a. (Connection -> IO a) -> IO a) -> Manager -> IO Bool
runOnce withConn mgr =
    withConn \conn -> do
        result <- try @SomeException (fetchAndLockDelivery conn)
        case result of
            Left _ -> pure False
            Right Nothing -> pure False
            Right (Just row) -> do
                processingResult <- try @SomeException (processDelivery conn mgr row)
                case processingResult of
                    Right () -> pure True
                    Left _ ->
                        releaseProcessing conn (drId row) `catch` (\(_ :: SomeException) -> pure ())
                            >> pure False

data DeliveryRow = DeliveryRow
    { drId :: UUID
    , drSubscriptionId :: UUID
    , drPayload :: Value
    , drAttempts :: Int
    }

{- | Atomically claim one due pending delivery, flipping it to @processing@.

The inner @SELECT ... FOR UPDATE SKIP LOCKED@ acquires the row lock; the
outer @UPDATE ... RETURNING@ both commits the status transition and hands
back the columns the worker needs.  Concurrent workers either lose the
lock race (their subquery picks nothing and the UPDATE affects zero rows)
or wake up after the winning commit to find the row already
@processing@.  Either way they observe @Nothing@.
-}
fetchAndLockDelivery :: Connection -> IO (Maybe DeliveryRow)
fetchAndLockDelivery conn = do
    rows <-
        query_
            conn
            "UPDATE auth.webhook_deliveries \
            \SET status = 'processing', updated_at = now() \
            \WHERE id = ( \
            \    SELECT id FROM auth.webhook_deliveries \
            \    WHERE status = 'pending' AND next_attempt_at <= now() \
            \    ORDER BY next_attempt_at \
            \    LIMIT 1 \
            \    FOR UPDATE SKIP LOCKED \
            \) \
            \RETURNING id, subscription_id, payload, attempts"
    case rows of
        [] -> pure Nothing
        ((rid, sid, payload, attempts) : _) ->
            pure $ Just (DeliveryRow rid sid payload attempts)

{- | Send the claimed delivery and finalize its row.

The row was flipped to @processing@ by 'fetchAndLockDelivery', so no
extra transaction is needed here — holding a row lock across the HTTP
call would only block other workers.  If the subscription has gone
missing under us, reset the row back to @pending@ (without bumping
attempts) so future loops can re-evaluate it.
-}
processDelivery :: Connection -> Manager -> DeliveryRow -> IO ()
processDelivery conn mgr row@DeliveryRow{..} = do
    mSub <- loadSubscription conn drSubscriptionId
    case mSub of
        Nothing -> releaseProcessing conn drId
        Just (url, secret) -> do
            outcome <- deliverPayload mgr url secret drId drPayload
            recordOutcome conn row outcome

-- | Move a row out of @processing@ back to @pending@ without bumping attempts.
releaseProcessing :: Connection -> UUID -> IO ()
releaseProcessing conn delId = do
    _ <-
        execute
            conn
            "UPDATE auth.webhook_deliveries \
            \SET status = 'pending', updated_at = now() \
            \WHERE id = ? AND status = 'processing'"
            (Only delId)
    pure ()

data DeliveryOutcome
    = DeliverySuccess Int BS.ByteString
    | DeliveryFailure (Maybe Int) (Maybe BS.ByteString) Text

loadSubscription :: Connection -> UUID -> IO (Maybe (Text, Text))
loadSubscription conn subId = do
    rows <-
        query
            conn
            "SELECT url, secret FROM auth.webhook_subscriptions WHERE id = ?"
            (Only subId)
    case rows of
        ((url, secret) : _) -> pure (Just (url, secret))
        [] -> pure Nothing

deliverPayload :: Manager -> Text -> Text -> UUID -> Value -> IO DeliveryOutcome
deliverPayload mgr url secret deliveryId payload = do
    let bodyBytes = BSL.toStrict (Aeson.encode payload)
    now <- getPOSIXTime
    let hdrs = signRequest (TE.encodeUtf8 secret) deliveryId now bodyBytes
    result <- try @SomeException (sendPost mgr url bodyBytes hdrs)
    case result of
        Left err ->
            pure (DeliveryFailure Nothing Nothing (T.pack (show err)))
        Right resp -> do
            let code = statusCode (responseStatus resp)
                body = BS.take 2048 (BSL.toStrict (responseBody resp))
            if code >= 200 && code < 300
                then pure (DeliverySuccess code body)
                else pure (DeliveryFailure (Just code) (Just body) (T.pack ("HTTP " <> show code)))

sendPost :: Manager -> Text -> BS.ByteString -> SignedHeaders -> IO (HTTP.Response BSL.ByteString)
sendPost mgr url body SignedHeaders{..} = do
    baseReq <- parseRequest (T.unpack url)
    let req =
            baseReq
                { method = "POST"
                , requestBody = RequestBodyBS body
                , requestHeaders =
                    [ ("Content-Type", "application/json")
                    , ("webhook-id", sigWebhookId)
                    , ("webhook-timestamp", sigWebhookTimestamp)
                    , ("webhook-signature", sigWebhookSignature)
                    ]
                }
    httpLbs req mgr

recordOutcome :: Connection -> DeliveryRow -> DeliveryOutcome -> IO ()
recordOutcome conn DeliveryRow{..} (DeliverySuccess code body) = do
    _ <-
        execute
            conn
            "UPDATE auth.webhook_deliveries \
            \SET status = 'sent', response_status = ?, response_body = ?, \
            \    last_error = NULL, updated_at = now() \
            \WHERE id = ? AND status = 'processing'"
            (code, BSC.unpack body, drId)
    pure ()
recordOutcome conn DeliveryRow{..} (DeliveryFailure mCode mBody errMsg) = do
    let newAttempts = drAttempts + 1
        backoff = backoffForAttempt drAttempts
    if newAttempts >= maxAttempts
        then do
            _ <-
                execute
                    conn
                    "UPDATE auth.webhook_deliveries \
                    \SET status = 'exhausted', attempts = ?, \
                    \    response_status = ?, response_body = ?, \
                    \    last_error = ?, updated_at = now() \
                    \WHERE id = ? AND status = 'processing'"
                    (newAttempts, mCode, fmap (BSC.unpack . BS.take 2048) mBody, errMsg, drId)
            pure ()
        else do
            _ <-
                execute
                    conn
                    "UPDATE auth.webhook_deliveries \
                    \SET status = 'pending', attempts = ?, \
                    \    next_attempt_at = now() + (? * interval '1 second'), \
                    \    response_status = ?, response_body = ?, \
                    \    last_error = ?, updated_at = now() \
                    \WHERE id = ? AND status = 'processing'"
                    (newAttempts, backoff, mCode, fmap (BSC.unpack . BS.take 2048) mBody, errMsg, drId)
            pure ()
