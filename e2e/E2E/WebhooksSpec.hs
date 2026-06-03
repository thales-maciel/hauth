{-# LANGUAGE OverloadedStrings #-}

{- | End-to-end webhook delivery test: subscription → auth actions → in-process
receiver → signature verification. Covers the full stack.
-}
module E2E.WebhooksSpec (spec) where

import Control.Concurrent (forkIO)
import Control.Concurrent.MVar (newEmptyMVar, putMVar, takeMVar)
import Control.Exception (bracket_)
import qualified Data.Aeson as Aeson
import qualified Data.Aeson.KeyMap as KeyMap
import qualified Data.ByteString as BS
import Data.IORef (IORef, atomicModifyIORef', newIORef, readIORef)
import qualified Data.Text as T
import qualified Data.Text.Encoding as TE
import Database.PostgreSQL.Simple (Only (..), execute)
import E2E.Helpers (
    TestEnv (..),
    decodeBody,
    expectStatus,
    jsonPost,
    mintServiceRoleJwt,
    runApp,
 )
import Hauth.Env (withDatabaseConnection)
import Hauth.User (User (..), getUserByEmail)
import Hauth.Webhooks.Signing (verifySignature)
import Hauth.Webhooks.Worker (dispatchPending)
import Network.HTTP.Types (HeaderName, RequestHeaders, status200)
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
import Network.Wai (Application, Request, getRequestBodyChunk, requestHeaders, responseLBS)
import qualified Network.Wai.Handler.Warp as Warp
import Test.Hspec (SpecWith, describe, it, shouldBe, shouldSatisfy)

-- | A received webhook request captured by the in-test receiver.
data CapturedRequest = CapturedRequest
    { capHeaders :: RequestHeaders
    , capBody :: BS.ByteString
    }

spec :: SpecWith TestEnv
spec = do
    describe "full webhook delivery pipeline" $
        it "signup + email_confirmed arrive at receiver with valid signatures" \env -> do
            -- 1. Spin up an in-process receiver that collects requests.
            captured <- newIORef ([] :: [CapturedRequest])
            port <- startReceiver captured

            -- 2. Create a subscription via the admin API pointing at the receiver.
            svcJwt <- mintServiceRoleJwt env
            let receiverUrl = "http://127.0.0.1:" <> T.pack (show port) <> "/"
            createResp <-
                runApp env $
                    jsonPost
                        "/admin/webhooks"
                        ( Aeson.object
                            [ "url" Aeson..= receiverUrl
                            , "secret" Aeson..= ("e2e-test-secret" :: T.Text)
                            , "events" Aeson..= ([] :: [T.Text])
                            ]
                        )
                        (Just svcJwt)
            expectStatus 200 createResp
            (subObj :: Aeson.Object) <- decodeBody createResp
            subId <- extractString "id" subObj

            -- Clean up subscription after the test.
            bracket_
                (pure ())
                ( withDatabaseConnection (testAppEnv env) \conn -> do
                    _ <-
                        execute
                            conn
                            "DELETE FROM auth.webhook_subscriptions WHERE id = ?::uuid"
                            (Only subId)
                    pure ()
                )
                $ do
                    -- 3. Sign up a user → triggers UserSignedUp outbox entry.
                    let email = "webhooks-e2e@example.com" :: T.Text
                    _ <-
                        runApp env $
                            jsonPost
                                "/signup"
                                ( Aeson.object
                                    [ "email" Aeson..= email
                                    , "password" Aeson..= ("correct horse battery" :: T.Text)
                                    ]
                                )
                                Nothing

                    -- 4. Confirm the email → triggers UserEmailConfirmed outbox entry.
                    mUser <- withDatabaseConnection (testAppEnv env) (`getUserByEmail` email)
                    token <- case mUser >>= userConfirmationToken of
                        Just t -> pure t
                        Nothing -> error "webhooks-e2e: no confirmation_token after signup"
                    _ <-
                        runApp env $
                            jsonPost
                                "/verify"
                                ( Aeson.object
                                    [ "type" Aeson..= ("signup" :: T.Text)
                                    , "token" Aeson..= token
                                    ]
                                )
                                Nothing

                    -- 5. Run the worker to dispatch the two pending deliveries.
                    withDatabaseConnection (testAppEnv env) dispatchPending

                    -- 6. Poll the receiver IORef (worker is synchronous in tests).
                    reqs <- readIORef captured
                    length reqs `shouldSatisfy` (>= 2)

                    -- 7. Verify signatures on each captured request.
                    let secret = TE.encodeUtf8 "e2e-test-secret"
                    mapM_ (assertValidSignature secret) reqs

-- ---------------------------------------------------------------------------
-- Assertion helpers
-- ---------------------------------------------------------------------------

assertValidSignature :: BS.ByteString -> CapturedRequest -> IO ()
assertValidSignature secret CapturedRequest{capHeaders, capBody} = do
    let wId = lookupHeader "webhook-id" capHeaders
        wTs = lookupHeader "webhook-timestamp" capHeaders
        wSig = lookupHeader "webhook-signature" capHeaders
    (wId, wTs, wSig) `shouldSatisfy` \(i, t, s) ->
        not (BS.null i) && not (BS.null t) && not (BS.null s)
    ok <- verifySignature secret wId wTs wSig capBody
    ok `shouldBe` True

lookupHeader :: HeaderName -> RequestHeaders -> BS.ByteString
lookupHeader name hdrs =
    case lookup name hdrs of
        Just v -> v
        Nothing -> ""

-- ---------------------------------------------------------------------------
-- In-process Warp receiver
-- ---------------------------------------------------------------------------

startReceiver :: IORef [CapturedRequest] -> IO Int
startReceiver ref = do
    ready <- newEmptyMVar
    probe <- openFreeSocket
    port <- fromIntegral <$> socketPort probe
    close probe
    let settings =
            Warp.setPort port
                . Warp.setHost "127.0.0.1"
                . Warp.setBeforeMainLoop (putMVar ready ())
                $ Warp.defaultSettings
    _ <- forkIO (Warp.runSettings settings (receiverApp ref))
    takeMVar ready
    pure port

openFreeSocket :: IO Sock.Socket
openFreeSocket = do
    sock <- socket AF_INET Stream 0
    setSocketOption sock ReuseAddr 1
    bind sock (SockAddrInet 0 0)
    listen sock maxListenQueue
    pure sock

-- | Accept every request; store headers + body; respond 200.
receiverApp :: IORef [CapturedRequest] -> Application
receiverApp ref req respond = do
    body <- strictRequestBody req
    let hdrs = requestHeaders req
    atomicModifyIORef' ref (\xs -> (xs ++ [CapturedRequest hdrs body], ()))
    respond (responseLBS status200 [("Content-Type", "application/json")] "{}")

strictRequestBody :: Request -> IO BS.ByteString
strictRequestBody req = do
    chunk <- getRequestBodyChunk req
    if BS.null chunk
        then pure BS.empty
        else do
            rest <- strictRequestBody req
            pure (chunk <> rest)

-- ---------------------------------------------------------------------------
-- Misc helpers
-- ---------------------------------------------------------------------------

extractString :: Aeson.Key -> Aeson.Object -> IO T.Text
extractString k obj = case KeyMap.lookup k obj of
    Just (Aeson.String t) -> pure t
    other -> error ("expected string at " <> show k <> "; got " <> show other)
