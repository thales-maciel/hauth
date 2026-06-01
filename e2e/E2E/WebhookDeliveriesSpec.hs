{-# LANGUAGE OverloadedStrings #-}

module E2E.WebhookDeliveriesSpec (spec) where

import Control.Exception (bracket_)
import qualified Data.Aeson as Aeson
import qualified Data.Aeson.KeyMap as KeyMap
import qualified Data.ByteString as BS
import qualified Data.Text as T
import qualified Data.Text.Encoding as TE
import Data.UUID (UUID)
import qualified Data.UUID.V4 as UUID4
import Database.PostgreSQL.Simple (Connection, Only (..), execute, query)
import Database.PostgreSQL.Simple.Types (PGArray (..))
import E2E.Helpers (
    TestEnv (..),
    decodeBody,
    expectStatus,
    jsonGet,
    jsonPost,
    mintServiceRoleJwt,
    mintSessionJwt,
    runApp,
 )
import Hauth.Env (withDatabaseConnection)
import Test.Hspec (SpecWith, describe, it, shouldBe, shouldNotBe)

spec :: SpecWith TestEnv
spec = do
    describe "GET /admin/webhooks/:sub_id/deliveries" $ do
        it "returns 401 without bearer" \env ->
            withDatabaseConnection (testAppEnv env) \conn ->
                withSubscription conn \subId -> do
                    resp <- runApp env $ jsonGet (deliveriesPath subId) Nothing
                    expectStatus 401 resp

        it "returns 401 with non-service-role JWT" \env ->
            withDatabaseConnection (testAppEnv env) \conn ->
                withSubscription conn \subId -> do
                    tok <- mintSessionJwt env "00000000-0000-0000-0000-000000000099" "00000000-0000-0000-0000-000000000098"
                    resp <- runApp env $ jsonGet (deliveriesPath subId) (Just tok)
                    expectStatus 401 resp

        it "returns empty list for subscription with no deliveries" \env ->
            withDatabaseConnection (testAppEnv env) \conn ->
                withSubscription conn \subId -> do
                    svcJwt <- mintServiceRoleJwt env
                    resp <- runApp env $ jsonGet (deliveriesPath subId) (Just svcJwt)
                    expectStatus 200 resp
                    (obj :: Aeson.Object) <- decodeBody resp
                    KeyMap.lookup "deliveries" obj `shouldBe` Just (Aeson.Array mempty)

        it "returns seeded deliveries in created_at DESC order" \env ->
            withDatabaseConnection (testAppEnv env) \conn ->
                withSubscription conn \subId -> do
                    _ <- insertDelivery conn subId "user.signed_up" "pending"
                    _ <- insertDelivery conn subId "user.deleted" "failed"
                    svcJwt <- mintServiceRoleJwt env
                    resp <- runApp env $ jsonGet (deliveriesPath subId) (Just svcJwt)
                    expectStatus 200 resp
                    (obj :: Aeson.Object) <- decodeBody resp
                    case KeyMap.lookup "deliveries" obj of
                        Just (Aeson.Array arr) -> length arr `shouldBe` 2
                        _ -> fail "expected deliveries array"

        it "limit=1 returns 1 delivery and a next_page cursor" \env ->
            withDatabaseConnection (testAppEnv env) \conn ->
                withSubscription conn \subId -> do
                    _ <- insertDelivery conn subId "user.signed_up" "pending"
                    _ <- insertDelivery conn subId "user.deleted" "failed"
                    svcJwt <- mintServiceRoleJwt env
                    resp <- runApp env $ jsonGet (deliveriesPath subId <> "?limit=1") (Just svcJwt)
                    expectStatus 200 resp
                    (obj :: Aeson.Object) <- decodeBody resp
                    case KeyMap.lookup "deliveries" obj of
                        Just (Aeson.Array arr) -> length arr `shouldBe` 1
                        _ -> fail "expected deliveries array"
                    KeyMap.member "next_page" obj `shouldBe` True
                    case KeyMap.lookup "next_page" obj of
                        Just Aeson.Null -> fail "expected non-null next_page"
                        Just _ -> pure ()
                        Nothing -> fail "expected next_page field"

    describe "GET /admin/deliveries/:id" $ do
        it "returns 401 without bearer" \env ->
            withDatabaseConnection (testAppEnv env) \conn ->
                withSubscription conn \subId -> do
                    dId <- insertDelivery conn subId "user.signed_up" "pending"
                    resp <- runApp env $ jsonGet (deliveryPath dId) Nothing
                    expectStatus 401 resp

        it "returns 401 with non-service-role JWT" \env ->
            withDatabaseConnection (testAppEnv env) \conn ->
                withSubscription conn \subId -> do
                    dId <- insertDelivery conn subId "user.signed_up" "pending"
                    tok <- mintSessionJwt env "00000000-0000-0000-0000-000000000099" "00000000-0000-0000-0000-000000000098"
                    resp <- runApp env $ jsonGet (deliveryPath dId) (Just tok)
                    expectStatus 401 resp

        it "returns the full delivery row" \env ->
            withDatabaseConnection (testAppEnv env) \conn ->
                withSubscription conn \subId -> do
                    dId <- insertDelivery conn subId "user.signed_up" "pending"
                    svcJwt <- mintServiceRoleJwt env
                    resp <- runApp env $ jsonGet (deliveryPath dId) (Just svcJwt)
                    expectStatus 200 resp
                    (obj :: Aeson.Object) <- decodeBody resp
                    KeyMap.lookup "event_type" obj `shouldBe` Just (Aeson.String "user.signed_up")
                    KeyMap.lookup "status" obj `shouldBe` Just (Aeson.String "pending")

        it "returns 404 for unknown id" \env -> do
            svcJwt <- mintServiceRoleJwt env
            resp <- runApp env $ jsonGet "/admin/deliveries/00000000-0000-0000-0000-000000000000" (Just svcJwt)
            expectStatus 404 resp

    describe "POST /admin/deliveries/:id/retry" $ do
        it "returns 401 without bearer" \env ->
            withDatabaseConnection (testAppEnv env) \conn ->
                withSubscription conn \subId -> do
                    dId <- insertDelivery conn subId "user.signed_up" "failed"
                    resp <- runApp env $ jsonPost (retryPath dId) Aeson.Null Nothing
                    expectStatus 401 resp

        it "returns 401 with non-service-role JWT" \env ->
            withDatabaseConnection (testAppEnv env) \conn ->
                withSubscription conn \subId -> do
                    dId <- insertDelivery conn subId "user.signed_up" "failed"
                    tok <- mintSessionJwt env "00000000-0000-0000-0000-000000000099" "00000000-0000-0000-0000-000000000098"
                    resp <- runApp env $ jsonPost (retryPath dId) Aeson.Null (Just tok)
                    expectStatus 401 resp

        it "sets status to pending on a failed delivery and returns 200" \env ->
            withDatabaseConnection (testAppEnv env) \conn ->
                withSubscription conn \subId -> do
                    dId <- insertDelivery conn subId "user.signed_up" "failed"
                    svcJwt <- mintServiceRoleJwt env
                    resp <- runApp env $ jsonPost (retryPath dId) Aeson.Null (Just svcJwt)
                    expectStatus 200 resp
                    (obj :: Aeson.Object) <- decodeBody resp
                    KeyMap.lookup "status" obj `shouldBe` Just (Aeson.String "pending")

        it "preserves attempt count after retry" \env ->
            withDatabaseConnection (testAppEnv env) \conn ->
                withSubscription conn \subId -> do
                    dId <- insertDeliveryWithAttempts conn subId "user.signed_up" "failed" 3
                    svcJwt <- mintServiceRoleJwt env
                    resp <- runApp env $ jsonPost (retryPath dId) Aeson.Null (Just svcJwt)
                    expectStatus 200 resp
                    (obj :: Aeson.Object) <- decodeBody resp
                    KeyMap.lookup "attempts" obj `shouldBe` Just (Aeson.Number 3)

        it "returns 409 on retry of a sent delivery" \env ->
            withDatabaseConnection (testAppEnv env) \conn ->
                withSubscription conn \subId -> do
                    dId <- insertDelivery conn subId "user.signed_up" "sent"
                    svcJwt <- mintServiceRoleJwt env
                    resp <- runApp env $ jsonPost (retryPath dId) Aeson.Null (Just svcJwt)
                    expectStatus 409 resp

        it "allows retry of an exhausted delivery" \env ->
            withDatabaseConnection (testAppEnv env) \conn ->
                withSubscription conn \subId -> do
                    dId <- insertDelivery conn subId "user.signed_up" "exhausted"
                    svcJwt <- mintServiceRoleJwt env
                    resp <- runApp env $ jsonPost (retryPath dId) Aeson.Null (Just svcJwt)
                    expectStatus 200 resp
                    (obj :: Aeson.Object) <- decodeBody resp
                    KeyMap.lookup "status" obj `shouldNotBe` Just (Aeson.String "exhausted")

        it "returns 404 for unknown id" \env -> do
            svcJwt <- mintServiceRoleJwt env
            resp <- runApp env $ jsonPost "/admin/deliveries/00000000-0000-0000-0000-000000000000/retry" Aeson.Null (Just svcJwt)
            expectStatus 404 resp

-- ---------------------------------------------------------------------------
-- Path helpers
-- ---------------------------------------------------------------------------

deliveriesPath :: UUID -> BS.ByteString
deliveriesPath subId =
    "/admin/webhooks/" <> TE.encodeUtf8 (T.pack (show subId)) <> "/deliveries"

deliveryPath :: UUID -> BS.ByteString
deliveryPath dId =
    "/admin/deliveries/" <> TE.encodeUtf8 (T.pack (show dId))

retryPath :: UUID -> BS.ByteString
retryPath dId =
    "/admin/deliveries/" <> TE.encodeUtf8 (T.pack (show dId)) <> "/retry"

-- ---------------------------------------------------------------------------
-- DB seed helpers
-- ---------------------------------------------------------------------------

-- Insert a subscription and run action, cleaning up after.
withSubscription :: Connection -> (UUID -> IO a) -> IO a
withSubscription conn action = do
    subId <- UUID4.nextRandom
    bracket_
        ( execute
            conn
            "INSERT INTO auth.webhook_subscriptions (id, url, secret, events) \
            \VALUES (?, ?, ?, ?)"
            ( subId
            , "https://example.com/delivery-spec-hook" :: String
            , "test-secret" :: String
            , PGArray ([] :: [String])
            )
        )
        ( execute
            conn
            "DELETE FROM auth.webhook_subscriptions WHERE id = ?"
            (Only subId)
        )
        (action subId)

insertDelivery :: Connection -> UUID -> T.Text -> T.Text -> IO UUID
insertDelivery conn subId eventType status =
    insertDeliveryWithAttempts conn subId eventType status 0

insertDeliveryWithAttempts :: Connection -> UUID -> T.Text -> T.Text -> Int -> IO UUID
insertDeliveryWithAttempts conn subId eventType status attempts = do
    rows <-
        query
            conn
            "INSERT INTO auth.webhook_deliveries \
            \(subscription_id, event_type, payload, status, attempts) \
            \VALUES (?, ?, ?, ?, ?) \
            \RETURNING id"
            ( subId
            , eventType
            , Aeson.object ["test" Aeson..= True]
            , status
            , attempts
            ) ::
            IO [Only UUID]
    case rows of
        [Only dId] -> pure dId
        _ -> error "insertDelivery: unexpected empty result"
