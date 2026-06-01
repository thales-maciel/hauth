{-# LANGUAGE OverloadedStrings #-}

module E2E.WebhookOutboxSpec (spec) where

import Control.Exception (bracket_)
import Data.Time (getCurrentTime)
import Data.UUID (UUID)
import qualified Data.UUID.V4 as UUID4
import Database.PostgreSQL.Simple (Connection, Only (..), execute, query)
import Database.PostgreSQL.Simple.Types (PGArray (..))
import E2E.Helpers (TestEnv (..))
import Hauth.Env (withDatabaseConnection)
import Hauth.Webhooks.Events (MfaPayload (..), UserPayload (..), WebhookEvent (..))
import Hauth.Webhooks.Outbox (enqueue)
import Test.Hspec (SpecWith, describe, it, shouldBe)

spec :: SpecWith TestEnv
spec = do
    describe "Outbox.enqueue" do
        it "no subscriptions → no deliveries" \env ->
            withDatabaseConnection (testAppEnv env) \conn -> do
                event <- sampleUserEvent
                enqueue conn event
                n <- countDeliveries conn
                n `shouldBe` (0 :: Int)

        it "empty events array → one delivery (subscribe-all)" \env ->
            withDatabaseConnection (testAppEnv env) \conn -> do
                event <- sampleUserEvent
                withSubscription conn [] \_ -> do
                    enqueue conn event
                    n <- countDeliveries conn
                    n `shouldBe` (1 :: Int)

        it "matching event in events array → one delivery" \env ->
            withDatabaseConnection (testAppEnv env) \conn -> do
                event <- sampleUserEvent
                withSubscription conn ["user.signed_up"] \_ -> do
                    enqueue conn event
                    n <- countDeliveries conn
                    n `shouldBe` (1 :: Int)

        it "non-matching event in events array → zero deliveries" \env ->
            withDatabaseConnection (testAppEnv env) \conn -> do
                event <- sampleUserEvent
                withSubscription conn ["session.revoked"] \_ -> do
                    enqueue conn event
                    n <- countDeliveries conn
                    n `shouldBe` (0 :: Int)

        it "two matching subscriptions → two deliveries" \env ->
            withDatabaseConnection (testAppEnv env) \conn -> do
                event <- sampleUserEvent
                withSubscription conn [] \_ ->
                    withSubscription conn [] \_ -> do
                        enqueue conn event
                        n <- countDeliveries conn
                        n `shouldBe` (2 :: Int)

        it "disabled subscription is skipped" \env ->
            withDatabaseConnection (testAppEnv env) \conn -> do
                event <- sampleUserEvent
                withDisabledSubscription conn \_ -> do
                    enqueue conn event
                    n <- countDeliveries conn
                    n `shouldBe` (0 :: Int)

-- ---------------------------------------------------------------------------
-- Helpers
-- ---------------------------------------------------------------------------

sampleUserEvent :: IO WebhookEvent
sampleUserEvent = do
    uid <- UUID4.nextRandom
    now <- getCurrentTime
    pure $
        UserSignedUp
            UserPayload
                { upUserId = uid
                , upEmail = Just "test@example.com"
                , upCreatedAt = now
                }

-- Insert an enabled subscription, run action, then delete it (and its deliveries).
withSubscription :: Connection -> [String] -> (UUID -> IO a) -> IO a
withSubscription conn events action = do
    subId <- UUID4.nextRandom
    bracket_
        ( execute
            conn
            "INSERT INTO auth.webhook_subscriptions (id, url, secret, events) \
            \VALUES (?, ?, ?, ?)"
            ( subId
            , "https://example.com/webhook" :: String
            , "test-secret" :: String
            , PGArray events
            )
        )
        ( execute
            conn
            "DELETE FROM auth.webhook_subscriptions WHERE id = ?"
            (Only subId)
        )
        (action subId)

-- Insert a disabled subscription (disabled_at IS NOT NULL).
withDisabledSubscription :: Connection -> (UUID -> IO a) -> IO a
withDisabledSubscription conn action = do
    subId <- UUID4.nextRandom
    bracket_
        ( execute
            conn
            "INSERT INTO auth.webhook_subscriptions (id, url, secret, events, disabled_at) \
            \VALUES (?, ?, ?, ?, now())"
            ( subId
            , "https://example.com/webhook" :: String
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

countDeliveries :: Connection -> IO Int
countDeliveries conn = do
    rows <- query conn "SELECT COUNT(*) FROM auth.webhook_deliveries" ()
    pure $ case rows of
        [Only n] -> n
        _ -> 0
