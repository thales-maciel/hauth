module Hauth.Webhooks.Outbox (
    enqueue,
) where

import Data.Aeson (Value)
import Data.Text (Text)
import Data.UUID (UUID)
import Database.PostgreSQL.Simple (Connection, Only (..), execute, query)
import Hauth.Webhooks.Events (WebhookEvent, eventName, eventPayload)

{- | Insert one @webhook_deliveries@ row per matching enabled subscription.
Runs inside the caller's transaction so delivery is atomic with the mutation.
-}
enqueue :: Connection -> WebhookEvent -> IO ()
enqueue conn event = do
    let name = eventName event
        payload = eventPayload event
    subIds <- matchingSubscriptions conn name
    mapM_ (insertDelivery conn name payload) subIds

{- | Subscriptions that are enabled and subscribe to this event name.
Empty events array means subscribe-all.
-}
matchingSubscriptions :: Connection -> Text -> IO [UUID]
matchingSubscriptions conn name = do
    rows <-
        query
            conn
            "SELECT id \
            \FROM auth.webhook_subscriptions \
            \WHERE disabled_at IS NULL \
            \  AND (cardinality(events) = 0 OR ? = ANY(events))"
            (Only name)
    pure (fmap fromOnly rows)

insertDelivery :: Connection -> Text -> Value -> UUID -> IO ()
insertDelivery conn name payload subId = do
    _ <-
        execute
            conn
            "INSERT INTO auth.webhook_deliveries \
            \    (subscription_id, event_type, payload) \
            \VALUES (?, ?, ?)"
            (subId, name, payload)
    pure ()
