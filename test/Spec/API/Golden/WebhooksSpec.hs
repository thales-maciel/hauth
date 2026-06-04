-- | Wire-shape coverage for the webhook subscription and delivery surfaces.
module Spec.API.Golden.WebhooksSpec (spec) where

import Hauth.API.Types
import Spec.API.Golden.Helpers (
    canonicalWebhookDeliveryResponse,
    canonicalWebhookSubResponse,
    roundTrip,
    t0,
    webhookDeliveryJson,
    webhookSubJson,
 )
import Test.Hspec (Spec, describe, it)

spec :: Spec
spec = do
    describe "Webhook subscriptions" $ do
        it "WebhookSubscriptionResponse" $
            roundTrip
                "WebhookSubscriptionResponse"
                canonicalWebhookSubResponse
                webhookSubJson

        it "ListWebhookSubscriptionsResponse" $
            roundTrip
                "ListWebhookSubscriptionsResponse"
                ListWebhookSubscriptionsResponse{listWebhookSubscriptions = [canonicalWebhookSubResponse]}
                ("{\"webhooks\":[" <> webhookSubJson <> "]}")

        it "CreateWebhookSubscriptionRequest" $
            roundTrip
                "CreateWebhookSubscriptionRequest"
                CreateWebhookSubscriptionRequest
                    { createWebhookSubUrl = "https://example.com/wh"
                    , createWebhookSubEvents = Just ["user.signed_up"]
                    , createWebhookSubSecret = Just "shh"
                    }
                "{\"url\":\"https://example.com/wh\",\"events\":[\"user.signed_up\"],\"secret\":\"shh\"}"

        it "UpdateWebhookSubscriptionRequest" $
            roundTrip
                "UpdateWebhookSubscriptionRequest"
                UpdateWebhookSubscriptionRequest
                    { updateWebhookSubUrl = Just "https://example.com/wh2"
                    , updateWebhookSubEvents = Just ["user.signed_up"]
                    , updateWebhookSubSecret = Just "shh"
                    , updateWebhookSubDisabledAt = Just (Just t0)
                    }
                "{\"url\":\"https://example.com/wh2\",\"events\":[\"user.signed_up\"]\
                \,\"secret\":\"shh\",\"disabled_at\":\"2026-01-02T03:04:05Z\"}"

    describe "Webhook deliveries" $ do
        it "WebhookDeliveryResponse" $
            roundTrip
                "WebhookDeliveryResponse"
                canonicalWebhookDeliveryResponse
                webhookDeliveryJson

        it "ListWebhookDeliveriesResponse" $
            roundTrip
                "ListWebhookDeliveriesResponse"
                ListWebhookDeliveriesResponse
                    { listDeliveries = [canonicalWebhookDeliveryResponse]
                    , listDeliveriesNextPage = Nothing
                    }
                ("{\"deliveries\":[" <> webhookDeliveryJson <> "],\"next_page\":null}")

        it "WebhookDeliveriesResponse" $
            roundTrip
                "WebhookDeliveriesResponse"
                WebhookDeliveriesResponse{webhookDeliveries = [canonicalWebhookDeliveryResponse]}
                ("{\"deliveries\":[" <> webhookDeliveryJson <> "]}")
