-- | Wire-shape coverage for the webhook subscription and delivery surfaces.
module Spec.API.Golden.WebhooksSpec (spec) where

import Hauth.API.Types
import Spec.API.Golden.Helpers (
    canonicalWebhookDeliveryResponse,
    canonicalWebhookSubCreateResponse,
    canonicalWebhookSubResponse,
    decodeShape,
    encodeShape,
    roundTrip,
    t0,
    webhookDeliveryJson,
    webhookSubCreateJson,
    webhookSubJson,
 )
import Test.Hspec (Spec, describe, it)

spec :: Spec
spec = do
    describe "Webhook subscriptions" $ do
        -- WebhookSubscriptionResponse: secret always redacted on read/list.
        -- Like HookRow, encode and decode are asymmetric for the secret field.
        it "WebhookSubscriptionResponse encodes with redacted secret" $
            encodeShape
                "WebhookSubscriptionResponse"
                canonicalWebhookSubResponse
                webhookSubJson

        -- WebhookSubscriptionCreateResponse: reveals plaintext secret once.
        it "WebhookSubscriptionCreateResponse round-trips" $
            roundTrip
                "WebhookSubscriptionCreateResponse"
                canonicalWebhookSubCreateResponse
                webhookSubCreateJson

        it "ListWebhookSubscriptionsResponse encodes with redacted secrets" $
            encodeShape
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

        -- UpdateWebhookSubscriptionRequest no longer has a secret field.
        it "UpdateWebhookSubscriptionRequest" $
            roundTrip
                "UpdateWebhookSubscriptionRequest"
                UpdateWebhookSubscriptionRequest
                    { updateWebhookSubUrl = Just "https://example.com/wh2"
                    , updateWebhookSubEvents = Just ["user.signed_up"]
                    , updateWebhookSubDisabledAt = Just (Just t0)
                    }
                "{\"url\":\"https://example.com/wh2\",\"events\":[\"user.signed_up\"]\
                \,\"disabled_at\":\"2026-01-02T03:04:05Z\"}"

        it "RotateWebhookSecretRequest decodes with explicit secret" $
            decodeShape
                "RotateWebhookSecretRequest"
                "{\"secret\":\"newsecret\"}"
                RotateWebhookSecretRequest{rotateWebhookSecret = Just "newsecret"}

        it "RotateWebhookSecretRequest decodes with absent secret" $
            decodeShape
                "RotateWebhookSecretRequest"
                "{}"
                RotateWebhookSecretRequest{rotateWebhookSecret = Nothing}

        it "RotateWebhookSecretResponse" $
            roundTrip
                "RotateWebhookSecretResponse"
                RotateWebhookSecretResponse{rotateWebhookNewSecret = "fresh-secret"}
                "{\"secret\":\"fresh-secret\"}"

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
