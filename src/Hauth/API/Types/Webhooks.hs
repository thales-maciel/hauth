{- | Wire types for the admin webhook surfaces: subscriptions CRUD and
delivery inspection.
-}
module Hauth.API.Types.Webhooks (
    WebhookDeliveryId (..),
    WebhookDeliveryResponse (..),
    ListWebhookDeliveriesResponse (..),
    WebhookDeliveriesResponse (..),
    WebhookSubscriptionId (..),
    WebhookSubscriptionResponse (..),
    ListWebhookSubscriptionsResponse (..),
    CreateWebhookSubscriptionRequest (..),
    UpdateWebhookSubscriptionRequest (..),
) where

import Data.Aeson (FromJSON (..), ToJSON (toJSON), Value, object, (.=))
import qualified Data.Aeson as Aeson
import Data.Text (Text)
import Data.Time (UTCTime)
import Data.UUID (UUID)
import GHC.Generics (Generic)
import Web.HttpApiData (FromHttpApiData, ToHttpApiData)

newtype WebhookDeliveryId = WebhookDeliveryId {unWebhookDeliveryId :: Text}
    deriving stock (Eq, Generic, Ord, Show)
    deriving newtype (FromHttpApiData, FromJSON, ToHttpApiData, ToJSON)

-- | Full delivery row returned by GET single and POST retry.
data WebhookDeliveryResponse = WebhookDeliveryResponse
    { webhookDeliveryId :: UUID
    , webhookDeliverySubscriptionId :: UUID
    , webhookDeliveryEventType :: Text
    , webhookDeliveryPayload :: Value
    , webhookDeliveryStatus :: Text
    , webhookDeliveryAttempts :: Int
    , webhookDeliveryNextAttemptAt :: UTCTime
    , webhookDeliveryResponseStatus :: Maybe Int
    , webhookDeliveryResponseBody :: Maybe Text
    , webhookDeliveryLastError :: Maybe Text
    , webhookDeliveryCreatedAt :: UTCTime
    , webhookDeliveryUpdatedAt :: UTCTime
    }
    deriving stock (Eq, Show)

instance ToJSON WebhookDeliveryResponse where
    toJSON WebhookDeliveryResponse{..} =
        object
            [ "id" .= webhookDeliveryId
            , "subscription_id" .= webhookDeliverySubscriptionId
            , "event_type" .= webhookDeliveryEventType
            , "payload" .= webhookDeliveryPayload
            , "status" .= webhookDeliveryStatus
            , "attempts" .= webhookDeliveryAttempts
            , "next_attempt_at" .= webhookDeliveryNextAttemptAt
            , "response_status" .= webhookDeliveryResponseStatus
            , "response_body" .= webhookDeliveryResponseBody
            , "last_error" .= webhookDeliveryLastError
            , "created_at" .= webhookDeliveryCreatedAt
            , "updated_at" .= webhookDeliveryUpdatedAt
            ]

instance FromJSON WebhookDeliveryResponse where
    parseJSON = Aeson.withObject "WebhookDeliveryResponse" \o ->
        WebhookDeliveryResponse
            <$> o Aeson..: "id"
            <*> o Aeson..: "subscription_id"
            <*> o Aeson..: "event_type"
            <*> o Aeson..: "payload"
            <*> o Aeson..: "status"
            <*> o Aeson..: "attempts"
            <*> o Aeson..: "next_attempt_at"
            <*> o Aeson..:? "response_status"
            <*> o Aeson..:? "response_body"
            <*> o Aeson..:? "last_error"
            <*> o Aeson..: "created_at"
            <*> o Aeson..: "updated_at"

data ListWebhookDeliveriesResponse = ListWebhookDeliveriesResponse
    { listDeliveries :: [WebhookDeliveryResponse]
    , listDeliveriesNextPage :: Maybe Int
    }
    deriving stock (Eq, Show)

instance ToJSON ListWebhookDeliveriesResponse where
    toJSON ListWebhookDeliveriesResponse{listDeliveries, listDeliveriesNextPage} =
        object
            [ "deliveries" .= listDeliveries
            , "next_page" .= listDeliveriesNextPage
            ]

instance FromJSON ListWebhookDeliveriesResponse where
    parseJSON = Aeson.withObject "ListWebhookDeliveriesResponse" \o ->
        ListWebhookDeliveriesResponse
            <$> o Aeson..: "deliveries"
            <*> o Aeson..:? "next_page"

-- | Legacy response type kept for the existing AdminWebhookAPI stubs.
newtype WebhookDeliveriesResponse = WebhookDeliveriesResponse
    { webhookDeliveries :: [WebhookDeliveryResponse]
    }
    deriving stock (Eq, Show)

instance ToJSON WebhookDeliveriesResponse where
    toJSON WebhookDeliveriesResponse{webhookDeliveries} =
        object ["deliveries" .= webhookDeliveries]

instance FromJSON WebhookDeliveriesResponse where
    parseJSON = Aeson.withObject "WebhookDeliveriesResponse" \o ->
        WebhookDeliveriesResponse <$> o Aeson..: "deliveries"

newtype WebhookSubscriptionId = WebhookSubscriptionId {unWebhookSubscriptionId :: Text}
    deriving stock (Eq, Generic, Ord, Show)
    deriving newtype (FromHttpApiData, FromJSON, ToHttpApiData, ToJSON)

data WebhookSubscriptionResponse = WebhookSubscriptionResponse
    { webhookSubId :: UUID
    , webhookSubUrl :: Text
    , webhookSubEvents :: [Text]
    , webhookSubSecret :: Text
    , webhookSubDisabledAt :: Maybe UTCTime
    , webhookSubCreatedAt :: UTCTime
    , webhookSubUpdatedAt :: UTCTime
    }
    deriving stock (Eq, Show)

instance ToJSON WebhookSubscriptionResponse where
    toJSON WebhookSubscriptionResponse{..} =
        object
            [ "id" .= webhookSubId
            , "url" .= webhookSubUrl
            , "events" .= webhookSubEvents
            , "secret" .= webhookSubSecret
            , "disabled_at" .= webhookSubDisabledAt
            , "created_at" .= webhookSubCreatedAt
            , "updated_at" .= webhookSubUpdatedAt
            ]

instance FromJSON WebhookSubscriptionResponse where
    parseJSON = Aeson.withObject "WebhookSubscriptionResponse" \o ->
        WebhookSubscriptionResponse
            <$> o Aeson..: "id"
            <*> o Aeson..: "url"
            <*> o Aeson..: "events"
            <*> o Aeson..: "secret"
            <*> o Aeson..:? "disabled_at"
            <*> o Aeson..: "created_at"
            <*> o Aeson..: "updated_at"

newtype ListWebhookSubscriptionsResponse = ListWebhookSubscriptionsResponse
    { listWebhookSubscriptions :: [WebhookSubscriptionResponse]
    }
    deriving stock (Eq, Show)

instance ToJSON ListWebhookSubscriptionsResponse where
    toJSON ListWebhookSubscriptionsResponse{listWebhookSubscriptions} =
        object ["webhooks" .= listWebhookSubscriptions]

instance FromJSON ListWebhookSubscriptionsResponse where
    parseJSON = Aeson.withObject "ListWebhookSubscriptionsResponse" \o ->
        ListWebhookSubscriptionsResponse <$> o Aeson..: "webhooks"

data CreateWebhookSubscriptionRequest = CreateWebhookSubscriptionRequest
    { createWebhookSubUrl :: Text
    , createWebhookSubEvents :: Maybe [Text]
    , createWebhookSubSecret :: Maybe Text
    }
    deriving stock (Eq, Show)

instance FromJSON CreateWebhookSubscriptionRequest where
    parseJSON = Aeson.withObject "CreateWebhookSubscriptionRequest" \o ->
        CreateWebhookSubscriptionRequest
            <$> o Aeson..: "url"
            <*> o Aeson..:? "events"
            <*> o Aeson..:? "secret"

instance ToJSON CreateWebhookSubscriptionRequest where
    toJSON CreateWebhookSubscriptionRequest{..} =
        object
            [ "url" .= createWebhookSubUrl
            , "events" .= createWebhookSubEvents
            , "secret" .= createWebhookSubSecret
            ]

data UpdateWebhookSubscriptionRequest = UpdateWebhookSubscriptionRequest
    { updateWebhookSubUrl :: Maybe Text
    , updateWebhookSubEvents :: Maybe [Text]
    , updateWebhookSubSecret :: Maybe Text
    , updateWebhookSubDisabledAt :: Maybe (Maybe UTCTime)
    }
    deriving stock (Eq, Show)

instance FromJSON UpdateWebhookSubscriptionRequest where
    parseJSON = Aeson.withObject "UpdateWebhookSubscriptionRequest" \o ->
        UpdateWebhookSubscriptionRequest
            <$> o Aeson..:? "url"
            <*> o Aeson..:? "events"
            <*> o Aeson..:? "secret"
            <*> (fmap Just <$> o Aeson..:? "disabled_at")

instance ToJSON UpdateWebhookSubscriptionRequest where
    toJSON UpdateWebhookSubscriptionRequest{..} =
        object
            [ "url" .= updateWebhookSubUrl
            , "events" .= updateWebhookSubEvents
            , "secret" .= updateWebhookSubSecret
            , "disabled_at" .= updateWebhookSubDisabledAt
            ]
