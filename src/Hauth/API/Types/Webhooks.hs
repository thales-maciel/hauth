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
    WebhookSubscriptionCreateResponse (..),
    RotateWebhookSecretRequest (..),
    RotateWebhookSecretResponse (..),
    ListWebhookSubscriptionsResponse (..),
    CreateWebhookSubscriptionRequest (..),
    UpdateWebhookSubscriptionRequest (..),
    toWebhookCreateResponse,
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

-- | Sentinel emitted in place of the real secret on read/list responses.
webhookRedactedSecret :: Text
webhookRedactedSecret = "***redacted***"

{- | Subscription row returned by GET/list. The secret field is always
serialised as @"***redacted***"@ — the real value is retained in the record
for internal use (signing) but is never exposed on read paths.
-}
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
            , "secret" .= webhookRedactedSecret
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

{- | Response type for the create endpoint. Identical shape to
'WebhookSubscriptionResponse' but serialises the real plaintext secret so
operators can configure receivers. After this one-time response the secret
is no longer readable via the API.
-}
data WebhookSubscriptionCreateResponse = WebhookSubscriptionCreateResponse
    { webhookCreateSubId :: UUID
    , webhookCreateSubUrl :: Text
    , webhookCreateSubEvents :: [Text]
    , webhookCreateSubSecret :: Text
    , webhookCreateSubDisabledAt :: Maybe UTCTime
    , webhookCreateSubCreatedAt :: UTCTime
    , webhookCreateSubUpdatedAt :: UTCTime
    }
    deriving stock (Eq, Show)

instance ToJSON WebhookSubscriptionCreateResponse where
    toJSON WebhookSubscriptionCreateResponse{..} =
        object
            [ "id" .= webhookCreateSubId
            , "url" .= webhookCreateSubUrl
            , "events" .= webhookCreateSubEvents
            , "secret" .= webhookCreateSubSecret
            , "disabled_at" .= webhookCreateSubDisabledAt
            , "created_at" .= webhookCreateSubCreatedAt
            , "updated_at" .= webhookCreateSubUpdatedAt
            ]

instance FromJSON WebhookSubscriptionCreateResponse where
    parseJSON = Aeson.withObject "WebhookSubscriptionCreateResponse" \o ->
        WebhookSubscriptionCreateResponse
            <$> o Aeson..: "id"
            <*> o Aeson..: "url"
            <*> o Aeson..: "events"
            <*> o Aeson..: "secret"
            <*> o Aeson..:? "disabled_at"
            <*> o Aeson..: "created_at"
            <*> o Aeson..: "updated_at"

{- | Convert an internal 'WebhookSubscriptionResponse' (which holds the real
secret) into a 'WebhookSubscriptionCreateResponse' that reveals it once.
-}
toWebhookCreateResponse :: WebhookSubscriptionResponse -> WebhookSubscriptionCreateResponse
toWebhookCreateResponse WebhookSubscriptionResponse{..} =
    WebhookSubscriptionCreateResponse
        { webhookCreateSubId = webhookSubId
        , webhookCreateSubUrl = webhookSubUrl
        , webhookCreateSubEvents = webhookSubEvents
        , webhookCreateSubSecret = webhookSubSecret
        , webhookCreateSubDisabledAt = webhookSubDisabledAt
        , webhookCreateSubCreatedAt = webhookSubCreatedAt
        , webhookCreateSubUpdatedAt = webhookSubUpdatedAt
        }

{- | Optional request body for @POST /admin/webhooks\/:id\/rotate-secret@.
If @rotateWebhookSecret@ is absent the server generates a fresh secret.
-}
newtype RotateWebhookSecretRequest = RotateWebhookSecretRequest
    { rotateWebhookSecret :: Maybe Text
    }
    deriving stock (Eq, Show)

instance FromJSON RotateWebhookSecretRequest where
    parseJSON = Aeson.withObject "RotateWebhookSecretRequest" \o ->
        RotateWebhookSecretRequest
            <$> o Aeson..:? "secret"

-- | Response for the rotate endpoint: returns the new plaintext secret once.
newtype RotateWebhookSecretResponse = RotateWebhookSecretResponse
    { rotateWebhookNewSecret :: Text
    }
    deriving stock (Eq, Show)

instance ToJSON RotateWebhookSecretResponse where
    toJSON RotateWebhookSecretResponse{rotateWebhookNewSecret} =
        object ["secret" .= rotateWebhookNewSecret]

instance FromJSON RotateWebhookSecretResponse where
    parseJSON = Aeson.withObject "RotateWebhookSecretResponse" \o ->
        RotateWebhookSecretResponse <$> o Aeson..: "secret"

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

{- | PUT body. The @secret@ field is intentionally absent — updating other
fields does not rotate the secret. Use @POST \/:id\/rotate-secret@ instead.
-}
data UpdateWebhookSubscriptionRequest = UpdateWebhookSubscriptionRequest
    { updateWebhookSubUrl :: Maybe Text
    , updateWebhookSubEvents :: Maybe [Text]
    , updateWebhookSubDisabledAt :: Maybe (Maybe UTCTime)
    }
    deriving stock (Eq, Show)

instance FromJSON UpdateWebhookSubscriptionRequest where
    parseJSON = Aeson.withObject "UpdateWebhookSubscriptionRequest" \o ->
        UpdateWebhookSubscriptionRequest
            <$> o Aeson..:? "url"
            <*> o Aeson..:? "events"
            <*> (fmap Just <$> o Aeson..:? "disabled_at")

instance ToJSON UpdateWebhookSubscriptionRequest where
    toJSON UpdateWebhookSubscriptionRequest{..} =
        object
            [ "url" .= updateWebhookSubUrl
            , "events" .= updateWebhookSubEvents
            , "disabled_at" .= updateWebhookSubDisabledAt
            ]
