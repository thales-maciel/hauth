module Hauth.Server.WebhookDeliveries (
    getDeliveryHandler,
    listDeliveriesBySubscriptionHandler,
    retryDeliveryHandler,
) where

import Control.Monad.Except (throwError)
import Control.Monad.IO.Class (liftIO)
import Control.Monad.Reader (ReaderT, ask)
import qualified Data.Aeson as Aeson
import qualified Data.Text as T
import Data.Time.Clock (UTCTime)
import Data.UUID (UUID)
import qualified Data.UUID as UUID
import Database.PostgreSQL.Simple (Connection, Only (..), execute, query)
import Database.PostgreSQL.Simple.FromRow (FromRow (..), field)
import Hauth.API.Auth (ServiceRolePrincipal)
import Hauth.API.Types (
    ListWebhookDeliveriesResponse (..),
    WebhookDeliveryId (..),
    WebhookDeliveryResponse (..),
    WebhookSubscriptionId (..),
 )
import Hauth.Env (AppEnv, withDatabaseConnection)
import Servant.Server (Handler, ServerError (errBody), err400, err404, err409)

type AppHandler = ReaderT AppEnv Handler

data RetryError = NotFound | AlreadySent

-- | Internal row type mirroring auth.webhook_deliveries.
data DeliveryRow = DeliveryRow
    { drId :: UUID
    , drSubscriptionId :: UUID
    , drEventType :: T.Text
    , drPayload :: Aeson.Value
    , drStatus :: T.Text
    , drAttempts :: Int
    , drNextAttemptAt :: UTCTime
    , drResponseStatus :: Maybe Int
    , drResponseBody :: Maybe T.Text
    , drLastError :: Maybe T.Text
    , drCreatedAt :: UTCTime
    , drUpdatedAt :: UTCTime
    }

instance FromRow DeliveryRow where
    fromRow =
        DeliveryRow
            <$> field
            <*> field
            <*> field
            <*> field
            <*> field
            <*> field
            <*> field
            <*> field
            <*> field
            <*> field
            <*> field
            <*> field

rowToResponse :: DeliveryRow -> WebhookDeliveryResponse
rowToResponse DeliveryRow{..} =
    WebhookDeliveryResponse
        { webhookDeliveryId = drId
        , webhookDeliverySubscriptionId = drSubscriptionId
        , webhookDeliveryEventType = drEventType
        , webhookDeliveryPayload = drPayload
        , webhookDeliveryStatus = drStatus
        , webhookDeliveryAttempts = drAttempts
        , webhookDeliveryNextAttemptAt = drNextAttemptAt
        , webhookDeliveryResponseStatus = drResponseStatus
        , webhookDeliveryResponseBody = drResponseBody
        , webhookDeliveryLastError = drLastError
        , webhookDeliveryCreatedAt = drCreatedAt
        , webhookDeliveryUpdatedAt = drUpdatedAt
        }

-- | GET /admin/webhooks/:sub_id/deliveries
listDeliveriesBySubscriptionHandler ::
    ServiceRolePrincipal ->
    WebhookSubscriptionId ->
    Maybe Int ->
    Maybe T.Text ->
    AppHandler ListWebhookDeliveriesResponse
listDeliveriesBySubscriptionHandler _ (WebhookSubscriptionId subIdText) mLimit mAfter = do
    subUid <- parseUUID "subscription_id" subIdText
    let lim = min 200 (maybe 50 (max 1) mLimit)
    env <- ask
    rows <- liftIO $ withDatabaseConnection env \conn ->
        selectDeliveries conn subUid lim mAfter
    let nextPage = if length rows == lim then Just lim else Nothing
    pure ListWebhookDeliveriesResponse{listDeliveries = fmap rowToResponse rows, listDeliveriesNextPage = nextPage}

-- | GET /admin/deliveries/:id
getDeliveryHandler ::
    ServiceRolePrincipal ->
    WebhookDeliveryId ->
    AppHandler WebhookDeliveryResponse
getDeliveryHandler _ (WebhookDeliveryId idText) = do
    uid <- parseUUID "delivery_id" idText
    env <- ask
    mRow <- liftIO $ withDatabaseConnection env (`selectDeliveryById` uid)
    case mRow of
        Nothing -> throwError deliveryNotFoundError
        Just row -> pure (rowToResponse row)

-- | POST /admin/deliveries/:id/retry — sets pending, refuses if already sent.
retryDeliveryHandler ::
    ServiceRolePrincipal ->
    WebhookDeliveryId ->
    AppHandler WebhookDeliveryResponse
retryDeliveryHandler _ (WebhookDeliveryId idText) = do
    uid <- parseUUID "delivery_id" idText
    env <- ask
    result <- liftIO $ withDatabaseConnection env \conn -> do
        mRow <- selectDeliveryById conn uid
        case mRow of
            Nothing -> pure (Left NotFound)
            Just row | drStatus row == "sent" -> pure (Left AlreadySent)
            Just _ -> do
                applyRetry conn uid
                mUpdated <- selectDeliveryById conn uid
                pure $ case mUpdated of
                    Nothing -> Left NotFound
                    Just r -> Right r
    case result of
        Left NotFound -> throwError deliveryNotFoundError
        Left AlreadySent ->
            throwError
                err409
                    { errBody =
                        Aeson.encode $
                            Aeson.object
                                [ "error" Aeson..= ("already_sent" :: T.Text)
                                , "msg" Aeson..= ("Cannot retry a delivery that has already been sent" :: T.Text)
                                ]
                    }
        Right row -> pure (rowToResponse row)

-- ---------------------------------------------------------------------------
-- Helpers
-- ---------------------------------------------------------------------------

parseUUID :: T.Text -> T.Text -> AppHandler UUID
parseUUID fieldName idText =
    case UUID.fromText idText of
        Nothing ->
            throwError
                err400
                    { errBody =
                        Aeson.encode $
                            Aeson.object
                                [ "error" Aeson..= ("invalid_id" :: T.Text)
                                , "msg" Aeson..= ("malformed " <> fieldName :: T.Text)
                                ]
                    }
        Just uid -> pure uid

deliveryNotFoundError :: ServerError
deliveryNotFoundError =
    err404
        { errBody =
            Aeson.encode $
                Aeson.object
                    [ "error" Aeson..= ("delivery_not_found" :: T.Text)
                    , "msg" Aeson..= ("Webhook delivery not found" :: T.Text)
                    ]
        }

-- ---------------------------------------------------------------------------
-- DB queries
-- ---------------------------------------------------------------------------

selectDeliveries :: Connection -> UUID -> Int -> Maybe T.Text -> IO [DeliveryRow]
selectDeliveries conn subUid lim Nothing =
    query
        conn
        "SELECT id, subscription_id, event_type, payload, status, attempts, \
        \next_attempt_at, response_status, response_body, last_error, created_at, updated_at \
        \FROM auth.webhook_deliveries \
        \WHERE subscription_id = ? \
        \ORDER BY created_at DESC \
        \LIMIT ?"
        (subUid, lim)
selectDeliveries conn subUid lim (Just afterCursor) =
    query
        conn
        "SELECT id, subscription_id, event_type, payload, status, attempts, \
        \next_attempt_at, response_status, response_body, last_error, created_at, updated_at \
        \FROM auth.webhook_deliveries \
        \WHERE subscription_id = ? AND created_at < ?::timestamptz \
        \ORDER BY created_at DESC \
        \LIMIT ?"
        (subUid, afterCursor, lim)

selectDeliveryById :: Connection -> UUID -> IO (Maybe DeliveryRow)
selectDeliveryById conn uid = do
    rows <-
        query
            conn
            "SELECT id, subscription_id, event_type, payload, status, attempts, \
            \next_attempt_at, response_status, response_body, last_error, created_at, updated_at \
            \FROM auth.webhook_deliveries \
            \WHERE id = ?"
            (Only uid)
    pure $ case rows of
        [r] -> Just r
        _ -> Nothing

applyRetry :: Connection -> UUID -> IO ()
applyRetry conn uid = do
    _ <-
        execute
            conn
            "UPDATE auth.webhook_deliveries \
            \SET status = 'pending', next_attempt_at = now(), updated_at = now() \
            \WHERE id = ?"
            (Only uid)
    pure ()
