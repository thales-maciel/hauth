module Hauth.Server.WebhookSubscriptions (
    createWebhookSubscriptionHandler,
    deleteWebhookSubscriptionHandler,
    getWebhookSubscriptionHandler,
    listWebhookSubscriptionsHandler,
    rotateWebhookSecretHandler,
    updateWebhookSubscriptionHandler,
) where

import Control.Monad.Except (throwError)
import Control.Monad.IO.Class (liftIO)
import Control.Monad.Reader (ReaderT, ask)
import qualified Crypto.Random as CR
import qualified Data.Aeson as Aeson
import Data.ByteArray.Encoding (Base (..), convertToBase)
import qualified Data.ByteString as BS
import Data.Foldable (for_)
import Data.Maybe (fromMaybe)
import qualified Data.Text as T
import qualified Data.Text.Encoding as TE
import Data.Time.Clock (UTCTime)
import Data.UUID (UUID)
import qualified Data.UUID as UUID
import Database.PostgreSQL.Simple (Connection, Only (..), execute, query, query_)
import Database.PostgreSQL.Simple.FromRow (FromRow (..), field)
import Database.PostgreSQL.Simple.Types (PGArray (..))
import Hauth.API.Auth (ServiceRolePrincipal)
import Hauth.API.Types (
    CreateWebhookSubscriptionRequest (..),
    ListWebhookSubscriptionsResponse (..),
    RotateWebhookSecretRequest (..),
    RotateWebhookSecretResponse (..),
    UpdateWebhookSubscriptionRequest (..),
    WebhookSubscriptionCreateResponse (..),
    WebhookSubscriptionId (..),
    WebhookSubscriptionResponse (..),
    toWebhookCreateResponse,
 )
import Hauth.Env (AppEnv, withDatabaseConnection)
import Hauth.Security.OutboundDestination (checkDestination, defaultResolver)
import Servant.API (NoContent (..))
import Servant.Server (Handler, ServerError (errBody), err400, err404, err409)

type AppHandler = ReaderT AppEnv Handler

-- | Internal row type for DB reads. events is a Postgres text[] column.
data SubRow = SubRow
    { subRowId :: UUID
    , subRowUrl :: T.Text
    , subRowEvents :: PGArray T.Text
    , subRowSecret :: T.Text
    , subRowDisabledAt :: Maybe UTCTime
    , subRowCreatedAt :: UTCTime
    , subRowUpdatedAt :: UTCTime
    }

instance FromRow SubRow where
    fromRow =
        SubRow
            <$> field
            <*> field
            <*> field
            <*> field
            <*> field
            <*> field
            <*> field

subRowToResponse :: SubRow -> WebhookSubscriptionResponse
subRowToResponse SubRow{..} =
    WebhookSubscriptionResponse
        { webhookSubId = subRowId
        , webhookSubUrl = subRowUrl
        , webhookSubEvents = fromPGArray subRowEvents
        , webhookSubSecret = subRowSecret
        , webhookSubDisabledAt = subRowDisabledAt
        , webhookSubCreatedAt = subRowCreatedAt
        , webhookSubUpdatedAt = subRowUpdatedAt
        }

{- | POST /admin/webhooks
Returns the plaintext secret once; subsequent GET/list responses redact it.
-}
createWebhookSubscriptionHandler ::
    ServiceRolePrincipal ->
    CreateWebhookSubscriptionRequest ->
    AppHandler WebhookSubscriptionCreateResponse
createWebhookSubscriptionHandler _ req = do
    let url = createWebhookSubUrl req
        events = fromMaybe [] (createWebhookSubEvents req)
    validateUrl url
    secret <- case createWebhookSubSecret req of
        Just s -> pure s
        Nothing -> liftIO generateSecret
    env <- ask
    result <- liftIO $ withDatabaseConnection env \conn ->
        insertSubscription conn url events secret
    case result of
        Left () ->
            throwError
                err409
                    { errBody =
                        Aeson.encode $
                            Aeson.object
                                [ "error" Aeson..= ("duplicate_url" :: T.Text)
                                , "msg" Aeson..= ("A subscription for this URL already exists" :: T.Text)
                                ]
                    }
        Right sub -> pure (toWebhookCreateResponse sub)

-- | GET /admin/webhooks
listWebhookSubscriptionsHandler ::
    ServiceRolePrincipal ->
    AppHandler ListWebhookSubscriptionsResponse
listWebhookSubscriptionsHandler _ = do
    env <- ask
    subs <- liftIO $ withDatabaseConnection env selectAllSubscriptions
    pure ListWebhookSubscriptionsResponse{listWebhookSubscriptions = subs}

-- | GET /admin/webhooks/:id
getWebhookSubscriptionHandler ::
    ServiceRolePrincipal ->
    WebhookSubscriptionId ->
    AppHandler WebhookSubscriptionResponse
getWebhookSubscriptionHandler _ (WebhookSubscriptionId idText) = do
    uid <- parseSubId idText
    env <- ask
    mSub <- liftIO $ withDatabaseConnection env (`selectSubscriptionById` uid)
    case mSub of
        Nothing -> throwError subNotFoundError
        Just sub -> pure sub

{- | PUT /admin/webhooks/:id
Updates URL, events, and disabled_at. Secret is NOT updated here; use
POST \/:id\/rotate-secret to rotate the signing secret.
-}
updateWebhookSubscriptionHandler ::
    ServiceRolePrincipal ->
    WebhookSubscriptionId ->
    UpdateWebhookSubscriptionRequest ->
    AppHandler WebhookSubscriptionResponse
updateWebhookSubscriptionHandler _ (WebhookSubscriptionId idText) req = do
    uid <- parseSubId idText
    for_ (updateWebhookSubUrl req) validateUrl
    env <- ask
    mSub <- liftIO $ withDatabaseConnection env \conn -> do
        mExisting <- selectSubscriptionById conn uid
        case mExisting of
            Nothing -> pure Nothing
            Just existing -> do
                let url' = fromMaybe (webhookSubUrl existing) (updateWebhookSubUrl req)
                    events' = fromMaybe (webhookSubEvents existing) (updateWebhookSubEvents req)
                    -- Secret is intentionally NOT changed via PUT.
                    secret' = webhookSubSecret existing
                    disabledAt' = case updateWebhookSubDisabledAt req of
                        Nothing -> webhookSubDisabledAt existing
                        Just v -> v
                applySubscriptionUpdate conn uid url' events' secret' disabledAt'
                selectSubscriptionById conn uid
    case mSub of
        Nothing -> throwError subNotFoundError
        Just sub -> pure sub

{- | POST /admin/webhooks/:id/rotate-secret
Rotate the HMAC signing secret. Supply @{"secret":"..."}@ to use a
caller-provided value, or omit the body to have the server generate a
fresh 32-byte hex secret. Returns the new secret once as
@{"secret":"<plaintext>"}@; subsequent reads will redact it.
-}
rotateWebhookSecretHandler ::
    ServiceRolePrincipal ->
    WebhookSubscriptionId ->
    RotateWebhookSecretRequest ->
    AppHandler RotateWebhookSecretResponse
rotateWebhookSecretHandler _ (WebhookSubscriptionId idText) req = do
    uid <- parseSubId idText
    env <- ask
    mSub <- liftIO $ withDatabaseConnection env (`selectSubscriptionById` uid)
    case mSub of
        Nothing -> throwError subNotFoundError
        Just _ -> do
            newSecret <- case rotateWebhookSecret req of
                Just s -> pure s
                Nothing -> liftIO generateSecret
            _ <- liftIO $
                withDatabaseConnection env \conn ->
                    execute
                        conn
                        "UPDATE auth.webhook_subscriptions \
                        \SET secret = ?, updated_at = now() WHERE id = ?"
                        (newSecret, uid)
            pure RotateWebhookSecretResponse{rotateWebhookNewSecret = newSecret}

-- | DELETE /admin/webhooks/:id
deleteWebhookSubscriptionHandler ::
    ServiceRolePrincipal ->
    WebhookSubscriptionId ->
    AppHandler NoContent
deleteWebhookSubscriptionHandler _ (WebhookSubscriptionId idText) = do
    uid <- parseSubId idText
    env <- ask
    n <- liftIO $ withDatabaseConnection env (`deleteSubscription` uid)
    if n == 0
        then throwError subNotFoundError
        else pure NoContent

-- ---------------------------------------------------------------------------
-- Helpers
-- ---------------------------------------------------------------------------

-- Validate that a URL is an absolute http:// or https:// URI
-- with a publicly-routable destination.
validateUrl :: T.Text -> AppHandler ()
validateUrl url = do
    result <- liftIO (checkDestination defaultResolver url)
    case result of
        Right () -> pure ()
        Left _ ->
            throwError
                err400
                    { errBody =
                        Aeson.encode $
                            Aeson.object
                                [ "error" Aeson..= ("invalid_url" :: T.Text)
                                , "msg" Aeson..= ("url must be an absolute http:// or https:// URI with a publicly-routable destination" :: T.Text)
                                ]
                    }

parseSubId :: T.Text -> AppHandler UUID
parseSubId idText =
    case UUID.fromText idText of
        Nothing ->
            throwError
                err400
                    { errBody =
                        Aeson.encode $
                            Aeson.object
                                [ "error" Aeson..= ("invalid_subscription_id" :: T.Text)
                                , "msg" Aeson..= ("malformed subscription id" :: T.Text)
                                ]
                    }
        Just uid -> pure uid

generateSecret :: IO T.Text
generateSecret = do
    bytes <- CR.getRandomBytes 32 :: IO BS.ByteString
    pure (TE.decodeUtf8 (convertToBase Base16 bytes))

subNotFoundError :: ServerError
subNotFoundError =
    err404
        { errBody =
            Aeson.encode $
                Aeson.object
                    [ "error" Aeson..= ("subscription_not_found" :: T.Text)
                    , "msg" Aeson..= ("Webhook subscription not found" :: T.Text)
                    ]
        }

-- ---------------------------------------------------------------------------
-- DB queries
-- ---------------------------------------------------------------------------

selectAllSubscriptions :: Connection -> IO [WebhookSubscriptionResponse]
selectAllSubscriptions conn = do
    rows <-
        query_
            conn
            "SELECT id, url, events, secret, disabled_at, created_at, updated_at \
            \FROM auth.webhook_subscriptions \
            \ORDER BY created_at" ::
            IO [SubRow]
    pure (fmap subRowToResponse rows)

selectSubscriptionById :: Connection -> UUID -> IO (Maybe WebhookSubscriptionResponse)
selectSubscriptionById conn uid = do
    rows <-
        query
            conn
            "SELECT id, url, events, secret, disabled_at, created_at, updated_at \
            \FROM auth.webhook_subscriptions \
            \WHERE id = ?"
            (Only uid) ::
            IO [SubRow]
    pure $ case rows of
        [r] -> Just (subRowToResponse r)
        _ -> Nothing

insertSubscription ::
    Connection ->
    T.Text ->
    [T.Text] ->
    T.Text ->
    IO (Either () WebhookSubscriptionResponse)
insertSubscription conn url events secret = do
    existing <-
        query
            conn
            "SELECT id FROM auth.webhook_subscriptions WHERE url = ?"
            (Only url) ::
            IO [Only UUID]
    case existing of
        (_ : _) -> pure (Left ())
        [] -> do
            rows <-
                query
                    conn
                    "INSERT INTO auth.webhook_subscriptions (url, events, secret) \
                    \VALUES (?, ?, ?) \
                    \RETURNING id, url, events, secret, disabled_at, created_at, updated_at"
                    (url, PGArray events, secret) ::
                    IO [SubRow]
            case rows of
                [r] -> pure (Right (subRowToResponse r))
                _ -> error "insertSubscription: unexpected empty result"

applySubscriptionUpdate ::
    Connection ->
    UUID ->
    T.Text ->
    [T.Text] ->
    T.Text ->
    Maybe UTCTime ->
    IO ()
applySubscriptionUpdate conn uid url events secret disabledAt = do
    _ <-
        execute
            conn
            "UPDATE auth.webhook_subscriptions \
            \SET url = ?, events = ?, secret = ?, disabled_at = ?, updated_at = now() \
            \WHERE id = ?"
            (url, PGArray events, secret, disabledAt, uid)
    pure ()

deleteSubscription :: Connection -> UUID -> IO Int
deleteSubscription conn uid = do
    n <-
        execute
            conn
            "DELETE FROM auth.webhook_subscriptions WHERE id = ?"
            (Only uid)
    pure (fromIntegral n)
