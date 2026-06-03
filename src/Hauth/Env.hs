{- | Application-wide runtime environment.

Construction is split into two phases so callers can sequence migrations and
background-service startup explicitly:

* 'createAppEnv' / 'createAppEnvWithLogger' build the cheap dependencies
  (logger, connection pool, empty template cache). No I/O against the schema
  is performed beyond opening a pool connection on first use, so a freshly
  created 'AppEnv' is safe to hold across migrations and one-shot CLI
  subcommands like @hauth verify@.
* 'startBackgroundServices' spawns the webhook delivery worker and the
  template-cache LISTEN/NOTIFY listener; both expect a migrated schema.
  Callers (server bootstrap, e2e harness) run this after migrations.

'destroyAppEnv' only releases pool resources. Background services have their
own 'stopBackgroundServices' lifecycle.
-}
module Hauth.Env (
    AppEnv (..),
    BackgroundServices,
    BackgroundServiceName (..),
    BackgroundServiceStatus (..),
    BackgroundServiceStatuses,
    ConnectionPool,
    LogLevel (..),
    Logger (..),
    backgroundServiceStatusChecks,
    createAppEnv,
    createAppEnvWithLogger,
    destroyAppEnv,
    readBackgroundServiceStatus,
    recordBackgroundServiceStatus,
    requireBackgroundServices,
    startBackgroundServices,
    startBackgroundServicesWith,
    startRequiredBackgroundServices,
    stdoutLogger,
    stopBackgroundServices,
    withDatabaseConnection,
) where

import Control.Exception (SomeAsyncException, SomeException, bracketOnError, fromException, throwIO, try)
import Data.IORef (IORef, newIORef, readIORef, writeIORef)
import Data.Pool (Pool, createPool, destroyAllResources, withResource)
import Data.Text (Text)
import qualified Data.Text as T
import qualified Data.Text.Encoding as TE
import Data.Time (NominalDiffTime)
import Database.PostgreSQL.Simple (Connection, close, connectPostgreSQL)
import Hauth.Config (Config (..), DatabaseConfig (..))
import Hauth.Email.TemplateCache (
    TemplateCache,
    TemplateCacheListener,
    newTemplateCache,
    startTemplateCacheListener,
    stopTemplateCacheListener,
 )
import Hauth.Webhooks.Worker (WorkerHandle, startWorker, stopWorker)

data AppEnv = AppEnv
    { appConfig :: Config
    , appLogger :: Logger
    , appConnectionPool :: ConnectionPool
    , appTemplateCache :: TemplateCache
    , appBackgroundServiceStatuses :: BackgroundServiceStatuses
    }

{- | Handles for background workers/listeners spawned by
'startBackgroundServices'. Pass to 'stopBackgroundServices' on shutdown.

Each field is 'Maybe' because a startup failure for one service does not
fail-stop the whole 'AppEnv' — e.g. the webhook worker tolerates a missing
@auth.webhook_deliveries@ table during e2e setup.
-}
data BackgroundServices = BackgroundServices
    { bgWebhookWorker :: Maybe WorkerHandle
    , bgTemplateCacheListener :: Maybe TemplateCacheListener
    , bgServiceStatuses :: BackgroundServiceStatuses
    }

data BackgroundServiceName
    = WebhookWorker
    | TemplateListener
    deriving stock (Eq, Show)

data BackgroundServiceStatus
    = BackgroundServiceNotStarted
    | BackgroundServiceRunning
    | BackgroundServiceFailed Text
    | BackgroundServiceStopped
    deriving stock (Eq, Show)

data BackgroundServiceStatuses = BackgroundServiceStatuses
    { webhookWorkerStatus :: IORef BackgroundServiceStatus
    , templateListenerStatus :: IORef BackgroundServiceStatus
    }

newtype ConnectionPool = ConnectionPool
    { unConnectionPool :: Pool Connection
    }

data LogLevel
    = LogDebug
    | LogInfo
    | LogWarn
    | LogError
    deriving stock (Eq, Show)

newtype Logger = Logger
    { logMessage :: LogLevel -> Text -> IO ()
    }

createAppEnv :: Config -> IO AppEnv
createAppEnv =
    createAppEnvWithLogger stdoutLogger

createAppEnvWithLogger :: Logger -> Config -> IO AppEnv
createAppEnvWithLogger logger config = do
    pool <- createConnectionPool config
    cache <- newTemplateCache
    statuses <- newBackgroundServiceStatuses
    pure
        AppEnv
            { appConfig = config
            , appLogger = logger
            , appConnectionPool = pool
            , appTemplateCache = cache
            , appBackgroundServiceStatuses = statuses
            }

{- | Spawn the webhook delivery worker and the template-cache LISTEN/NOTIFY
listener. Both expect a migrated schema and a reachable DB — call this AFTER
@hauth migrate up@.

Per-service failures are tolerated: if a service throws on startup the
corresponding 'BackgroundServices' field is 'Nothing' and the rest of the
process keeps running. This matters for e2e harnesses that race service
startup against truncation/migration windows.
-}
startBackgroundServices :: AppEnv -> IO BackgroundServices
startBackgroundServices env@AppEnv{appConfig, appConnectionPool, appTemplateCache} =
    startBackgroundServicesWith
        env
        (startWorker (withResource (unConnectionPool appConnectionPool)))
        (startTemplateCacheListener (databaseUrl (configDatabase appConfig)) appTemplateCache)

startBackgroundServicesWith :: AppEnv -> IO WorkerHandle -> IO TemplateCacheListener -> IO BackgroundServices
startBackgroundServicesWith env startWorkerAction startListenerAction = do
    workerResult <- startOne env WebhookWorker startWorkerAction
    let mWorker = case workerResult of
            Left _ -> Nothing
            Right h -> Just h
    listenerResult <- startOne env TemplateListener startListenerAction
    let mListener = case listenerResult of
            Left _ -> Nothing
            Right h -> Just h
    pure
        BackgroundServices
            { bgWebhookWorker = mWorker
            , bgTemplateCacheListener = mListener
            , bgServiceStatuses = appBackgroundServiceStatuses env
            }

startRequiredBackgroundServices :: AppEnv -> IO BackgroundServices
startRequiredBackgroundServices env =
    bracketOnError
        (startBackgroundServices env)
        stopBackgroundServices
        (requireBackgroundServices env)

requireBackgroundServices :: AppEnv -> BackgroundServices -> IO BackgroundServices
requireBackgroundServices env services =
    case bgWebhookWorker services of
        Just _ ->
            pure services
        Nothing -> do
            status <- readBackgroundServiceStatus env WebhookWorker
            throwIO (userError ("required background service failed: webhook_worker: " <> statusText status))

{- | Stop background services. Idempotent; safe to call once per
'startBackgroundServices'.
-}
stopBackgroundServices :: BackgroundServices -> IO ()
stopBackgroundServices BackgroundServices{bgWebhookWorker, bgTemplateCacheListener, bgServiceStatuses} = do
    mapM_ stopWorker bgWebhookWorker
    mapM_ stopTemplateCacheListener bgTemplateCacheListener
    setBackgroundServiceStatus bgServiceStatuses WebhookWorker BackgroundServiceStopped
    setBackgroundServiceStatus bgServiceStatuses TemplateListener BackgroundServiceStopped

destroyAppEnv :: AppEnv -> IO ()
destroyAppEnv AppEnv{appConnectionPool} =
    destroyAllResources (unConnectionPool appConnectionPool)

withDatabaseConnection :: AppEnv -> (Connection -> IO a) -> IO a
withDatabaseConnection AppEnv{appConnectionPool} =
    withResource (unConnectionPool appConnectionPool)

stdoutLogger :: Logger
stdoutLogger =
    Logger \level message ->
        putStrLn ("[" <> logLevelText level <> "] " <> T.unpack message)

createConnectionPool :: Config -> IO ConnectionPool
createConnectionPool Config{configDatabase = DatabaseConfig{databaseUrl, databasePoolSize}} =
    ConnectionPool
        <$> createPool
            (connectPostgreSQL (TE.encodeUtf8 databaseUrl))
            close
            poolStripes
            poolIdleTimeSeconds
            databasePoolSize

poolStripes :: Int
poolStripes =
    1

poolIdleTimeSeconds :: NominalDiffTime
poolIdleTimeSeconds =
    30

logLevelText :: LogLevel -> String
logLevelText = \case
    LogDebug ->
        "debug"
    LogInfo ->
        "info"
    LogWarn ->
        "warn"
    LogError ->
        "error"

newBackgroundServiceStatuses :: IO BackgroundServiceStatuses
newBackgroundServiceStatuses =
    BackgroundServiceStatuses
        <$> newIORef BackgroundServiceNotStarted
        <*> newIORef BackgroundServiceNotStarted

readBackgroundServiceStatus :: AppEnv -> BackgroundServiceName -> IO BackgroundServiceStatus
readBackgroundServiceStatus AppEnv{appBackgroundServiceStatuses} =
    readBackgroundServiceStatusFrom appBackgroundServiceStatuses

readBackgroundServiceStatusFrom :: BackgroundServiceStatuses -> BackgroundServiceName -> IO BackgroundServiceStatus
readBackgroundServiceStatusFrom statuses name =
    readIORef (statusRef statuses name)

setBackgroundServiceStatus :: BackgroundServiceStatuses -> BackgroundServiceName -> BackgroundServiceStatus -> IO ()
setBackgroundServiceStatus statuses name =
    writeIORef (statusRef statuses name)

recordBackgroundServiceStatus :: AppEnv -> BackgroundServiceName -> BackgroundServiceStatus -> IO ()
recordBackgroundServiceStatus AppEnv{appBackgroundServiceStatuses} =
    setBackgroundServiceStatus appBackgroundServiceStatuses

backgroundServiceStatusChecks :: AppEnv -> IO [(BackgroundServiceName, BackgroundServiceStatus)]
backgroundServiceStatusChecks env =
    traverse
        ( \name -> do
            status <- readBackgroundServiceStatus env name
            pure (name, status)
        )
        [WebhookWorker, TemplateListener]

statusRef :: BackgroundServiceStatuses -> BackgroundServiceName -> IORef BackgroundServiceStatus
statusRef BackgroundServiceStatuses{webhookWorkerStatus, templateListenerStatus} = \case
    WebhookWorker ->
        webhookWorkerStatus
    TemplateListener ->
        templateListenerStatus

startOne :: AppEnv -> BackgroundServiceName -> IO a -> IO (Either SomeException a)
startOne AppEnv{appLogger, appBackgroundServiceStatuses} name action = do
    result <- tryNoAsync action
    case result of
        Left err -> do
            let reason = T.pack (show err)
            setBackgroundServiceStatus appBackgroundServiceStatuses name (BackgroundServiceFailed reason)
            logMessage appLogger LogError (backgroundServiceNameText name <> " startup failed: " <> reason)
        Right _ ->
            setBackgroundServiceStatus appBackgroundServiceStatuses name BackgroundServiceRunning
    pure result

backgroundServiceNameText :: BackgroundServiceName -> Text
backgroundServiceNameText = \case
    WebhookWorker ->
        "webhook_worker"
    TemplateListener ->
        "template_listener"

statusText :: BackgroundServiceStatus -> String
statusText = \case
    BackgroundServiceNotStarted ->
        "not started"
    BackgroundServiceRunning ->
        "running"
    BackgroundServiceFailed reason ->
        T.unpack reason
    BackgroundServiceStopped ->
        "stopped"

tryNoAsync :: IO a -> IO (Either SomeException a)
tryNoAsync action =
    try action >>= \case
        Right x -> pure (Right x)
        Left e
            | Just (_ :: SomeAsyncException) <- fromException e -> throwIO e
            | otherwise -> pure (Left e)
