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
    ConnectionPool,
    LogLevel (..),
    Logger (..),
    createAppEnv,
    createAppEnvWithLogger,
    destroyAppEnv,
    startBackgroundServices,
    stdoutLogger,
    stopBackgroundServices,
    withDatabaseConnection,
) where

import Control.Exception (SomeException, try)
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
    pure
        AppEnv
            { appConfig = config
            , appLogger = logger
            , appConnectionPool = pool
            , appTemplateCache = cache
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
startBackgroundServices AppEnv{appConfig, appConnectionPool, appTemplateCache} = do
    workerResult <- try @SomeException (startWorker (withResource (unConnectionPool appConnectionPool)))
    let mWorker = case workerResult of
            Left _ -> Nothing
            Right h -> Just h
    let url = databaseUrl (configDatabase appConfig)
    listenerResult <- try @SomeException (startTemplateCacheListener url appTemplateCache)
    let mListener = case listenerResult of
            Left _ -> Nothing
            Right h -> Just h
    pure
        BackgroundServices
            { bgWebhookWorker = mWorker
            , bgTemplateCacheListener = mListener
            }

{- | Stop background services. Idempotent; safe to call once per
'startBackgroundServices'.
-}
stopBackgroundServices :: BackgroundServices -> IO ()
stopBackgroundServices BackgroundServices{bgWebhookWorker, bgTemplateCacheListener} = do
    mapM_ stopWorker bgWebhookWorker
    mapM_ stopTemplateCacheListener bgTemplateCacheListener

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
