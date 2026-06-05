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

The required-vs-optional policy for production @hauth serve@ is named in
'requiredForServe' and enforced by 'requireBackgroundServices' /
'startRequiredBackgroundServices'. See @docs\/PRODUCTION.md@ for the
operator-facing contract.

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
    isRequiredForServe,
    readBackgroundServiceStatus,
    recordBackgroundServiceStatus,
    requireBackgroundServices,
    requiredForServe,
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
import Hauth.Email (EmailSender)
import Hauth.Email.Smtp (makeSMTPSender)
import Hauth.Email.TemplateCache (
    TemplateCache,
    TemplateCacheListener,
    newTemplateCache,
    startTemplateCacheListener,
    stopTemplateCacheListener,
 )
import Hauth.OAuth.ProviderExchange (ProviderExchange, productionProviderExchange)
import Hauth.Webhooks.Worker (WorkerHandle, startWorker, stopWorker)
import Network.HTTP.Client (Manager, newManager)
import Network.HTTP.Client.TLS (tlsManagerSettings)

data AppEnv = AppEnv
    { appConfig :: Config
    , appLogger :: Logger
    , appConnectionPool :: ConnectionPool
    , appTemplateCache :: TemplateCache
    , appBackgroundServiceStatuses :: BackgroundServiceStatuses
    , appHookHttpManager :: Manager
    -- ^ Shared TLS-capable HTTP manager for synchronous hook invocations.
    -- A 'Manager' is thread-safe and meant to be long-lived; allocating a
    -- new one per request defeats connection pooling. Per-hook timeout is
    -- applied on the 'Request' (see "Hauth.Hooks.Runner"), not here.
    , appEmailSender :: EmailSender
    -- ^ Configured email sender. Points at real SMTP in production; tests
    -- inject a capturing fake to assert delivery without a live server.
    , appProviderExchange :: ProviderExchange
    -- ^ Injectable OAuth provider exchange record. Production uses
    -- 'productionProviderExchange'; e2e tests inject a fake.
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
    hookHttpManager <- newManager tlsManagerSettings
    let emailSender = makeSMTPSender (configEmail config)
    pure
        AppEnv
            { appConfig = config
            , appLogger = logger
            , appConnectionPool = pool
            , appTemplateCache = cache
            , appBackgroundServiceStatuses = statuses
            , appHookHttpManager = hookHttpManager
            , appEmailSender = emailSender
            , appProviderExchange = productionProviderExchange config
            }

{- | Spawn the webhook delivery worker and the template-cache LISTEN/NOTIFY
listener. Both expect a migrated schema and a reachable DB — call this AFTER
@hauth migrate up@.

Per-service failures are tolerated at this layer: if a service throws on
startup the corresponding 'BackgroundServices' field is 'Nothing' and the
rest of the process keeps running. The required/optional policy lives in
'requireBackgroundServices' and 'requiredForServe', so callers that want
fail-fast semantics for required services compose this with
'startRequiredBackgroundServices'. Tolerance at the spawn layer matters for
e2e harnesses that race service startup against truncation/migration
windows.
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

{- | Start background services with the production @serve@ policy: any service
listed in 'requiredForServe' MUST start cleanly or the bracket aborts. Optional
services that fail are logged at WARN and reported in deep health as
@degraded@, but do not abort startup.
-}
startRequiredBackgroundServices :: AppEnv -> IO BackgroundServices
startRequiredBackgroundServices env =
    bracketOnError
        (startBackgroundServices env)
        stopBackgroundServices
        (requireBackgroundServices env)

{- | The set of background services that 'hauth serve' considers required for
production. A failure for any service in this list must abort startup.

Services NOT in this list are optional and degrade gracefully — see the
@\"Background services\"@ section of @docs/PRODUCTION.md@ for the per-service
contract.

* 'WebhookWorker' — required. The outbox/delivery loop is a correctness
  concern: serving without it silently drops webhook events.
* 'TemplateListener' — optional. The template cache falls back to the
  TH-embedded defaults baked into the binary; auth flows still work but
  hot-reload of @auth.email_templates@ rows is unavailable.
-}
requiredForServe :: [BackgroundServiceName]
requiredForServe =
    [WebhookWorker]

-- | True when the given service must start cleanly for 'hauth serve'.
isRequiredForServe :: BackgroundServiceName -> Bool
isRequiredForServe name =
    name `elem` requiredForServe

{- | Apply the production @serve@ policy to an already-started
'BackgroundServices' bundle:

* every service in 'requiredForServe' must be running — otherwise this throws
  with the failed service's recorded status, matching the existing serve-error
  shape (an 'IOError' carrying a stable @\"required background service
  failed: <name>: <reason>\"@ message);
* optional services that failed to start are logged at WARN so the operator
  notices the degraded mode, and remain reflected in deep health.
-}
requireBackgroundServices :: AppEnv -> BackgroundServices -> IO BackgroundServices
requireBackgroundServices env services = do
    -- Warn on every failed optional service so the operator sees degraded
    -- mode immediately in journalctl, even when overall startup succeeds.
    mapM_ (warnIfOptionalDegraded env services) optionalServices
    -- Fail-fast on the first failed required service. The handle field is
    -- ground truth ('Nothing' == did-not-start), regardless of whatever the
    -- status IORef happens to read.
    firstFailure <- findRequiredFailure env services requiredForServe
    case firstFailure of
        Nothing -> pure services
        Just (name, status) ->
            throwIO
                ( userError
                    ( "required background service failed: "
                        <> T.unpack (backgroundServiceNameText name)
                        <> ": "
                        <> statusText status
                    )
                )
  where
    optionalServices = filter (not . isRequiredForServe) allServices

findRequiredFailure ::
    AppEnv ->
    BackgroundServices ->
    [BackgroundServiceName] ->
    IO (Maybe (BackgroundServiceName, BackgroundServiceStatus))
findRequiredFailure _ _ [] = pure Nothing
findRequiredFailure env services (name : rest)
    | serviceStarted services name =
        findRequiredFailure env services rest
    | otherwise = do
        status <- readBackgroundServiceStatus env name
        pure (Just (name, status))

warnIfOptionalDegraded :: AppEnv -> BackgroundServices -> BackgroundServiceName -> IO ()
warnIfOptionalDegraded env@AppEnv{appLogger} services name
    | serviceStarted services name = pure ()
    | otherwise = do
        status <- readBackgroundServiceStatus env name
        logMessage
            appLogger
            LogWarn
            ( backgroundServiceNameText name
                <> " optional background service did not start; running in degraded mode: "
                <> T.pack (statusText status)
            )

serviceStarted :: BackgroundServices -> BackgroundServiceName -> Bool
serviceStarted BackgroundServices{bgWebhookWorker, bgTemplateCacheListener} = \case
    WebhookWorker ->
        case bgWebhookWorker of
            Just _ -> True
            Nothing -> False
    TemplateListener ->
        case bgTemplateCacheListener of
            Just _ -> True
            Nothing -> False

-- | All known background services, in stable display order.
allServices :: [BackgroundServiceName]
allServices =
    [WebhookWorker, TemplateListener]

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
