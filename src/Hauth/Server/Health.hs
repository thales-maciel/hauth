{- | Health-check handlers for the @/healthz@ and @/healthz/deep@ endpoints.

@/healthz@ is a process-liveness probe; @/healthz/deep@ aggregates per-component
checks (process, config presence, Postgres reachability, every background
service) and returns one of three top-level statuses:

* @\"ok\"@ — every check passes (200).
* @\"degraded\"@ — only optional components failed (200). See
  'requiredForServe' for the policy.
* @\"unhealthy\"@ — at least one required component failed (503).

'aggregateStatus' and 'isUnhealthy' are exported for the unit suite
("Spec.ServerSpec") which exercises the aggregation logic without spinning up
the full server.
-}
module Hauth.Server.Health (
    healthHandler,
    deepHealthHandler,
    aggregateStatus,
    isUnhealthy,
) where

import Control.Exception (SomeException, try)
import Control.Monad (when)
import Control.Monad.Except (throwError)
import Control.Monad.IO.Class (liftIO)
import Control.Monad.Reader (ReaderT, ask)
import qualified Data.Aeson as Aeson
import qualified Data.Text as T
import Database.PostgreSQL.Simple (Only (..), query_)
import GHC.Clock (getMonotonicTimeNSec)
import Hauth.API.Auth (AnonymousPrincipal)
import Hauth.API.Types
import Hauth.Config (Config (..), DatabaseConfig (..), JwtConfig (..))
import Hauth.Env (
    AppEnv (..),
    BackgroundServiceName (..),
    BackgroundServiceStatus (..),
    backgroundServiceStatusChecks,
    isRequiredForServe,
    withDatabaseConnection,
 )
import Servant.Server (Handler, ServerError (errBody), err503)
import System.Timeout (timeout)

type AppHandler = ReaderT AppEnv Handler

healthHandler :: AnonymousPrincipal -> AppHandler HealthResponse
healthHandler _ =
    pure HealthResponse{healthStatus = "ok"}

deepHealthHandler :: AnonymousPrincipal -> AppHandler DeepHealthResponse
deepHealthHandler _ = do
    env <- ask
    checks <- liftIO (runDeepChecks env)
    let response =
            DeepHealthResponse
                { deepHealthStatus = aggregateStatus (fmap deepHealthCheckOutcome checks)
                , deepHealthChecks = checks
                }
    when (isUnhealthy response) $
        throwError err503{errBody = Aeson.encode response}
    pure response

{- | Roll a list of per-check outcomes into an overall status string for
@\/healthz\/deep@:

* @\"unhealthy\"@ — at least one check is 'CheckFailed' (a required
  component is down)
* @\"degraded\"@ — no 'CheckFailed', but at least one 'CheckDegraded'
  (optional component is down, service is still serving)
* @\"ok\"@ — everything is 'CheckOk'

@degraded@ is a deliberate addition: it lets the deep-health endpoint
distinguish a missing required service (operator must intervene, monitors
should page) from a missing optional service (operator should investigate,
monitors should warn but not page). See @docs\/PRODUCTION.md@ for the
background-services policy.
-}
aggregateStatus :: [CheckOutcome] -> T.Text
aggregateStatus outcomes
    | any isFailed outcomes = "unhealthy"
    | any isDegraded outcomes = "degraded"
    | otherwise = "ok"
  where
    isFailed (CheckFailed _) = True
    isFailed _ = False
    isDegraded (CheckDegraded _) = True
    isDegraded _ = False

{- | Should the deep-health response trigger a 503? Only @\"unhealthy\"@ does.
@\"degraded\"@ still returns 200 — by design, optional-service failures must
not flip monitors to red.
-}
isUnhealthy :: DeepHealthResponse -> Bool
isUnhealthy DeepHealthResponse{deepHealthStatus} =
    deepHealthStatus == "unhealthy"

runDeepChecks :: AppEnv -> IO [DeepHealthCheck]
runDeepChecks env = do
    processCheck <- checkProcess
    configCheck <- checkConfig env
    postgresCheck <- checkPostgres env
    backgroundChecks <- checkBackgroundServices env
    pure ([processCheck, configCheck, postgresCheck] <> backgroundChecks)

checkProcess :: IO DeepHealthCheck
checkProcess =
    pure
        DeepHealthCheck
            { deepHealthCheckName = "process"
            , deepHealthCheckOutcome = CheckOk
            , deepHealthCheckLatencyMs = Nothing
            }

checkConfig :: AppEnv -> IO DeepHealthCheck
checkConfig AppEnv{appConfig} =
    let Config{configDatabase = DatabaseConfig{databaseUrl}, configJwt = JwtConfig{jwtSecret}} = appConfig
        outcome =
            if T.null databaseUrl || T.null jwtSecret
                then CheckFailed "config fields are empty"
                else CheckOk
     in pure
            DeepHealthCheck
                { deepHealthCheckName = "config"
                , deepHealthCheckOutcome = outcome
                , deepHealthCheckLatencyMs = Nothing
                }

checkPostgres :: AppEnv -> IO DeepHealthCheck
checkPostgres env = do
    startNs <- getMonotonicTimeNSec
    -- SELECT returns a column, so we use query_ (not execute_) and discard the rows.
    let probe conn = query_ conn "SELECT 1" :: IO [Only Int]
    result <- try (timeout 2000000 (withDatabaseConnection env probe))
    endNs <- getMonotonicTimeNSec
    let latencyMs = Just (fromIntegral ((endNs - startNs) `div` 1000000))
    let outcome = case result of
            Left (err :: SomeException) ->
                CheckFailed (T.pack (show err))
            Right Nothing ->
                CheckFailed "postgres check timed out"
            Right (Just _) ->
                CheckOk
    pure
        DeepHealthCheck
            { deepHealthCheckName = "postgres"
            , deepHealthCheckOutcome = outcome
            , deepHealthCheckLatencyMs = latencyMs
            }

checkBackgroundServices :: AppEnv -> IO [DeepHealthCheck]
checkBackgroundServices env =
    fmap toCheck <$> backgroundServiceStatusChecks env
  where
    toCheck (name, status) =
        DeepHealthCheck
            { deepHealthCheckName = backgroundServiceName name
            , deepHealthCheckOutcome = backgroundServiceOutcome name status
            , deepHealthCheckLatencyMs = Nothing
            }

backgroundServiceName :: BackgroundServiceName -> T.Text
backgroundServiceName = \case
    WebhookWorker ->
        "webhook_worker"
    TemplateListener ->
        "template_listener"

{- | Map a recorded background-service status to a deep-health 'CheckOutcome'.

The wrinkle is policy-awareness: a failed or stopped optional service is
surfaced as 'CheckDegraded' (which aggregates to @\"degraded\"@ and keeps
the response at 200), while a failed required service surfaces as
'CheckFailed' (which aggregates to @\"unhealthy\"@ and triggers a 503).

Which services are required is owned by "Hauth.Env" — see
'requiredForServe' and the @\"Background services\"@ section of
@docs\/PRODUCTION.md@.
-}
backgroundServiceOutcome :: BackgroundServiceName -> BackgroundServiceStatus -> CheckOutcome
backgroundServiceOutcome name status =
    case status of
        BackgroundServiceRunning ->
            CheckOk
        BackgroundServiceNotStarted ->
            failureOutcome name "not started"
        BackgroundServiceFailed reason ->
            failureOutcome name reason
        BackgroundServiceStopped ->
            failureOutcome name "stopped"
  where
    failureOutcome n reason
        | isRequiredForServe n = CheckFailed reason
        | otherwise = CheckDegraded reason
