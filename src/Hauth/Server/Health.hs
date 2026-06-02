{- | Health-check handlers for the @/healthz@ and @/healthz/deep@ endpoints.

@/healthz@ is a process-liveness probe; @/healthz/deep@ aggregates per-component
checks (process, config presence, Postgres reachability) and returns 503 if any
component fails.

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
import Hauth.Env (AppEnv (..), withDatabaseConnection)
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

aggregateStatus :: [CheckOutcome] -> T.Text
aggregateStatus outcomes =
    if any isFailed outcomes
        then "unhealthy"
        else "ok"
  where
    isFailed (CheckFailed _) = True
    isFailed CheckOk = False

isUnhealthy :: DeepHealthResponse -> Bool
isUnhealthy DeepHealthResponse{deepHealthStatus} =
    deepHealthStatus /= "ok"

runDeepChecks :: AppEnv -> IO [DeepHealthCheck]
runDeepChecks env = do
    processCheck <- checkProcess
    configCheck <- checkConfig env
    postgresCheck <- checkPostgres env
    pure [processCheck, configCheck, postgresCheck]

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
