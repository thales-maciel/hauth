module Hauth.Env (
    AppEnv (..),
    ConnectionPool,
    LogLevel (..),
    Logger (..),
    createAppEnv,
    createAppEnvWithLogger,
    destroyAppEnv,
    stdoutLogger,
    withDatabaseConnection,
) where

import Data.Pool (Pool, createPool, destroyAllResources, withResource)
import Data.Text (Text)
import qualified Data.Text as T
import qualified Data.Text.Encoding as TE
import Data.Time (NominalDiffTime)
import Database.PostgreSQL.Simple (Connection, close, connectPostgreSQL)
import Hauth.Config (Config (..), DatabaseConfig (..))
import Hauth.Email.TemplateCache (TemplateCache, newTemplateCache)

data AppEnv = AppEnv
    { appConfig :: Config
    , appLogger :: Logger
    , appConnectionPool :: ConnectionPool
    , appTemplateCache :: TemplateCache
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
    cache <- newTemplateCache (databaseUrl (configDatabase config))
    pure
        AppEnv
            { appConfig = config
            , appLogger = logger
            , appConnectionPool = pool
            , appTemplateCache = cache
            }

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
