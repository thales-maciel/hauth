module Main (main) where

import qualified Data.ByteString.Char8 as BSC
import Hauth.API (hauthAPI)
import Hauth.CLI (
    CliError (..),
    Command (..),
    HelpTopic (..),
    MigrateCommand (..),
    MigrateOptions (..),
    Port (..),
    ServeOptions (..),
    parseCommand,
    resolveMigrateConfigPath,
    resolveServeConfigPath,
    resolveServePort,
 )
import Hauth.Config (
    Config (..),
    ConfigError (..),
    ConfigFieldError (..),
    DatabaseConfig (..),
    ServerConfig (..),
    decodeConfigBytes,
 )
import Hauth.Env (
    AppEnv (..),
    Logger (..),
    createAppEnvWithLogger,
    destroyAppEnv,
 )
import Hauth.Migrate (
    MigrationFile (..),
    embeddedMigrations,
    pendingMigrations,
 )
import Hauth.Server (server)
import System.Exit (exitSuccess)

main :: IO ()
main = do
    hauthAPI `seq` server `seq` pure ()
    assertEqual "top-level help" (Right (Help TopLevelHelp)) (parseCommand ["--help"])
    assertEqual "serve default" (Right (Serve (ServeOptions Nothing Nothing))) (parseCommand ["serve"])
    assertEqual
        "serve config"
        (Right (Serve (ServeOptions (Just "config.json") Nothing)))
        (parseCommand ["serve", "--config", "config.json"])
    assertEqual
        "serve port"
        (Right (Serve (ServeOptions Nothing (Just (Port 18080)))))
        (parseCommand ["serve", "--port", "18080"])
    assertEqual
        "serve config and port"
        (Right (Serve (ServeOptions (Just "config.json") (Just (Port 18080)))))
        (parseCommand ["serve", "--config=config.json", "--port=18080"])
    assertEqual
        "migrate status"
        (Right (Migrate (MigrateOptions Nothing) MigrateStatus))
        (parseCommand ["migrate", "status"])
    assertEqual
        "migrate up"
        (Right (Migrate (MigrateOptions Nothing) MigrateUp))
        (parseCommand ["migrate", "up"])
    assertEqual
        "migrate status --config"
        (Right (Migrate (MigrateOptions (Just "migrate.json")) MigrateStatus))
        (parseCommand ["migrate", "status", "--config", "migrate.json"])
    assertEqual
        "migrate up --config="
        (Right (Migrate (MigrateOptions (Just "migrate.json")) MigrateUp))
        (parseCommand ["migrate", "up", "--config=migrate.json"])
    assertEqual
        "migrate up -c"
        (Right (Migrate (MigrateOptions (Just "migrate.json")) MigrateUp))
        (parseCommand ["migrate", "up", "-c", "migrate.json"])
    assertEqual
        "migrate config path"
        (Right "migrate.json")
        (resolveMigrateConfigPath Nothing (MigrateOptions (Just "migrate.json")))
    assertEqual
        "migrate env config path"
        (Right "env.json")
        (resolveMigrateConfigPath (Just "env.json") (MigrateOptions Nothing))
    assertEqual
        "migrate option overrides env"
        (Right "override.json")
        (resolveMigrateConfigPath (Just "env.json") (MigrateOptions (Just "override.json")))
    assertEqual "config path" (Right "config.json") (resolveServeConfigPath Nothing (ServeOptions (Just "config.json") Nothing))
    assertEqual "env config path" (Right "env.json") (resolveServeConfigPath (Just "env.json") (ServeOptions Nothing Nothing))
    assertEqual "config port" (Right (Port 8080)) (resolveServePort (Port 8080) Nothing (ServeOptions Nothing Nothing))
    assertEqual "env port" (Right (Port 18081)) (resolveServePort (Port 8080) (Just "18081") (ServeOptions Nothing Nothing))
    assertEqual
        "option overrides env"
        (Right (Port 18082))
        (resolveServePort (Port 8080) (Just "18081") (ServeOptions Nothing (Just (Port 18082))))
    case decodeConfigBytes "valid.json" validConfigBytes of
        Left err ->
            fail ("valid config failed: " <> show err)
        Right config -> do
            assertEqual "config database url" "postgresql://hauth:hauth@localhost:5432/hauth" (databaseUrl (configDatabase config))
            assertEqual "config server port" 8080 (serverPort (configServer config))
            env <- createAppEnvWithLogger testLogger config
            assertEqual "env config" config (appConfig env)
            destroyAppEnv env
    assertConfigFields
        "missing config sections"
        ["database", "jwt", "site", "email", "oauth", "server"]
        (decodeConfigBytes "missing.json" "{}")
    assertConfigFields
        "invalid config fields"
        [ "database.url"
        , "database.pool_size"
        , "jwt.secret"
        , "jwt.issuer"
        , "jwt.audience"
        , "jwt.access_token_ttl_seconds"
        , "jwt.refresh_token_ttl_seconds"
        , "site.url"
        , "site.allowed_redirect_urls[0]"
        , "email.from"
        , "email.smtp_host"
        , "email.smtp_port"
        , "oauth.providers[0].name"
        , "oauth.providers[0].client_id"
        , "oauth.providers[0].client_secret"
        , "oauth.providers[0].discovery_url"
        , "server.host"
        , "server.port"
        ]
        (decodeConfigBytes "invalid.json" invalidConfigBytes)
    assertCliError "missing command" (parseCommand [])
    assertCliError "unknown command" (parseCommand ["wat"])
    assertCliError "missing migrate subcommand" (parseCommand ["migrate"])
    assertCliError "unknown migrate subcommand" (parseCommand ["migrate", "wat"])
    assertCliError "migrate missing --config value" (parseCommand ["migrate", "up", "--config"])
    assertCliError "migrate unknown option" (parseCommand ["migrate", "up", "--bogus"])
    assertCliError "bad port" (parseCommand ["serve", "--port", "nope"])
    let names = fmap migrationName embeddedMigrations
    assertEqual "embedded bootstrap" ["0001_init.sql"] names
    assertEqual
        "pending none when all applied"
        []
        (fmap migrationName (pendingMigrations names embeddedMigrations))
    assertEqual
        "pending all when nothing applied"
        names
        (fmap migrationName (pendingMigrations [] embeddedMigrations))
    exitSuccess

assertEqual :: (Eq a, Show a) => String -> a -> a -> IO ()
assertEqual label expected actual =
    if actual == expected
        then pure ()
        else fail (label <> ": expected " <> show expected <> ", got " <> show actual)

assertCliError :: String -> Either CliError a -> IO ()
assertCliError _ (Left CliError{}) =
    pure ()
assertCliError label (Right _) =
    fail (label <> ": expected CLI error")

assertConfigFields :: String -> [String] -> Either ConfigError Config -> IO ()
assertConfigFields label expected (Left (ConfigValidationError _ errors)) =
    assertEqual label expected (fmap configFieldPath errors)
assertConfigFields label _ actual =
    fail (label <> ": expected config validation error, got " <> show actual)

testLogger :: Logger
testLogger =
    Logger \_level _message ->
        pure ()

validConfigBytes :: BSC.ByteString
validConfigBytes =
    BSC.pack $
        unlines
            [ "{"
            , "  \"database\": {"
            , "    \"url\": \"postgresql://hauth:hauth@localhost:5432/hauth\","
            , "    \"pool_size\": 5"
            , "  },"
            , "  \"jwt\": {"
            , "    \"secret\": \"0123456789abcdef0123456789abcdef\","
            , "    \"issuer\": \"hauth\","
            , "    \"audience\": \"authenticated\","
            , "    \"access_token_ttl_seconds\": 3600,"
            , "    \"refresh_token_ttl_seconds\": 2592000"
            , "  },"
            , "  \"site\": {"
            , "    \"url\": \"http://localhost:3000\","
            , "    \"allowed_redirect_urls\": [\"http://localhost:3000/auth/callback\"]"
            , "  },"
            , "  \"email\": {"
            , "    \"from\": \"noreply@example.com\","
            , "    \"smtp_host\": \"localhost\","
            , "    \"smtp_port\": 1025"
            , "  },"
            , "  \"oauth\": {"
            , "    \"providers\": ["
            , "      {"
            , "        \"name\": \"github\","
            , "        \"client_id\": \"github-client-id\","
            , "        \"client_secret\": \"github-client-secret\","
            , "        \"discovery_url\": \"https://github.com/.well-known/openid-configuration\""
            , "      }"
            , "    ]"
            , "  },"
            , "  \"server\": {"
            , "    \"host\": \"127.0.0.1\","
            , "    \"port\": 8080"
            , "  }"
            , "}"
            ]

invalidConfigBytes :: BSC.ByteString
invalidConfigBytes =
    BSC.pack $
        unlines
            [ "{"
            , "  \"database\": {"
            , "    \"url\": \"mysql://localhost/hauth\","
            , "    \"pool_size\": 0"
            , "  },"
            , "  \"jwt\": {"
            , "    \"secret\": \"short\","
            , "    \"issuer\": \"\","
            , "    \"audience\": \"\","
            , "    \"access_token_ttl_seconds\": 0,"
            , "    \"refresh_token_ttl_seconds\": -1"
            , "  },"
            , "  \"site\": {"
            , "    \"url\": \"localhost:3000\","
            , "    \"allowed_redirect_urls\": [\"ftp://localhost/callback\"]"
            , "  },"
            , "  \"email\": {"
            , "    \"from\": \"noreply\","
            , "    \"smtp_host\": \"\","
            , "    \"smtp_port\": 70000"
            , "  },"
            , "  \"oauth\": {"
            , "    \"providers\": ["
            , "      {"
            , "        \"name\": \"\","
            , "        \"client_id\": \"\","
            , "        \"client_secret\": \"\","
            , "        \"discovery_url\": \"github.com\""
            , "      }"
            , "    ]"
            , "  },"
            , "  \"server\": {"
            , "    \"host\": \"\","
            , "    \"port\": 0"
            , "  }"
            , "}"
            ]
