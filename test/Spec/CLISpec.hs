module Spec.CLISpec (runSpec) where

import Hauth.CLI (
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
import Spec.TestUtils (assertCliError, assertEqual)

runSpec :: IO ()
runSpec = do
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
    assertCliError "missing command" (parseCommand [])
    assertCliError "unknown command" (parseCommand ["wat"])
    assertCliError "missing migrate subcommand" (parseCommand ["migrate"])
    assertCliError "unknown migrate subcommand" (parseCommand ["migrate", "wat"])
    assertCliError "migrate missing --config value" (parseCommand ["migrate", "up", "--config"])
    assertCliError "migrate unknown option" (parseCommand ["migrate", "up", "--bogus"])
    assertCliError "bad port" (parseCommand ["serve", "--port", "nope"])
