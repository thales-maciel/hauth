module Main (main) where

import Hauth.API (hauthAPI)
import Hauth.CLI (
    CliError (..),
    Command (..),
    HelpTopic (..),
    MigrateCommand (..),
    Port (..),
    ServeOptions (..),
    parseCommand,
    resolveServePort,
 )
import Hauth.Server (app)
import System.Exit (exitSuccess)

main :: IO ()
main = do
    hauthAPI `seq` app `seq` pure ()
    assertEqual "top-level help" (Right (Help TopLevelHelp)) (parseCommand ["--help"])
    assertEqual "serve default" (Right (Serve (ServeOptions Nothing))) (parseCommand ["serve"])
    assertEqual
        "serve port"
        (Right (Serve (ServeOptions (Just (Port 18080)))))
        (parseCommand ["serve", "--port", "18080"])
    assertEqual "migrate status" (Right (Migrate MigrateStatus)) (parseCommand ["migrate", "status"])
    assertEqual "migrate up" (Right (Migrate MigrateUp)) (parseCommand ["migrate", "up"])
    assertEqual "default port" (Right (Port 8080)) (resolveServePort Nothing (ServeOptions Nothing))
    assertEqual "env port" (Right (Port 18081)) (resolveServePort (Just "18081") (ServeOptions Nothing))
    assertEqual
        "option overrides env"
        (Right (Port 18082))
        (resolveServePort (Just "18081") (ServeOptions (Just (Port 18082))))
    assertCliError "missing command" (parseCommand [])
    assertCliError "unknown command" (parseCommand ["wat"])
    assertCliError "missing migrate subcommand" (parseCommand ["migrate"])
    assertCliError "bad port" (parseCommand ["serve", "--port", "nope"])
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
