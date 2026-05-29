module Main (main) where

import Hauth.CLI (
    CliError (..),
    Command (..),
    MigrateCommand (..),
    Port (..),
    helpText,
    parseCommand,
    resolveServeConfigPath,
    resolveServePort,
 )
import Hauth.Config (Config (..), ServerConfig (..), formatConfigError, loadConfig)
import Hauth.Server (runServer)
import System.Environment (getArgs, lookupEnv)
import System.Exit (exitFailure)
import System.IO (hPutStr, hPutStrLn, stderr)

main :: IO ()
main = do
    args <- getArgs
    case parseCommand args of
        Left err ->
            printCliError err
        Right command ->
            runCommand command

runCommand :: Command -> IO ()
runCommand = \case
    Help topic ->
        putStr (helpText topic)
    Serve options -> do
        envConfigPath <- lookupEnv "HAUTH_CONFIG"
        envPort <- lookupEnv "HAUTH_PORT"
        case resolveServeConfigPath envConfigPath options of
            Left message ->
                failWith message
            Right configPath -> do
                configResult <- loadConfig configPath
                case configResult of
                    Left err ->
                        failWith (formatConfigError err)
                    Right config -> do
                        let configPort = Port (serverPort (configServer config))
                        case resolveServePort configPort envPort options of
                            Left message ->
                                failWith message
                            Right (Port port) ->
                                runServer config{configServer = (configServer config){serverPort = port}}
    Migrate command ->
        failWith (migrateNotImplementedMessage command)

printCliError :: CliError -> IO ()
printCliError CliError{cliErrorMessage, cliErrorHelp} = do
    hPutStrLn stderr cliErrorMessage
    hPutStrLn stderr ""
    hPutStr stderr cliErrorHelp
    exitFailure

failWith :: String -> IO ()
failWith message = do
    hPutStrLn stderr message
    exitFailure

migrateNotImplementedMessage :: MigrateCommand -> String
migrateNotImplementedMessage command =
    "hauth migrate "
        <> migrateCommandName command
        <> " is not wired to a migration runner yet; see issue #5."

migrateCommandName :: MigrateCommand -> String
migrateCommandName = \case
    MigrateStatus -> "status"
    MigrateUp -> "up"
