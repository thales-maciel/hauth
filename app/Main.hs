module Main (main) where

import qualified Data.ByteString.Char8 as BSC
import qualified Data.Text.IO as TIO
import Hauth.CLI (
    CliError (..),
    Command (..),
    MigrateCommand,
    MigrateOptions,
    OutputFormat (..),
    Port (..),
    VerifyOptions (..),
    helpText,
    parseCommand,
    resolveMigrateConfigPath,
    resolveServeConfigPath,
    resolveServePort,
    resolveVerifyConfigPath,
 )
import Hauth.Config (Config (..), ServerConfig (..), formatConfigError, loadConfig)
import Hauth.Env (createAppEnv, destroyAppEnv)
import Hauth.Migrate (runMigrate)
import Hauth.Server (runServer)
import Hauth.Verify (Report (..), defaultChecks, formatJson, formatText, runChecks)
import System.Environment (getArgs, lookupEnv)
import System.Exit (ExitCode (..), exitFailure, exitSuccess, exitWith)
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
                config <- loadConfigOrExit configPath
                let configPort = Port (serverPort (configServer config))
                case resolveServePort configPort envPort options of
                    Left message ->
                        failWith message
                    Right (Port port) ->
                        runServer config{configServer = (configServer config){serverPort = port}}
    Migrate options command -> do
        envConfigPath <- lookupEnv "HAUTH_CONFIG"
        runMigrateCommand envConfigPath options command
    Verify options -> do
        envConfigPath <- lookupEnv "HAUTH_CONFIG"
        runVerifyCommand envConfigPath options

runMigrateCommand :: Maybe FilePath -> MigrateOptions -> MigrateCommand -> IO ()
runMigrateCommand envConfigPath options command =
    case resolveMigrateConfigPath envConfigPath options of
        Left message ->
            failWith message
        Right configPath -> do
            config <- loadConfigOrExit configPath
            code <- runMigrate config command
            exitWith code

runVerifyCommand :: Maybe FilePath -> VerifyOptions -> IO ()
runVerifyCommand envConfigPath options =
    case resolveVerifyConfigPath envConfigPath options of
        Left message ->
            failWith message
        Right configPath -> do
            config <- loadConfigOrExit configPath
            env <- createAppEnv config
            report <- runChecks env defaultChecks
            destroyAppEnv env
            printReport (verifyFormat options) report
            if reportFailed report > 0
                then exitWith (ExitFailure 1)
                else exitSuccess

printReport :: OutputFormat -> Report -> IO ()
printReport fmt report =
    case fmt of
        FormatText ->
            TIO.putStr (formatText report)
        FormatJson ->
            BSC.putStrLn (formatJson report)

loadConfigOrExit :: FilePath -> IO Config
loadConfigOrExit configPath = do
    result <- loadConfig configPath
    case result of
        Left err -> do
            hPutStrLn stderr (formatConfigError err)
            exitFailure
        Right config ->
            pure config

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
