module Hauth.CLI (
    CliError (..),
    Command (..),
    HelpTopic (..),
    MigrateCommand (..),
    MigrateOptions (..),
    OutputFormat (..),
    Port (..),
    ServeOptions (..),
    VerifyOptions (..),
    helpText,
    parseCommand,
    resolveMigrateConfigPath,
    resolveServeConfigPath,
    resolveServePort,
    resolveVerifyConfigPath,
) where

import Data.List (stripPrefix)
import Text.Read (readMaybe)

newtype Port = Port {unPort :: Int}
    deriving stock (Eq, Show)

data ServeOptions = ServeOptions
    { serveConfigPath :: Maybe FilePath
    , servePortOverride :: Maybe Port
    }
    deriving stock (Eq, Show)

newtype MigrateOptions = MigrateOptions
    { migrateConfigPath :: Maybe FilePath
    }
    deriving stock (Eq, Show)

data MigrateCommand
    = MigrateStatus
    | MigrateUp
    deriving stock (Eq, Show)

data OutputFormat
    = FormatText
    | FormatJson
    deriving stock (Eq, Show)

data VerifyOptions = VerifyOptions
    { verifyConfigPath :: Maybe FilePath
    , verifyFormat :: OutputFormat
    }
    deriving stock (Eq, Show)

data HelpTopic
    = TopLevelHelp
    | ServeHelp
    | MigrateHelp
    | VerifyHelp
    deriving stock (Eq, Show)

data Command
    = Help HelpTopic
    | Serve ServeOptions
    | Migrate MigrateOptions MigrateCommand
    | Verify VerifyOptions
    deriving stock (Eq, Show)

data CliError = CliError
    { cliErrorMessage :: String
    , cliErrorHelp :: String
    }
    deriving stock (Eq, Show)

parseCommand :: [String] -> Either CliError Command
parseCommand = \case
    [] ->
        Left (CliError "Missing command." topLevelHelp)
    ["-h"] ->
        Right (Help TopLevelHelp)
    ["--help"] ->
        Right (Help TopLevelHelp)
    ["help"] ->
        Right (Help TopLevelHelp)
    "serve" : args ->
        parseServeCommand args
    "migrate" : args ->
        parseMigrateCommand args
    "verify" : args ->
        parseVerifyCommand args
    command : _ ->
        Left (CliError ("Unknown command: " <> command) topLevelHelp)

parseServeCommand :: [String] -> Either CliError Command
parseServeCommand = \case
    [] ->
        Right (Serve (ServeOptions Nothing Nothing))
    ["-h"] ->
        Right (Help ServeHelp)
    ["--help"] ->
        Right (Help ServeHelp)
    args ->
        Serve <$> parseServeOptions (ServeOptions Nothing Nothing) args

parseServeOptions :: ServeOptions -> [String] -> Either CliError ServeOptions
parseServeOptions options = \case
    [] ->
        Right options
    "--config" : value : rest -> do
        configPath <- parseConfigPath "--config" serveHelp value
        parseServeOptions options{serveConfigPath = Just configPath} rest
    "-c" : value : rest -> do
        configPath <- parseConfigPath "-c" serveHelp value
        parseServeOptions options{serveConfigPath = Just configPath} rest
    "--port" : value : rest -> do
        port <- parsePort "--port" value serveHelp
        parseServeOptions options{servePortOverride = Just port} rest
    "-p" : value : rest -> do
        port <- parsePort "-p" value serveHelp
        parseServeOptions options{servePortOverride = Just port} rest
    arg : rest
        | Just value <- stripPrefix "--config=" arg -> do
            configPath <- parseConfigPath "--config" serveHelp value
            parseServeOptions options{serveConfigPath = Just configPath} rest
        | Just value <- stripPrefix "--port=" arg -> do
            port <- parsePort "--port" value serveHelp
            parseServeOptions options{servePortOverride = Just port} rest
    ["--config"] ->
        Left (CliError "Missing value for --config." serveHelp)
    ["-c"] ->
        Left (CliError "Missing value for -c." serveHelp)
    ["--port"] ->
        Left (CliError "Missing value for --port." serveHelp)
    ["-p"] ->
        Left (CliError "Missing value for -p." serveHelp)
    args ->
        Left (CliError ("Unknown serve option(s): " <> unwords args) serveHelp)

parseMigrateCommand :: [String] -> Either CliError Command
parseMigrateCommand = \case
    [] ->
        Left (CliError "Missing migrate command." migrateHelp)
    ["-h"] ->
        Right (Help MigrateHelp)
    ["--help"] ->
        Right (Help MigrateHelp)
    ["help"] ->
        Right (Help MigrateHelp)
    sub : rest -> do
        cmd <- parseMigrateSubcommand sub
        opts <- parseMigrateOptions (MigrateOptions Nothing) rest
        pure (Migrate opts cmd)

parseMigrateSubcommand :: String -> Either CliError MigrateCommand
parseMigrateSubcommand = \case
    "status" ->
        Right MigrateStatus
    "up" ->
        Right MigrateUp
    other ->
        Left (CliError ("Unknown migrate command: " <> other) migrateHelp)

parseMigrateOptions :: MigrateOptions -> [String] -> Either CliError MigrateOptions
parseMigrateOptions options = \case
    [] ->
        Right options
    "--config" : value : rest -> do
        configPath <- parseConfigPath "--config" migrateHelp value
        parseMigrateOptions options{migrateConfigPath = Just configPath} rest
    "-c" : value : rest -> do
        configPath <- parseConfigPath "-c" migrateHelp value
        parseMigrateOptions options{migrateConfigPath = Just configPath} rest
    arg : rest
        | Just value <- stripPrefix "--config=" arg -> do
            configPath <- parseConfigPath "--config" migrateHelp value
            parseMigrateOptions options{migrateConfigPath = Just configPath} rest
    ["--config"] ->
        Left (CliError "Missing value for --config." migrateHelp)
    ["-c"] ->
        Left (CliError "Missing value for -c." migrateHelp)
    args ->
        Left (CliError ("Unknown migrate option(s): " <> unwords args) migrateHelp)

parseVerifyCommand :: [String] -> Either CliError Command
parseVerifyCommand = \case
    [] ->
        Right (Verify (VerifyOptions Nothing FormatText))
    ["-h"] ->
        Right (Help VerifyHelp)
    ["--help"] ->
        Right (Help VerifyHelp)
    args ->
        Verify <$> parseVerifyOptions (VerifyOptions Nothing FormatText) args

parseVerifyOptions :: VerifyOptions -> [String] -> Either CliError VerifyOptions
parseVerifyOptions options = \case
    [] ->
        Right options
    "--config" : value : rest -> do
        configPath <- parseConfigPath "--config" verifyHelp value
        parseVerifyOptions options{verifyConfigPath = Just configPath} rest
    "-c" : value : rest -> do
        configPath <- parseConfigPath "-c" verifyHelp value
        parseVerifyOptions options{verifyConfigPath = Just configPath} rest
    "--format" : value : rest -> do
        fmt <- parseOutputFormat value
        parseVerifyOptions options{verifyFormat = fmt} rest
    arg : rest
        | Just value <- stripPrefix "--config=" arg -> do
            configPath <- parseConfigPath "--config" verifyHelp value
            parseVerifyOptions options{verifyConfigPath = Just configPath} rest
        | Just value <- stripPrefix "--format=" arg -> do
            fmt <- parseOutputFormat value
            parseVerifyOptions options{verifyFormat = fmt} rest
    ["--config"] ->
        Left (CliError "Missing value for --config." verifyHelp)
    ["-c"] ->
        Left (CliError "Missing value for -c." verifyHelp)
    ["--format"] ->
        Left (CliError "Missing value for --format." verifyHelp)
    args ->
        Left (CliError ("Unknown verify option(s): " <> unwords args) verifyHelp)

parseOutputFormat :: String -> Either CliError OutputFormat
parseOutputFormat = \case
    "text" ->
        Right FormatText
    "json" ->
        Right FormatJson
    other ->
        Left (CliError ("Unknown format: " <> other <> ". Use text or json.") verifyHelp)

resolveVerifyConfigPath :: Maybe FilePath -> VerifyOptions -> Either String FilePath
resolveVerifyConfigPath envConfigPath VerifyOptions{verifyConfigPath} =
    resolveConfigPath verifyConfigPath envConfigPath

resolveServeConfigPath :: Maybe FilePath -> ServeOptions -> Either String FilePath
resolveServeConfigPath envConfigPath ServeOptions{serveConfigPath} =
    resolveConfigPath serveConfigPath envConfigPath

resolveMigrateConfigPath :: Maybe FilePath -> MigrateOptions -> Either String FilePath
resolveMigrateConfigPath envConfigPath MigrateOptions{migrateConfigPath} =
    resolveConfigPath migrateConfigPath envConfigPath

resolveConfigPath :: Maybe FilePath -> Maybe FilePath -> Either String FilePath
resolveConfigPath optionPath envPath =
    case optionPath of
        Just configPath
            | not (null configPath) ->
                Right configPath
        Just _ ->
            missing
        Nothing ->
            case envPath of
                Just configPath
                    | not (null configPath) ->
                        Right configPath
                _ ->
                    missing
  where
    missing =
        Left "Missing config path. Set HAUTH_CONFIG or pass --config PATH."

resolveServePort :: Port -> Maybe String -> ServeOptions -> Either String Port
resolveServePort configPort envPort ServeOptions{servePortOverride} =
    case servePortOverride of
        Just port ->
            Right port
        Nothing ->
            maybe (Right configPort) (parseEnvPort "HAUTH_PORT") envPort

parseEnvPort :: String -> String -> Either String Port
parseEnvPort name value =
    case readPort value of
        Just port ->
            Right port
        Nothing ->
            Left ("Invalid " <> name <> ": " <> value)

parsePort :: String -> String -> String -> Either CliError Port
parsePort flag value help =
    case readPort value of
        Just port ->
            Right port
        Nothing ->
            Left (CliError ("Invalid " <> flag <> ": " <> value) help)

parseConfigPath :: String -> String -> FilePath -> Either CliError FilePath
parseConfigPath flag help value =
    if null value
        then Left (CliError ("Invalid " <> flag <> ": value must not be empty") help)
        else Right value

readPort :: String -> Maybe Port
readPort value =
    case readMaybe value of
        Just port
            | port >= 1 && port <= 65535 ->
                Just (Port port)
        _ ->
            Nothing

helpText :: HelpTopic -> String
helpText = \case
    TopLevelHelp ->
        topLevelHelp
    ServeHelp ->
        serveHelp
    MigrateHelp ->
        migrateHelp
    VerifyHelp ->
        verifyHelp

topLevelHelp :: String
topLevelHelp =
    unlines
        [ "Usage: hauth COMMAND"
        , ""
        , "Commands:"
        , "  serve       Start the Hauth HTTP server"
        , "  migrate     Manage database migrations"
        , "  verify      Run operational health checks"
        , ""
        , "Run `hauth COMMAND --help` for command-specific help."
        ]

serveHelp :: String
serveHelp =
    unlines
        [ "Usage: hauth serve --config PATH [--port PORT]"
        , ""
        , "Start the Hauth HTTP server."
        , ""
        , "Options:"
        , "  -c, --config PATH   Load startup config from PATH instead of HAUTH_CONFIG"
        , "  -p, --port PORT     Listen on PORT instead of HAUTH_PORT or config server.port"
        ]

migrateHelp :: String
migrateHelp =
    unlines
        [ "Usage: hauth migrate COMMAND [--config PATH]"
        , ""
        , "Manage database migrations."
        , ""
        , "Commands:"
        , "  status   Show applied and pending migrations"
        , "  up       Apply pending migrations in order"
        , ""
        , "Options:"
        , "  -c, --config PATH   Load startup config from PATH instead of HAUTH_CONFIG"
        ]

verifyHelp :: String
verifyHelp =
    unlines
        [ "Usage: hauth verify [--config PATH] [--format text|json]"
        , ""
        , "Run operational health checks and report results."
        , ""
        , "Options:"
        , "  -c, --config PATH          Load startup config from PATH instead of HAUTH_CONFIG"
        , "  --format text|json         Output format (default: text)"
        ]
