module Hauth.CLI (
    CliError (..),
    Command (..),
    HelpTopic (..),
    MigrateCommand (..),
    Port (..),
    ServeOptions (..),
    helpText,
    parseCommand,
    resolveServePort,
) where

import Data.List (stripPrefix)
import Text.Read (readMaybe)

newtype Port = Port {unPort :: Int}
    deriving stock (Eq, Show)

newtype ServeOptions = ServeOptions
    { servePortOverride :: Maybe Port
    }
    deriving stock (Eq, Show)

data MigrateCommand
    = MigrateStatus
    | MigrateUp
    deriving stock (Eq, Show)

data HelpTopic
    = TopLevelHelp
    | ServeHelp
    | MigrateHelp
    deriving stock (Eq, Show)

data Command
    = Help HelpTopic
    | Serve ServeOptions
    | Migrate MigrateCommand
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
    command : _ ->
        Left (CliError ("Unknown command: " <> command) topLevelHelp)

parseServeCommand :: [String] -> Either CliError Command
parseServeCommand = \case
    [] ->
        Right (Serve (ServeOptions Nothing))
    ["-h"] ->
        Right (Help ServeHelp)
    ["--help"] ->
        Right (Help ServeHelp)
    ["--port", value] ->
        Serve . ServeOptions . Just <$> parsePort "--port" value serveHelp
    ["-p", value] ->
        Serve . ServeOptions . Just <$> parsePort "-p" value serveHelp
    [arg]
        | Just value <- stripPrefix "--port=" arg ->
            Serve . ServeOptions . Just <$> parsePort "--port" value serveHelp
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
    ["status"] ->
        Right (Migrate MigrateStatus)
    ["up"] ->
        Right (Migrate MigrateUp)
    command : _ ->
        Left (CliError ("Unknown migrate command: " <> command) migrateHelp)

resolveServePort :: Maybe String -> ServeOptions -> Either String Port
resolveServePort envPort ServeOptions{servePortOverride} =
    case servePortOverride of
        Just port ->
            Right port
        Nothing ->
            maybe (Right defaultPort) (parseEnvPort "HAUTH_PORT") envPort

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

readPort :: String -> Maybe Port
readPort value =
    case readMaybe value of
        Just port
            | port >= 1 && port <= 65535 ->
                Just (Port port)
        _ ->
            Nothing

defaultPort :: Port
defaultPort =
    Port 8080

helpText :: HelpTopic -> String
helpText = \case
    TopLevelHelp ->
        topLevelHelp
    ServeHelp ->
        serveHelp
    MigrateHelp ->
        migrateHelp

topLevelHelp :: String
topLevelHelp =
    unlines
        [ "Usage: hauth COMMAND"
        , ""
        , "Commands:"
        , "  serve       Start the Hauth HTTP server"
        , "  migrate     Manage database migrations"
        , ""
        , "Run `hauth COMMAND --help` for command-specific help."
        ]

serveHelp :: String
serveHelp =
    unlines
        [ "Usage: hauth serve [--port PORT]"
        , ""
        , "Start the Hauth HTTP server."
        , ""
        , "Options:"
        , "  -p, --port PORT   Listen on PORT instead of HAUTH_PORT or 8080"
        ]

migrateHelp :: String
migrateHelp =
    unlines
        [ "Usage: hauth migrate COMMAND"
        , ""
        , "Manage database migrations."
        , ""
        , "Commands:"
        , "  status   Show migration status"
        , "  up       Apply pending migrations"
        , ""
        , "Migration actions are parsed now and will be wired to the runner in issue #5."
        ]
