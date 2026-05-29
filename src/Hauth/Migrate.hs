{-# LANGUAGE TemplateHaskell #-}

module Hauth.Migrate (
    MigrationFile (..),
    embeddedMigrations,
    pendingMigrations,
    runMigrate,
) where

import Control.Exception (SomeException, bracket, try)
import Data.ByteString (ByteString)
import Data.FileEmbed (embedDir)
import Data.List (sortOn)
import Data.Text (Text)
import qualified Data.Text as T
import qualified Data.Text.Encoding as TE
import Database.PostgreSQL.Simple (
    Connection,
    Only (..),
    close,
    connectPostgreSQL,
    execute,
    execute_,
    fromOnly,
    query_,
    withTransaction,
 )
import Database.PostgreSQL.Simple.Types (Query (..))
import Hauth.CLI (MigrateCommand (..))
import Hauth.Config (Config (..), DatabaseConfig (..))
import System.Exit (ExitCode (..))
import System.IO (hPutStrLn, stderr)

data MigrationFile = MigrationFile
    { migrationName :: Text
    , migrationBytes :: ByteString
    }
    deriving stock (Eq, Show)

embeddedMigrations :: [MigrationFile]
embeddedMigrations =
    sortOn migrationName $
        fmap toMigrationFile $(embedDir "migrations")
  where
    toMigrationFile (path, bytes) =
        MigrationFile (T.pack path) bytes

pendingMigrations :: [Text] -> [MigrationFile] -> [MigrationFile]
pendingMigrations applied =
    filter (\m -> migrationName m `notElem` applied)

runMigrate :: Config -> MigrateCommand -> IO ExitCode
runMigrate Config{configDatabase = DatabaseConfig{databaseUrl}} command =
    bracket
        (connectPostgreSQL (TE.encodeUtf8 databaseUrl))
        close
        \conn -> do
            ensureTrackingTable conn
            case command of
                MigrateUp -> applyMigrations conn
                MigrateStatus -> showStatus conn

ensureTrackingTable :: Connection -> IO ()
ensureTrackingTable conn =
    withTransaction conn do
        _ <- execute_ conn "CREATE SCHEMA IF NOT EXISTS auth"
        _ <-
            execute_
                conn
                "CREATE TABLE IF NOT EXISTS auth.schema_migrations \
                \( filename text PRIMARY KEY \
                \, applied_at timestamptz NOT NULL DEFAULT now() \
                \)"
        pure ()

queryApplied :: Connection -> IO [Text]
queryApplied conn = do
    rows <- query_ conn "SELECT filename FROM auth.schema_migrations ORDER BY filename"
    pure (fmap fromOnly rows)

showStatus :: Connection -> IO ExitCode
showStatus conn = do
    applied <- queryApplied conn
    let pending = pendingMigrations applied embeddedMigrations
    putStrLn (show (length applied) <> " applied, " <> show (length pending) <> " pending")
    mapM_ (\name -> putStrLn ("  applied  " <> T.unpack name)) applied
    mapM_ (\m -> putStrLn ("  pending  " <> T.unpack (migrationName m))) pending
    pure ExitSuccess

applyMigrations :: Connection -> IO ExitCode
applyMigrations conn = do
    _ <- execute_ conn "SELECT pg_advisory_lock(7401)"
    applied <- queryApplied conn
    let pending = pendingMigrations applied embeddedMigrations
    if null pending
        then do
            putStrLn "up to date; 0 migration(s) applied"
            pure ExitSuccess
        else applyEach conn pending 0

applyEach :: Connection -> [MigrationFile] -> Int -> IO ExitCode
applyEach _ [] count = do
    putStrLn ("applied " <> show count <> " migration(s)")
    pure ExitSuccess
applyEach conn (m : rest) count = do
    result <- try @SomeException $
        withTransaction conn do
            _ <- execute_ conn (Query (migrationBytes m))
            _ <-
                execute
                    conn
                    "INSERT INTO auth.schema_migrations (filename) VALUES (?)"
                    (Only (migrationName m))
            pure ()
    case result of
        Left err -> do
            hPutStrLn stderr ("migration " <> T.unpack (migrationName m) <> " failed: " <> show err)
            pure (ExitFailure 1)
        Right () -> do
            putStrLn ("applied  " <> T.unpack (migrationName m))
            applyEach conn rest (count + 1)
