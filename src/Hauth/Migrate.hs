{-# LANGUAGE TemplateHaskell #-}

module Hauth.Migrate (
    MigrationFile (..),
    DriftResult (..),
    embeddedMigrations,
    hashMigration,
    pendingMigrations,
    checkDrift,
    runMigrate,
) where

import Control.Exception (SomeException, bracket, try)
import Crypto.Hash (Digest, SHA256, hash)
import Data.ByteArray.Encoding (Base (..), convertToBase)
import Data.ByteString (ByteString)
import Data.FileEmbed (embedDir)
import Data.List (sortOn)
import Data.Map.Strict (Map)
import qualified Data.Map.Strict as Map
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
    query_,
    withTransaction,
 )
import Database.PostgreSQL.Simple.Types (Query (..))
import Hauth.CLI (MigrateCommand (..))
import Hauth.Config (Config (..), DatabaseConfig (..))
import System.Exit (ExitCode (..))
import System.IO (Handle, hPutStrLn, stderr)

data MigrationFile = MigrationFile
    { migrationName :: Text
    , migrationBytes :: ByteString
    }
    deriving stock (Eq, Show)

-- | Result of comparing stored hashes against embedded migration hashes.
data DriftResult
    = NoDrift
    | -- | List of (filename, expected-hash, stored-hash) triples.
      Drifted [(Text, Text, Text)]
    deriving stock (Eq, Show)

embeddedMigrations :: [MigrationFile]
embeddedMigrations =
    sortOn migrationName $
        fmap toMigrationFile $(embedDir "migrations")
  where
    toMigrationFile (path, bytes) =
        MigrationFile (T.pack path) bytes

-- | Compute the hex-encoded SHA256 of a migration body.
hashMigration :: ByteString -> Text
hashMigration bytes =
    TE.decodeUtf8 $
        convertToBase Base16 (hash bytes :: Digest SHA256)

pendingMigrations :: [Text] -> [MigrationFile] -> [MigrationFile]
pendingMigrations applied =
    filter (\m -> migrationName m `notElem` applied)

{- | Compare stored hashes against embedded hashes for applied migrations.

NULL rows (legacy, pre-hash-column) are treated as "unverified" and skipped
rather than failing. This avoids false drift for databases that existed
before 0013_migration_hash.sql and whose hashes were not yet backfilled.
Applied filenames with no matching embedded migration are also skipped
(unknown-legacy contract); they cannot be drift-checked without a reference.
-}
checkDrift ::
    -- | Embedded migrations indexed by name.
    Map Text ByteString ->
    -- | (filename, maybe-stored-hash) rows from the DB.
    [(Text, Maybe Text)] ->
    DriftResult
checkDrift embedded applied =
    let mismatches =
            [ (name, expected, stored)
            | (name, Just stored) <- applied
            , Just body <- [Map.lookup name embedded]
            , let expected = hashMigration body
            , expected /= stored
            ]
     in if null mismatches then NoDrift else Drifted mismatches

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
                \, sha256 text \
                \)"
        pure ()

-- | Query applied migrations returning (filename, maybe sha256).
queryApplied :: Connection -> IO [(Text, Maybe Text)]
queryApplied conn =
    query_
        conn
        "SELECT filename, sha256 FROM auth.schema_migrations ORDER BY filename"

showStatus :: Connection -> IO ExitCode
showStatus conn = do
    applied <- queryApplied conn
    let appliedNames = fmap fst applied
    let pending = pendingMigrations appliedNames embeddedMigrations
    let embedded = Map.fromList [(migrationName m, migrationBytes m) | m <- embeddedMigrations]
    case checkDrift embedded applied of
        Drifted mismatches -> do
            hPutStrLn stderr "ERROR: content drift detected in applied migrations"
            mapM_ (reportMismatch stderr) mismatches
            hPutStrLn stderr "Remedy: restore the original migration file or reset the stored hash manually."
            pure (ExitFailure 1)
        NoDrift -> do
            putStrLn (show (length appliedNames) <> " applied, " <> show (length pending) <> " pending")
            mapM_ (\name -> putStrLn ("  applied  " <> T.unpack name)) appliedNames
            mapM_ (\m -> putStrLn ("  pending  " <> T.unpack (migrationName m))) pending
            pure ExitSuccess

applyMigrations :: Connection -> IO ExitCode
applyMigrations conn = do
    -- pg_advisory_lock is a function call returning void via SELECT, so we use
    -- query_ (not execute_) to swallow the single-column result row.
    _ <- query_ conn "SELECT pg_advisory_lock(7401)" :: IO [Only ()]
    applied <- queryApplied conn
    let appliedNames = fmap fst applied
    let embedded = Map.fromList [(migrationName m, migrationBytes m) | m <- embeddedMigrations]
    case checkDrift embedded applied of
        Drifted mismatches -> do
            hPutStrLn stderr "ERROR: content drift detected in applied migrations"
            mapM_ (reportMismatch stderr) mismatches
            hPutStrLn stderr "Remedy: restore the original migration file or reset the stored hash manually."
            pure (ExitFailure 1)
        NoDrift -> do
            let pending = pendingMigrations appliedNames embeddedMigrations
            if null pending
                then do
                    putStrLn "up to date; 0 migration(s) applied"
                    backfillHashes conn embedded applied
                    pure ExitSuccess
                else do
                    result <- applyEach conn pending 0
                    -- Backfill hashes for legacy rows (sha256 IS NULL) whose
                    -- embedded body still matches the current binary. Rows with
                    -- no matching embedded migration are left NULL ("legacy
                    -- unverified") rather than failing — they predate the hash
                    -- column and cannot be drift-checked retroactively.
                    appliedAfter <- queryApplied conn
                    backfillHashes conn embedded appliedAfter
                    pure result

{- | Populate sha256 for rows that are NULL and whose embedded body is known.
Rows with no embedded counterpart are left NULL (legacy-unverified).
-}
backfillHashes :: Connection -> Map Text ByteString -> [(Text, Maybe Text)] -> IO ()
backfillHashes conn embedded applied = do
    let nullRows = [name | (name, Nothing) <- applied]
    mapM_ backfillOne nullRows
  where
    backfillOne name = case Map.lookup name embedded of
        Nothing -> pure () -- unknown legacy file; cannot verify
        Just body -> do
            let h = hashMigration body
            _ <-
                execute
                    conn
                    "UPDATE auth.schema_migrations SET sha256 = ? WHERE filename = ? AND sha256 IS NULL"
                    (h, name)
            pure ()

reportMismatch :: Handle -> (Text, Text, Text) -> IO ()
reportMismatch h (name, expected, found) =
    hPutStrLn h $
        "  drift  "
            <> T.unpack name
            <> "  expected="
            <> take 16 (T.unpack expected)
            <> "  found="
            <> take 16 (T.unpack found)

applyEach :: Connection -> [MigrationFile] -> Int -> IO ExitCode
applyEach _ [] count = do
    putStrLn ("applied " <> show count <> " migration(s)")
    pure ExitSuccess
applyEach conn (m : rest) count = do
    let h = hashMigration (migrationBytes m)
    result <- try @SomeException $
        withTransaction conn do
            _ <- execute_ conn (Query (migrationBytes m))
            _ <-
                execute
                    conn
                    "INSERT INTO auth.schema_migrations (filename, sha256) VALUES (?, ?)"
                    (migrationName m, h)
            pure ()
    case result of
        Left err -> do
            hPutStrLn stderr ("migration " <> T.unpack (migrationName m) <> " failed: " <> show err)
            pure (ExitFailure 1)
        Right () -> do
            putStrLn ("applied  " <> T.unpack (migrationName m))
            applyEach conn rest (count + 1)
