{-# LANGUAGE OverloadedStrings #-}

{- | E2E tests for migration drift detection.

Applies migrations, corrupts a stored hash via raw SQL, then asserts that
checkDrift identifies the tampered row before any further migrations run.
auth.schema_migrations is restored in a bracket so no other spec sees the
modified row.
-}
module E2E.MigrateSpec (spec) where

import Control.Exception (bracket_)
import Data.ByteString (ByteString)
import Data.Map.Strict (Map)
import qualified Data.Map.Strict as Map
import qualified Data.Text as T
import Database.PostgreSQL.Simple (execute, query)
import E2E.Helpers (TestEnv (..))
import Hauth.Env (withDatabaseConnection)
import Hauth.Migrate (
    DriftResult (..),
    MigrationFile (..),
    checkDrift,
    embeddedMigrations,
    hashMigration,
 )
import Test.Hspec (SpecWith, describe, it, shouldBe, shouldSatisfy)

embeddedMap :: Map T.Text ByteString
embeddedMap =
    Map.fromList [(migrationName m, migrationBytes m) | m <- embeddedMigrations]

spec :: SpecWith TestEnv
spec = describe "migration drift detection" $ do
    it "applied migrations have stored hashes matching embedded content" \env -> do
        withDatabaseConnection (testAppEnv env) \conn -> do
            rows <-
                query
                    conn
                    "SELECT filename, sha256 FROM auth.schema_migrations ORDER BY filename"
                    ()
            let applied = rows :: [(T.Text, Maybe T.Text)]
            checkDrift embeddedMap applied `shouldBe` NoDrift

    it "detects drift when a stored hash is mutated" \env -> do
        let target = migrationName (head embeddedMigrations)
        let badHash = "0000000000000000000000000000000000000000000000000000000000000000" :: T.Text
        withDatabaseConnection (testAppEnv env) \conn ->
            bracket_
                ( do
                    _ <-
                        execute
                            conn
                            "UPDATE auth.schema_migrations SET sha256 = ? WHERE filename = ?"
                            (badHash, target)
                    pure ()
                )
                ( do
                    let body = migrationBytes (head embeddedMigrations)
                        good = hashMigration body
                    _ <-
                        execute
                            conn
                            "UPDATE auth.schema_migrations SET sha256 = ? WHERE filename = ?"
                            (good, target)
                    pure ()
                )
                $ do
                    rows <-
                        query
                            conn
                            "SELECT filename, sha256 FROM auth.schema_migrations ORDER BY filename"
                            ()
                    let applied = rows :: [(T.Text, Maybe T.Text)]
                    checkDrift embeddedMap applied
                        `shouldSatisfy` \case
                            Drifted ((name, _, found) : _) ->
                                name == target && found == badHash
                            _ -> False
