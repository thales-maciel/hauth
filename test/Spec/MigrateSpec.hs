module Spec.MigrateSpec (spec) where

import Data.ByteString (ByteString)
import Data.Map.Strict (Map)
import qualified Data.Map.Strict as Map
import Data.Text (Text)
import qualified Data.Text as T
import qualified Data.Text.Encoding as TE
import Hauth.Migrate (
    DriftResult (..),
    MigrationFile (..),
    checkDrift,
    embeddedMigrations,
    hashMigration,
    pendingMigrations,
 )
import Test.Hspec (Spec, describe, it, shouldBe, shouldSatisfy)

expectedNames :: [Text]
expectedNames =
    [ "0001_init.sql"
    , "0002_users.sql"
    , "0003_identities.sql"
    , "0004_sessions.sql"
    , "0005_refresh_tokens.sql"
    , "0006_mfa_factors.sql"
    , "0007_flow_state.sql"
    , "0008_webhook_subscriptions.sql"
    , "0009_webhook_deliveries.sql"
    , "0010_auth_hooks.sql"
    , "0011_email_templates.sql"
    , "0012_email_templates_notify.sql"
    , "0013_migration_hash.sql"
    , "0014_admin_ui_sessions.sql"
    ]

-- Build an embedded map as checkDrift expects.
embeddedMap :: Map Text ByteString
embeddedMap =
    Map.fromList
        [(migrationName m, migrationBytes m) | m <- embeddedMigrations]

spec :: Spec
spec = describe "Hauth.Migrate" $ do
    let names = fmap migrationName embeddedMigrations

    it "lists embedded migrations in order" $
        names `shouldBe` expectedNames

    it "returns no pending migrations when all are applied" $
        fmap migrationName (pendingMigrations names embeddedMigrations) `shouldBe` []

    it "returns all migrations as pending when none are applied" $
        fmap migrationName (pendingMigrations [] embeddedMigrations) `shouldBe` names

    describe "drift detection" $ do
        it "accepts matching hash for applied migration" $ do
            let body = "SELECT 1;"
                h = hashMigration (TE.encodeUtf8 body)
                em = Map.singleton "0001_init.sql" (TE.encodeUtf8 body)
                applied = [("0001_init.sql", Just h)]
            checkDrift em applied `shouldBe` NoDrift

        it "reports drift when stored hash differs from embedded" $ do
            let body = "SELECT 1;"
                badHash = "0000000000000000"
                em = Map.singleton "0001_init.sql" (TE.encodeUtf8 body)
                applied = [("0001_init.sql", Just badHash)]
                result = checkDrift em applied
            result `shouldSatisfy` \case
                Drifted [(name, _, found)] ->
                    name == "0001_init.sql" && found == badHash
                _ -> False

        it "skips NULL hash rows (legacy unverified)" $ do
            let em = Map.singleton "0001_init.sql" (TE.encodeUtf8 "SELECT 1;")
                applied = [("0001_init.sql", Nothing)]
            checkDrift em applied `shouldBe` NoDrift

        it "skips applied filenames not in embedded set (unknown legacy)" $ do
            let em = Map.empty
                applied = [("9999_unknown.sql", Just "somehash")]
            checkDrift em applied `shouldBe` NoDrift

        it "returns NoDrift for empty applied list" $
            checkDrift embeddedMap [] `shouldBe` NoDrift

        it "hashMigration produces a 64-character hex string" $
            T.length (hashMigration "hello") `shouldBe` 64

-- NOTE: The failure-path guard added to applyMigrations — where backfillHashes
-- is only called when applyEach returns ExitSuccess — is not unit-tested here
-- because the test harness uses pure helpers (checkDrift, pendingMigrations)
-- and has no IO-mocked DB infrastructure. The correctness of the guard is
-- validated by code review: lines 172-176 of Migrate.hs wrap the backfill in
-- `case result of { ExitSuccess -> ...; _ -> pure () }`, ensuring a partial or
-- failed apply never stamps hashes onto rows that may have been rolled back.
