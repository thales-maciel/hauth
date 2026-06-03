module Spec.MigrateSpec (spec) where

import Data.Text (Text)
import Hauth.Migrate (
    MigrationFile (..),
    embeddedMigrations,
    pendingMigrations,
 )
import Test.Hspec (Spec, describe, it, shouldBe)

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
    ]

spec :: Spec
spec = describe "Hauth.Migrate" $ do
    let names = fmap migrationName embeddedMigrations
    it "lists embedded migrations in order" $
        names `shouldBe` expectedNames
    it "returns no pending migrations when all are applied" $
        fmap migrationName (pendingMigrations names embeddedMigrations) `shouldBe` []
    it "returns all migrations as pending when none are applied" $
        fmap migrationName (pendingMigrations [] embeddedMigrations) `shouldBe` names
