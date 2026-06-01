module Spec.MigrateSpec (runSpec) where

import Hauth.Migrate (
    MigrationFile (..),
    embeddedMigrations,
    pendingMigrations,
 )
import Spec.TestUtils (assertEqual)

runSpec :: IO ()
runSpec = do
    let names = fmap migrationName embeddedMigrations
    assertEqual
        "embedded migrations"
        [ "0001_init.sql"
        , "0002_users.sql"
        , "0003_identities.sql"
        , "0004_sessions.sql"
        , "0005_refresh_tokens.sql"
        , "0006_mfa_factors.sql"
        , "0007_flow_state.sql"
        , "0008_webhook_subscriptions.sql"
        , "0009_webhook_deliveries.sql"
        ]
        names
    assertEqual
        "pending none when all applied"
        []
        (fmap migrationName (pendingMigrations names embeddedMigrations))
    assertEqual
        "pending all when nothing applied"
        names
        (fmap migrationName (pendingMigrations [] embeddedMigrations))
