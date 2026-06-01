module E2E.VerifyDatabaseSpec (spec) where

import Control.Exception (bracket_)
import qualified Data.Text as T
import Database.PostgreSQL.Simple (Only (..), execute, execute_, query_)
import E2E.Helpers (TestEnv (..))
import Hauth.Config (Config (..), DatabaseConfig (..))
import Hauth.Env (createAppEnvWithLogger, destroyAppEnv, withDatabaseConnection)
import qualified Hauth.Env as Env
import Hauth.Verify (CheckOutcome (..), checkRun)
import Hauth.Verify.Database (checks)
import Test.Hspec (SpecWith, describe, it, shouldBe)

spec :: SpecWith TestEnv
spec = do
    describe "database.connect" $ do
        it "returns CheckOk against a working database" \env -> do
            let connectCheck = checks !! 1
            outcome <- checkRun connectCheck (testAppEnv env)
            outcome `shouldBe` CheckOk

        it "returns CheckFail against an unreachable port" \env -> do
            let connectCheck = checks !! 1
            let badCfg =
                    (testConfig env)
                        { configDatabase =
                            (configDatabase (testConfig env))
                                { databaseUrl = "postgresql://hauth:hauth@localhost:5499/hauth_e2e"
                                }
                        }
            -- Pool creation succeeds; the actual connection attempt fails on first use
            badAppEnv <- createAppEnvWithLogger (Env.Logger \_ _ -> pure ()) badCfg
            outcome <- checkRun connectCheck badAppEnv
            destroyAppEnv badAppEnv
            case outcome of
                CheckFail _ -> pure ()
                _ -> fail ("expected CheckFail, got: " <> show outcome)

    describe "database.migrations" $ do
        it "returns CheckOk when all migrations are applied" \env -> do
            let migrationsCheck = checks !! 2
            outcome <- checkRun migrationsCheck (testAppEnv env)
            outcome `shouldBe` CheckOk

        it "returns CheckWarn when a migration row is missing" \env -> do
            let migrationsCheck = checks !! 2
            -- Capture the last applied row, delete it to simulate a pending
            -- migration, then restore it so the next test (and subsequent local
            -- runs against the same database) see a consistent schema_migrations
            -- table. Without the restore, the next runMigrate tries to re-apply
            -- the migration whose objects already exist, breaking every
            -- subsequent invocation until the operator drops the database.
            outcome <-
                withDatabaseConnection (testAppEnv env) \conn -> do
                    rows <-
                        query_
                            conn
                            "SELECT filename FROM auth.schema_migrations \
                            \ORDER BY filename DESC LIMIT 1" ::
                            IO [Only T.Text]
                    case rows of
                        [Only lastFilename] ->
                            bracket_
                                (execute conn "DELETE FROM auth.schema_migrations WHERE filename = ?" (Only lastFilename))
                                (execute conn "INSERT INTO auth.schema_migrations (filename) VALUES (?)" (Only lastFilename))
                                (checkRun migrationsCheck (testAppEnv env))
                        _ -> fail "expected at least one applied migration"
            case outcome of
                CheckWarn msg -> T.isInfixOf "pending" msg `shouldBe` True
                _ -> fail ("expected CheckWarn, got: " <> show outcome)
