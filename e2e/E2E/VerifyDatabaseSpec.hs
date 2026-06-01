module E2E.VerifyDatabaseSpec (spec) where

import qualified Data.Text as T
import Database.PostgreSQL.Simple (execute_)
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
            -- Remove one applied migration row to simulate a pending migration
            _ <-
                withDatabaseConnection (testAppEnv env) \conn ->
                    execute_
                        conn
                        "DELETE FROM auth.schema_migrations WHERE filename = (SELECT filename FROM auth.schema_migrations ORDER BY filename DESC LIMIT 1)"
            pure ()
            outcome <- checkRun migrationsCheck (testAppEnv env)
            case outcome of
                CheckWarn msg -> T.isInfixOf "pending" msg `shouldBe` True
                _ -> fail ("expected CheckWarn, got: " <> show outcome)
