module E2E.VerifySpec (spec) where

import qualified Data.Text as T
import E2E.Helpers (TestEnv (..), testConfig)
import Hauth.Verify (Check (..), Report (..), defaultChecks, runChecks)
import Test.Hspec (SpecWith, describe, it, shouldBe)

spec :: SpecWith TestEnv
spec = do
    describe "all default checks" $ do
        it "reports zero failures against a healthy test env" \env -> do
            let cfg = testConfig env
                -- CI doesn't run MailHog or have real OAuth providers, so smtp.*
                -- and oauth.* checks fail in this environment. Filter them out —
                -- their own specs cover those paths with deliberate listeners.
                isExternal c =
                    "smtp." `T.isPrefixOf` checkName c
                        || "oauth." `T.isPrefixOf` checkName c
                checks = filter (not . isExternal) (defaultChecks cfg)
            report <- runChecks (testAppEnv env) checks
            reportFailed report `shouldBe` 0
