module Spec.VerifySpec (spec) where

import Data.Aeson (Value (..), decode)
import qualified Data.Aeson.Key as Key
import qualified Data.Aeson.KeyMap as KeyMap
import qualified Data.ByteString.Lazy as BSL
import Data.Text (Text)
import qualified Data.Text as T
import Hauth.Verify (
    Check (..),
    CheckOutcome (..),
    Report (..),
    formatJson,
    formatText,
 )
import Test.Hspec (Spec, describe, expectationFailure, it, shouldBe, shouldSatisfy)

-- | A pure check that always returns CheckOk.
okCheck :: Text -> Check
okCheck name =
    Check
        { checkName = name
        , checkLabel = "ok check " <> name
        , checkRun = \_env -> pure CheckOk
        }

-- | A pure check that always returns CheckWarn.
warnCheck :: Text -> Text -> Check
warnCheck name msg =
    Check
        { checkName = name
        , checkLabel = "warn check " <> name
        , checkRun = \_env -> pure (CheckWarn msg)
        }

-- | A pure check that always returns CheckFail.
failCheck :: Text -> Text -> Check
failCheck name msg =
    Check
        { checkName = name
        , checkLabel = "fail check " <> name
        , checkRun = \_env -> pure (CheckFail msg)
        }

{- | Build a Report by running pure checks that ignore the env.
Safe because these test checks never force the env argument.
-}
buildReport :: [Check] -> IO Report
buildReport checks = do
    results <- mapM (\c -> (,) c <$> checkRun c (error "env not used by test checks")) checks
    let passed = length [() | (_, CheckOk) <- results]
        warned = length [() | (_, CheckWarn _) <- results]
        failed = length [() | (_, CheckFail _) <- results]
    pure Report{reportResults = results, reportPassed = passed, reportWarned = warned, reportFailed = failed}

assertHasKey :: String -> KeyMap.KeyMap Value -> IO ()
assertHasKey key obj =
    case KeyMap.lookup (Key.fromString key) obj of
        Nothing -> expectationFailure ("formatJson: missing key " <> show key)
        Just _ -> pure ()

spec :: Spec
spec = do
    describe "runChecks aggregation" $ do
        it "all ok" $ do
            r1 <- buildReport [okCheck "a", okCheck "b"]
            reportPassed r1 `shouldBe` 2
            reportWarned r1 `shouldBe` 0
            reportFailed r1 `shouldBe` 0
        it "mix of ok, warn, fail" $ do
            r2 <- buildReport [okCheck "a", warnCheck "b" "slow", failCheck "c" "down"]
            reportPassed r2 `shouldBe` 1
            reportWarned r2 `shouldBe` 1
            reportFailed r2 `shouldBe` 1
        it "all fail" $ do
            r3 <- buildReport [failCheck "x" "err1", failCheck "y" "err2"]
            reportPassed r3 `shouldBe` 0
            reportFailed r3 `shouldBe` 2
        it "empty" $ do
            r4 <- buildReport []
            reportPassed r4 `shouldBe` 0
            length (reportResults r4) `shouldBe` 0

    describe "formatText" $ do
        it "renders ok marker" $ do
            r <- buildReport [okCheck "verify.framework", warnCheck "db.connect" "slow", failCheck "jwt.key" "missing"]
            formatText r `shouldSatisfy` T.isInfixOf "ok  "
        it "renders warn marker" $ do
            r <- buildReport [okCheck "verify.framework", warnCheck "db.connect" "slow", failCheck "jwt.key" "missing"]
            formatText r `shouldSatisfy` T.isInfixOf "warn"
        it "renders FAIL marker" $ do
            r <- buildReport [okCheck "verify.framework", warnCheck "db.connect" "slow", failCheck "jwt.key" "missing"]
            formatText r `shouldSatisfy` T.isInfixOf "FAIL"
        it "includes check name" $ do
            r <- buildReport [okCheck "verify.framework", warnCheck "db.connect" "slow", failCheck "jwt.key" "missing"]
            formatText r `shouldSatisfy` T.isInfixOf "verify.framework"
        it "includes summary header" $ do
            r <- buildReport [okCheck "verify.framework", warnCheck "db.connect" "slow", failCheck "jwt.key" "missing"]
            formatText r `shouldSatisfy` T.isInfixOf "passed:"
        it "includes failed count" $ do
            r <- buildReport [okCheck "verify.framework", warnCheck "db.connect" "slow", failCheck "jwt.key" "missing"]
            formatText r `shouldSatisfy` T.isInfixOf "failed: 1"

    describe "formatJson" $
        it "encodes passed, warned, failed, checks keys" $ do
            r <- buildReport [okCheck "verify.framework", failCheck "db.connect" "unreachable"]
            let bs = formatJson r
            case decode (BSL.fromStrict bs) of
                Nothing -> expectationFailure "formatJson: invalid JSON"
                Just (Object obj) -> do
                    assertHasKey "passed" obj
                    assertHasKey "warned" obj
                    assertHasKey "failed" obj
                    assertHasKey "checks" obj
                Just _ ->
                    expectationFailure "formatJson: expected JSON object"
