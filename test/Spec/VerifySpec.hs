module Spec.VerifySpec (runSpec) where

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
import Spec.TestUtils (assertEqual)

runSpec :: IO ()
runSpec = do
    testRunChecksAggregation
    testFormatText
    testFormatJson

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

testRunChecksAggregation :: IO ()
testRunChecksAggregation = do
    -- All ok
    r1 <- buildReport [okCheck "a", okCheck "b"]
    assertEqual "all ok: passed" 2 (reportPassed r1)
    assertEqual "all ok: warned" 0 (reportWarned r1)
    assertEqual "all ok: failed" 0 (reportFailed r1)

    -- Mix of ok, warn, fail
    r2 <- buildReport [okCheck "a", warnCheck "b" "slow", failCheck "c" "down"]
    assertEqual "mix: passed" 1 (reportPassed r2)
    assertEqual "mix: warned" 1 (reportWarned r2)
    assertEqual "mix: failed" 1 (reportFailed r2)

    -- All fail
    r3 <- buildReport [failCheck "x" "err1", failCheck "y" "err2"]
    assertEqual "all fail: passed" 0 (reportPassed r3)
    assertEqual "all fail: failed" 2 (reportFailed r3)

    -- Empty
    r4 <- buildReport []
    assertEqual "empty: passed" 0 (reportPassed r4)
    assertEqual "empty: results" 0 (length (reportResults r4))

testFormatText :: IO ()
testFormatText = do
    r <- buildReport [okCheck "verify.framework", warnCheck "db.connect" "slow", failCheck "jwt.key" "missing"]
    let txt = formatText r
    assertContainsT "text has ok" "ok  " txt
    assertContainsT "text has warn" "warn" txt
    assertContainsT "text has FAIL" "FAIL" txt
    assertContainsT "text has check name" "verify.framework" txt
    assertContainsT "text has summary" "passed:" txt
    assertContainsT "text has failed count" "failed: 1" txt

testFormatJson :: IO ()
testFormatJson = do
    r <- buildReport [okCheck "verify.framework", failCheck "db.connect" "unreachable"]
    let bs = formatJson r
    case decode (BSL.fromStrict bs) of
        Nothing -> fail "formatJson: invalid JSON"
        Just (Object obj) -> do
            assertHasKey "passed" obj
            assertHasKey "warned" obj
            assertHasKey "failed" obj
            assertHasKey "checks" obj
        Just _ ->
            fail "formatJson: expected JSON object"

assertContainsT :: String -> Text -> Text -> IO ()
assertContainsT label needle haystack =
    if T.isInfixOf needle haystack
        then pure ()
        else
            fail
                ( label
                    <> ": expected "
                    <> show needle
                    <> " in "
                    <> show haystack
                )

assertHasKey :: String -> KeyMap.KeyMap Value -> IO ()
assertHasKey key obj =
    case KeyMap.lookup (Key.fromString key) obj of
        Nothing -> fail ("formatJson: missing key " <> show key)
        Just _ -> pure ()
