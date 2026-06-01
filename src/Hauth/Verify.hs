module Hauth.Verify (
    Check (..),
    CheckOutcome (..),
    Report (..),
    defaultChecks,
    formatJson,
    formatText,
    runChecks,
) where

import Data.ByteString (ByteString)
import qualified Data.ByteString.Char8 as BSC
import Data.Text (Text)
import qualified Data.Text as T
import Hauth.Env (AppEnv)
import qualified Hauth.Verify.Database as Database
import qualified Hauth.Verify.Identity as Identity
import Hauth.Verify.Types (Check (..), CheckOutcome (..), Report (..))

defaultChecks :: [Check]
defaultChecks =
    Check
        { checkName = "verify.framework"
        , checkLabel = "Verify framework"
        , checkRun = \_env -> pure CheckOk
        }
        : Database.checks
        <> Identity.checks

runChecks :: AppEnv -> [Check] -> IO Report
runChecks env checks = do
    results <- mapM (runCheck env) checks
    let passed = length [() | (_, CheckOk) <- results]
        warned = length [() | (_, CheckWarn _) <- results]
        failed = length [() | (_, CheckFail _) <- results]
    pure
        Report
            { reportResults = results
            , reportPassed = passed
            , reportWarned = warned
            , reportFailed = failed
            }

runCheck :: AppEnv -> Check -> IO (Check, CheckOutcome)
runCheck env check = do
    outcome <- checkRun check env
    pure (check, outcome)

formatText :: Report -> Text
formatText Report{reportResults, reportPassed, reportWarned, reportFailed} =
    T.unlines (fmap formatLine reportResults)
        <> "\n"
        <> "passed: "
        <> T.pack (show reportPassed)
        <> ", warned: "
        <> T.pack (show reportWarned)
        <> ", failed: "
        <> T.pack (show reportFailed)

formatLine :: (Check, CheckOutcome) -> Text
formatLine (check, outcome) =
    statusLabel outcome <> "  " <> checkName check <> "  " <> checkLabel check <> outcomeDetail outcome

statusLabel :: CheckOutcome -> Text
statusLabel = \case
    CheckOk -> "ok  "
    CheckWarn _ -> "warn"
    CheckFail _ -> "FAIL"

outcomeDetail :: CheckOutcome -> Text
outcomeDetail = \case
    CheckOk -> ""
    CheckWarn msg -> "  (" <> msg <> ")"
    CheckFail msg -> "  (" <> msg <> ")"

formatJson :: Report -> ByteString
formatJson Report{reportResults, reportPassed, reportWarned, reportFailed} =
    BSC.pack $
        "{"
            <> "\"passed\":"
            <> show reportPassed
            <> ","
            <> "\"warned\":"
            <> show reportWarned
            <> ","
            <> "\"failed\":"
            <> show reportFailed
            <> ","
            <> "\"checks\":["
            <> commaSep (fmap formatCheckJson reportResults)
            <> "]}"

formatCheckJson :: (Check, CheckOutcome) -> String
formatCheckJson (check, outcome) =
    "{"
        <> "\"name\":"
        <> jsonStr (T.unpack (checkName check))
        <> ","
        <> "\"label\":"
        <> jsonStr (T.unpack (checkLabel check))
        <> ","
        <> "\"status\":"
        <> jsonStr (outcomeStatus outcome)
        <> outcomeMessageField outcome
        <> "}"

outcomeStatus :: CheckOutcome -> String
outcomeStatus = \case
    CheckOk -> "ok"
    CheckWarn _ -> "warn"
    CheckFail _ -> "fail"

outcomeMessageField :: CheckOutcome -> String
outcomeMessageField = \case
    CheckOk -> ""
    CheckWarn msg -> ",\"message\":" <> jsonStr (T.unpack msg)
    CheckFail msg -> ",\"message\":" <> jsonStr (T.unpack msg)

jsonStr :: String -> String
jsonStr s = "\"" <> escapeJson s <> "\""

escapeJson :: String -> String
escapeJson = concatMap escapeChar
  where
    escapeChar '"' = "\\\""
    escapeChar '\\' = "\\\\"
    escapeChar '\n' = "\\n"
    escapeChar '\r' = "\\r"
    escapeChar '\t' = "\\t"
    escapeChar c = [c]

commaSep :: [String] -> String
commaSep [] = ""
commaSep [x] = x
commaSep (x : xs) = x <> "," <> commaSep xs
