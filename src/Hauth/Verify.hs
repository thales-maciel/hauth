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
import Data.Text (Text)
import qualified Data.Text as T
import qualified Data.Text.Encoding as TE
import Hauth.Config (Config)
import Hauth.Env (AppEnv)
import qualified Hauth.Verify.Database as Database
import qualified Hauth.Verify.Identity as Identity
import qualified Hauth.Verify.Oauth as OauthChecks
import qualified Hauth.Verify.Smtp as Smtp
import Hauth.Verify.Types (Check (..), CheckOutcome (..), Report (..))
import Numeric (showHex)

defaultChecks :: Config -> [Check]
defaultChecks cfg =
    Check
        { checkName = "verify.framework"
        , checkLabel = "Verify framework"
        , checkRun = \_env -> pure CheckOk
        }
        : Database.checks
            <> Identity.checks
            <> Smtp.checks
            <> OauthChecks.checks cfg

runChecks :: AppEnv -> [Check] -> IO Report
runChecks env cks = do
    results <- mapM (runCheck env) cks
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

{- | Encode the report as UTF-8 JSON. `BSC.pack` is not used because it
truncates `Char` to the low byte, corrupting any message that contains
non-ASCII text (e.g. an em-dash becomes a raw control byte and the output
is no longer parseable JSON).
-}
formatJson :: Report -> ByteString
formatJson Report{reportResults, reportPassed, reportWarned, reportFailed} =
    TE.encodeUtf8 . T.pack $
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

{- | RFC 8259 §7: chars `\x00`-`\x1F`, `"`, and `\\` MUST be escaped in a
JSON string. The five short forms are preferred where they exist; every
other control char gets a `\uXXXX` escape. Non-ASCII (>= U+0080) is
emitted as-is and carried by the UTF-8 encoder in `formatJson`.
-}
escapeJson :: String -> String
escapeJson = concatMap escapeChar
  where
    escapeChar '"' = "\\\""
    escapeChar '\\' = "\\\\"
    escapeChar '\b' = "\\b"
    escapeChar '\f' = "\\f"
    escapeChar '\n' = "\\n"
    escapeChar '\r' = "\\r"
    escapeChar '\t' = "\\t"
    escapeChar c
        | c < '\x20' =
            let h = showHex (fromEnum c) ""
                padded = replicate (4 - length h) '0' <> h
             in "\\u" <> padded
        | otherwise = [c]

commaSep :: [String] -> String
commaSep [] = ""
commaSep [x] = x
commaSep (x : xs) = x <> "," <> commaSep xs
