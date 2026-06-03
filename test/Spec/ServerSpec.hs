module Spec.ServerSpec (runSpec) where

import Control.Exception (SomeException, bracket, try)
import Control.Monad (void)
import Data.Aeson (Object, Value (..))
import qualified Data.Aeson as Aeson
import qualified Data.Aeson.KeyMap as KeyMap
import Data.IORef (newIORef, readIORef, writeIORef)
import qualified Data.Text as T
import Hauth.API.Types (
    CheckOutcome (..),
    DeepHealthCheck (..),
    DeepHealthResponse (..),
 )
import Hauth.Config (decodeConfigBytes)
import Hauth.Env (
    BackgroundServiceName (..),
    BackgroundServiceStatus (..),
    Logger (..),
    createAppEnvWithLogger,
    destroyAppEnv,
    readBackgroundServiceStatus,
    requireBackgroundServices,
    startBackgroundServicesWith,
 )
import Hauth.Server (aggregateStatus, isUnhealthy)
import Spec.TestUtils (assertEqual, validConfigBytes)

runSpec :: IO ()
runSpec = do
    assertEqual "aggregateStatus all ok" "ok" (aggregateStatus [CheckOk, CheckOk])
    assertEqual "aggregateStatus with failure" "unhealthy" (aggregateStatus [CheckOk, CheckFailed "boom"])
    assertEqual "aggregateStatus empty" "ok" (aggregateStatus [])
    let allOkResponse =
            DeepHealthResponse
                { deepHealthStatus = aggregateStatus [CheckOk, CheckOk]
                , deepHealthChecks =
                    [ DeepHealthCheck{deepHealthCheckName = "process", deepHealthCheckOutcome = CheckOk, deepHealthCheckLatencyMs = Nothing}
                    , DeepHealthCheck{deepHealthCheckName = "config", deepHealthCheckOutcome = CheckOk, deepHealthCheckLatencyMs = Nothing}
                    ]
                }
    assertEqual "isUnhealthy all ok" False (isUnhealthy allOkResponse)
    let oneFailedResponse =
            DeepHealthResponse
                { deepHealthStatus = aggregateStatus [CheckOk, CheckFailed "db down"]
                , deepHealthChecks =
                    [ DeepHealthCheck{deepHealthCheckName = "process", deepHealthCheckOutcome = CheckOk, deepHealthCheckLatencyMs = Nothing}
                    , DeepHealthCheck{deepHealthCheckName = "postgres", deepHealthCheckOutcome = CheckFailed "db down", deepHealthCheckLatencyMs = Just 5}
                    ]
                }
    assertEqual "isUnhealthy one failed" True (isUnhealthy oneFailedResponse)
    -- JSON shape tests
    let mixedResponse =
            DeepHealthResponse
                { deepHealthStatus = "unhealthy"
                , deepHealthChecks =
                    [ DeepHealthCheck{deepHealthCheckName = "process", deepHealthCheckOutcome = CheckOk, deepHealthCheckLatencyMs = Nothing}
                    , DeepHealthCheck{deepHealthCheckName = "postgres", deepHealthCheckOutcome = CheckFailed "connection refused", deepHealthCheckLatencyMs = Just 12}
                    ]
                }
    case Aeson.decode (Aeson.encode mixedResponse) of
        Nothing ->
            fail "deep health response: JSON decode failed"
        Just (obj :: Object) -> do
            if KeyMap.member "status" obj
                then pure ()
                else fail "deep health response: missing 'status' key"
            if KeyMap.member "checks" obj
                then pure ()
                else fail "deep health response: missing 'checks' key"
            case KeyMap.lookup "checks" obj of
                Just (Array checksVec) ->
                    case foldr (:) [] checksVec of
                        (Object firstCheck : Object failedCheck : _) -> do
                            if KeyMap.member "name" firstCheck
                                then pure ()
                                else fail "ok check: missing 'name' key"
                            assertEqual
                                "ok check status"
                                (Just (String "ok"))
                                (KeyMap.lookup "status" firstCheck)
                            assertEqual
                                "failed check status"
                                (Just (String "failed"))
                                (KeyMap.lookup "status" failedCheck)
                            if KeyMap.member "reason" failedCheck
                                then pure ()
                                else fail "failed check: missing 'reason' key"
                        _ ->
                            fail "deep health response: expected 2 object checks"
                _ ->
                    fail "deep health response: 'checks' is not an Array"
    testBackgroundServiceStartupFailure

testBackgroundServiceStartupFailure :: IO ()
testBackgroundServiceStartupFailure =
    case decodeConfigBytes "valid.json" validConfigBytes of
        Left err ->
            fail ("background service test config failed: " <> show err)
        Right cfg -> do
            logsRef <- newIORef []
            let logger = Logger \level msg ->
                    writeIORef logsRef . ((level, msg) :) =<< readIORef logsRef
            bracket (createAppEnvWithLogger logger cfg) destroyAppEnv \env -> do
                services <-
                    startBackgroundServicesWith
                        env
                        (ioError (userError "worker boom"))
                        (ioError (userError "listener boom"))
                workerStatus <- readBackgroundServiceStatus env WebhookWorker
                listenerStatus <- readBackgroundServiceStatus env TemplateListener
                assertFailedStatus "webhook worker status" "worker boom" workerStatus
                assertFailedStatus "template listener status" "listener boom" listenerStatus
                logs <- readIORef logsRef
                assertEqual
                    "startup failure logs include service names"
                    True
                    ( any (\(_, msg) -> "webhook_worker startup failed" `T.isInfixOf` msg) logs
                        && any (\(_, msg) -> "template_listener startup failed" `T.isInfixOf` msg) logs
                    )
                required <- try (void (requireBackgroundServices env services)) :: IO (Either SomeException ())
                case required of
                    Left _ ->
                        pure ()
                    Right _ ->
                        fail "required background services should reject a failed webhook worker"

assertFailedStatus :: String -> T.Text -> BackgroundServiceStatus -> IO ()
assertFailedStatus label needle = \case
    BackgroundServiceFailed reason ->
        assertEqual label True (needle `T.isInfixOf` reason)
    other ->
        fail (label <> ": expected failed status, got " <> show other)
