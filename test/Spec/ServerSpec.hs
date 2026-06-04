{-# LANGUAGE BlockArguments #-}
{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE ScopedTypeVariables #-}

module Spec.ServerSpec (spec) where

import Control.Exception (SomeException, bracket, try)
import Control.Monad (void)
import Data.Aeson (Object, Value (..))
import qualified Data.Aeson as Aeson
import qualified Data.Aeson.KeyMap as KeyMap
import Data.IORef (IORef, newIORef, readIORef, writeIORef)
import qualified Data.Text as T
import Hauth.API.Types (
    CheckOutcome (..),
    DeepHealthCheck (..),
    DeepHealthResponse (..),
 )
import Hauth.Config (decodeConfigBytes)
import Hauth.Env (
    AppEnv,
    BackgroundServiceName (..),
    BackgroundServiceStatus (..),
    LogLevel (..),
    Logger (..),
    createAppEnvWithLogger,
    destroyAppEnv,
    isRequiredForServe,
    readBackgroundServiceStatus,
    requireBackgroundServices,
    requiredForServe,
    startBackgroundServicesWith,
    stopBackgroundServices,
 )
import Hauth.Server (aggregateStatus, isUnhealthy)
import Hauth.Webhooks.Worker (WorkerHandle, startWorker)
import Spec.TestUtils (validConfigBytes)
import Test.Hspec (Spec, describe, expectationFailure, it, shouldBe)

spec :: Spec
spec = do
    describe "aggregateStatus" $ do
        it "all ok" $
            aggregateStatus [CheckOk, CheckOk] `shouldBe` "ok"
        it "with failure" $
            aggregateStatus [CheckOk, CheckFailed "boom"] `shouldBe` "unhealthy"
        it "empty" $
            aggregateStatus [] `shouldBe` "ok"

    describe "isUnhealthy" $ do
        it "all ok" $
            let allOkResponse =
                    DeepHealthResponse
                        { deepHealthStatus = aggregateStatus [CheckOk, CheckOk]
                        , deepHealthChecks =
                            [ DeepHealthCheck{deepHealthCheckName = "process", deepHealthCheckOutcome = CheckOk, deepHealthCheckLatencyMs = Nothing}
                            , DeepHealthCheck{deepHealthCheckName = "config", deepHealthCheckOutcome = CheckOk, deepHealthCheckLatencyMs = Nothing}
                            ]
                        }
             in isUnhealthy allOkResponse `shouldBe` False
        it "one failed" $
            let oneFailedResponse =
                    DeepHealthResponse
                        { deepHealthStatus = aggregateStatus [CheckOk, CheckFailed "db down"]
                        , deepHealthChecks =
                            [ DeepHealthCheck{deepHealthCheckName = "process", deepHealthCheckOutcome = CheckOk, deepHealthCheckLatencyMs = Nothing}
                            , DeepHealthCheck{deepHealthCheckName = "postgres", deepHealthCheckOutcome = CheckFailed "db down", deepHealthCheckLatencyMs = Just 5}
                            ]
                        }
             in isUnhealthy oneFailedResponse `shouldBe` True

    describe "deep health response JSON" $
        it "encodes status, checks, and per-check fields" $ do
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
                    expectationFailure "deep health response: JSON decode failed"
                Just (obj :: Object) -> do
                    if KeyMap.member "status" obj
                        then pure ()
                        else expectationFailure "deep health response: missing 'status' key"
                    if KeyMap.member "checks" obj
                        then pure ()
                        else expectationFailure "deep health response: missing 'checks' key"
                    case KeyMap.lookup "checks" obj of
                        Just (Array checksVec) ->
                            case foldr (:) [] checksVec of
                                (Object firstCheck : Object failedCheck : _) -> do
                                    if KeyMap.member "name" firstCheck
                                        then pure ()
                                        else expectationFailure "ok check: missing 'name' key"
                                    KeyMap.lookup "status" firstCheck `shouldBe` Just (String "ok")
                                    KeyMap.lookup "status" failedCheck `shouldBe` Just (String "failed")
                                    if KeyMap.member "reason" failedCheck
                                        then pure ()
                                        else expectationFailure "failed check: missing 'reason' key"
                                _ ->
                                    expectationFailure "deep health response: expected 2 object checks"
                        _ ->
                            expectationFailure "deep health response: 'checks' is not an Array"

    describe "background service startup policy" $ do
        -- Both required (webhook worker) and optional (template listener)
        -- fail. Per the policy, requireBackgroundServices must reject — the
        -- worker is required.
        it "rejects when a required service fails" $
            withFakeEnv $ \env logsRef -> do
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
                ( any (\(_, msg) -> "webhook_worker startup failed" `T.isInfixOf` msg) logs
                        && any (\(_, msg) -> "template_listener startup failed" `T.isInfixOf` msg) logs
                    )
                    `shouldBe` True
                required <- try (void (requireBackgroundServices env services)) :: IO (Either SomeException ())
                case required of
                    Left _ ->
                        pure ()
                    Right _ ->
                        expectationFailure "required background services should reject a failed webhook worker"

        -- Only the optional template listener fails. Per the policy,
        -- requireBackgroundServices must succeed (no required service is
        -- down), AND a WARN-level log must surface so the operator sees the
        -- degraded mode. We bracket the started services so the fake worker
        -- thread is stopped on the way out (no leaked async).
        it "tolerates an optional-service failure and warns" $
            withFakeEnv $ \env logsRef ->
                bracket
                    ( startBackgroundServicesWith
                        env
                        fakeWorkerHandle
                        (ioError (userError "listener boom"))
                    )
                    stopBackgroundServices
                    \services -> do
                        listenerStatus <- readBackgroundServiceStatus env TemplateListener
                        assertFailedStatus "template listener status" "listener boom" listenerStatus
                        required <- try (void (requireBackgroundServices env services)) :: IO (Either SomeException ())
                        case required of
                            Left err ->
                                expectationFailure ("optional-service failure must not reject required check: " <> show err)
                            Right () ->
                                pure ()
                        logs <- readIORef logsRef
                        let hasDegradedWarn (lvl, msg) =
                                lvl == LogWarn
                                    && "template_listener" `T.isInfixOf` msg
                                    && "degraded mode" `T.isInfixOf` msg
                        any hasDegradedWarn logs `shouldBe` True

        -- The policy itself is data — assert the actual list so a future
        -- accidental flip from "required" to "optional" (or vice versa) is
        -- caught by the test suite rather than discovered in production.
        it "names webhook_worker as the only required service" $
            requiredForServe `shouldBe` [WebhookWorker]
        it "classifies the webhook worker as required" $
            isRequiredForServe WebhookWorker `shouldBe` True
        it "classifies the template listener as optional" $
            isRequiredForServe TemplateListener `shouldBe` False

    describe "deep-health aggregation" $ do
        it "aggregates degraded outcomes to 'degraded'" $
            aggregateStatus [CheckOk, CheckDegraded "optional down"] `shouldBe` "degraded"
        it "promotes failed over degraded to 'unhealthy'" $
            aggregateStatus [CheckDegraded "opt", CheckFailed "req"] `shouldBe` "unhealthy"
        it "does not trip 503 for a degraded response" $
            let degraded =
                    DeepHealthResponse
                        { deepHealthStatus = aggregateStatus [CheckOk, CheckDegraded "opt"]
                        , deepHealthChecks =
                            [ DeepHealthCheck{deepHealthCheckName = "webhook_worker", deepHealthCheckOutcome = CheckOk, deepHealthCheckLatencyMs = Nothing}
                            , DeepHealthCheck{deepHealthCheckName = "template_listener", deepHealthCheckOutcome = CheckDegraded "opt", deepHealthCheckLatencyMs = Nothing}
                            ]
                        }
             in isUnhealthy degraded `shouldBe` False

{- | Build a fake AppEnv that records every log line into 'logsRef'. The
inner action runs inside 'bracket' so 'destroyAppEnv' always runs.
-}
withFakeEnv ::
    (AppEnv -> IORef [(LogLevel, T.Text)] -> IO ()) ->
    IO ()
withFakeEnv action =
    case decodeConfigBytes "valid.json" validConfigBytes of
        Left err ->
            expectationFailure ("background service test config failed: " <> show err)
        Right cfg -> do
            logsRef <- newIORef []
            let logger = Logger \level msg ->
                    writeIORef logsRef . ((level, msg) :) =<< readIORef logsRef
            bracket (createAppEnvWithLogger logger cfg) destroyAppEnv (`action` logsRef)

{- | Spawn a real but inert webhook worker for tests that need a successful
'WorkerHandle' without actually delivering anything. 'Hauth.Webhooks.Worker'
catches every per-loop exception and retries, so a withConn that always
throws is harmless: the loop just retries on the polling interval and never
makes progress. 'stopWorker' will cancel it cleanly.
-}
fakeWorkerHandle :: IO WorkerHandle
fakeWorkerHandle =
    startWorker (\_ -> ioError (userError "test withConn: never connects"))

assertFailedStatus :: String -> T.Text -> BackgroundServiceStatus -> IO ()
assertFailedStatus label needle = \case
    BackgroundServiceFailed reason ->
        (needle `T.isInfixOf` reason) `shouldBe` True
    other ->
        expectationFailure (label <> ": expected failed status, got " <> show other)
