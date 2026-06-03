{-# LANGUAGE BlockArguments #-}
{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE ScopedTypeVariables #-}

module Spec.ServerSpec (spec) where

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

    describe "background service startup failure" $
        it "logs failed services and rejects required check" $
            case decodeConfigBytes "valid.json" validConfigBytes of
                Left err ->
                    expectationFailure ("background service test config failed: " <> show err)
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

assertFailedStatus :: String -> T.Text -> BackgroundServiceStatus -> IO ()
assertFailedStatus label needle = \case
    BackgroundServiceFailed reason ->
        (needle `T.isInfixOf` reason) `shouldBe` True
    other ->
        expectationFailure (label <> ": expected failed status, got " <> show other)
