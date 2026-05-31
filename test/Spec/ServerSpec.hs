module Spec.ServerSpec (runSpec) where

import Data.Aeson (Object, Value (..))
import qualified Data.Aeson as Aeson
import qualified Data.Aeson.KeyMap as KeyMap
import Hauth.API.Types (
    CheckOutcome (..),
    DeepHealthCheck (..),
    DeepHealthResponse (..),
 )
import Hauth.Server (aggregateStatus, isUnhealthy)
import Spec.TestUtils (assertEqual)

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
