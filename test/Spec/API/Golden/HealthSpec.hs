-- | Wire-shape coverage for the @\/health@ and @\/health\/deep@ endpoints.
module Spec.API.Golden.HealthSpec (spec) where

import Hauth.API.Types
import Spec.API.Golden.Helpers (encodeShape)
import Test.Hspec (Spec, describe, it)

spec :: Spec
spec = describe "Health" $ do
    it "HealthResponse" $
        encodeShape
            "HealthResponse"
            HealthResponse{healthStatus = "ok"}
            "{\"status\":\"ok\"}"

    it "DeepHealthResponse" $
        encodeShape
            "DeepHealthResponse"
            DeepHealthResponse
                { deepHealthStatus = "ok"
                , deepHealthChecks =
                    [ DeepHealthCheck
                        { deepHealthCheckName = "process"
                        , deepHealthCheckOutcome = CheckOk
                        , deepHealthCheckLatencyMs = Nothing
                        }
                    , DeepHealthCheck
                        { deepHealthCheckName = "postgres"
                        , deepHealthCheckOutcome = CheckFailed "boom"
                        , deepHealthCheckLatencyMs = Just 42
                        }
                    ]
                }
            "{\"status\":\"ok\",\"checks\":\
            \[{\"name\":\"process\",\"status\":\"ok\",\"latency_ms\":null}\
            \,{\"name\":\"postgres\",\"status\":\"failed\",\"reason\":\"boom\",\"latency_ms\":42}]}"
