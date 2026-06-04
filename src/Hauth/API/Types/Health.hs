-- | Wire types for the @\/health@ and @\/health\/deep@ endpoints.
module Hauth.API.Types.Health (
    HealthResponse (..),
    CheckOutcome (..),
    DeepHealthCheck (..),
    DeepHealthResponse (..),
) where

import Data.Aeson (ToJSON (toJSON), object, (.=))
import qualified Data.Aeson as Aeson
import Data.Text (Text)

newtype HealthResponse = HealthResponse
    { healthStatus :: Text
    }
    deriving stock (Eq, Show)

instance ToJSON HealthResponse where
    toJSON HealthResponse{healthStatus} =
        object ["status" .= healthStatus]

{- | Outcome of one deep-health component check.

The @\"degraded\"@ status is reserved for optional components that failed
but should not flip the overall response to @\"unhealthy\"@ / 503. See
'Hauth.Server.Health.aggregateStatus' and the @\"Background services\"@
section of @docs\/PRODUCTION.md@ for the policy.
-}
data CheckOutcome
    = CheckOk
    | CheckFailed Text
    | CheckDegraded Text
    deriving stock (Eq, Show)

instance ToJSON CheckOutcome where
    toJSON CheckOk =
        Aeson.String "ok"
    toJSON (CheckFailed reason) =
        object
            [ "status" .= ("failed" :: Text)
            , "reason" .= reason
            ]
    toJSON (CheckDegraded reason) =
        object
            [ "status" .= ("degraded" :: Text)
            , "reason" .= reason
            ]

data DeepHealthCheck = DeepHealthCheck
    { deepHealthCheckName :: Text
    , deepHealthCheckOutcome :: CheckOutcome
    , deepHealthCheckLatencyMs :: Maybe Int
    }
    deriving stock (Eq, Show)

instance ToJSON DeepHealthCheck where
    toJSON DeepHealthCheck{deepHealthCheckName, deepHealthCheckOutcome, deepHealthCheckLatencyMs} =
        let base =
                [ "name" .= deepHealthCheckName
                , "latency_ms" .= deepHealthCheckLatencyMs
                ]
            statusFields = case deepHealthCheckOutcome of
                CheckOk -> ["status" .= ("ok" :: Text)]
                CheckFailed reason ->
                    [ "status" .= ("failed" :: Text)
                    , "reason" .= reason
                    ]
                CheckDegraded reason ->
                    [ "status" .= ("degraded" :: Text)
                    , "reason" .= reason
                    ]
         in object (base <> statusFields)

data DeepHealthResponse = DeepHealthResponse
    { deepHealthStatus :: Text
    , deepHealthChecks :: [DeepHealthCheck]
    }
    deriving stock (Eq, Show)

instance ToJSON DeepHealthResponse where
    toJSON DeepHealthResponse{deepHealthStatus, deepHealthChecks} =
        object
            [ "status" .= deepHealthStatus
            , "checks" .= deepHealthChecks
            ]
