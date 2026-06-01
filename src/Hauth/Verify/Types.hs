module Hauth.Verify.Types (
    Check (..),
    CheckOutcome (..),
    Report (..),
) where

import Data.Text (Text)
import Hauth.Env (AppEnv)

data CheckOutcome
    = CheckOk
    | CheckWarn Text
    | CheckFail Text
    deriving stock (Eq, Show)

data Check = Check
    { checkName :: Text
    , checkLabel :: Text
    , checkRun :: AppEnv -> IO CheckOutcome
    }

data Report = Report
    { reportResults :: [(Check, CheckOutcome)]
    , reportPassed :: Int
    , reportWarned :: Int
    , reportFailed :: Int
    }
