module Spec.Verify.DatabaseSpec (runSpec) where

import Hauth.Verify (Check (..))
import Hauth.Verify.Database (checks)
import Spec.TestUtils (assertEqual)

runSpec :: IO ()
runSpec = do
    testChecksExported

-- | Verify the three checks are present and correctly named.
testChecksExported :: IO ()
testChecksExported = do
    assertEqual "database checks count" 3 (length checks)
    assertEqual "first check name" "config.parse" (checkName (checks !! 0))
    assertEqual "second check name" "database.connect" (checkName (checks !! 1))
    assertEqual "third check name" "database.migrations" (checkName (checks !! 2))
