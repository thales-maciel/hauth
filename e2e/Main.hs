module Main (main) where

import qualified E2E.AdminSpec
import qualified E2E.AuthSpec
import E2E.Helpers (TestEnv, truncateAll, withTestEnv)
import qualified E2E.HooksTypesSpec
import qualified E2E.MfaSpec
import qualified E2E.OAuthSpec
import qualified E2E.RecoverySpec
import qualified E2E.UserSpec
import qualified E2E.WebhookOutboxSpec
import Test.Hspec (SpecWith, aroundAll, beforeWith, describe, hspec)

main :: IO ()
main = hspec $ aroundAll withTestEnv $ beforeWith truncateBefore allSpecs
  where
    truncateBefore env = truncateAll env >> pure env

allSpecs :: SpecWith TestEnv
allSpecs = do
    describe "auth flow" E2E.AuthSpec.spec
    describe "/user" E2E.UserSpec.spec
    describe "password recovery" E2E.RecoverySpec.spec
    describe "MFA TOTP" E2E.MfaSpec.spec
    describe "admin users API" E2E.AdminSpec.spec
    describe "OAuth (limited)" E2E.OAuthSpec.spec
    describe "hooks types (loadHookConfig)" E2E.HooksTypesSpec.spec
    describe "webhook outbox" E2E.WebhookOutboxSpec.spec
