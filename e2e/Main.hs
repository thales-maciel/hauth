module Main (main) where

import qualified E2E.AdminSpec
import qualified E2E.AuthSpec
import qualified E2E.EmailTemplatesCrudSpec
import qualified E2E.EmailTemplatesLoaderSpec
import E2E.Helpers (TestEnv, truncateAll, withTestEnv)
import qualified E2E.HooksCrudSpec
import qualified E2E.HooksTypesSpec
import qualified E2E.MfaSpec
import qualified E2E.OAuthSpec
import qualified E2E.RecoverySpec
import qualified E2E.UserSpec
import qualified E2E.VerifyDatabaseSpec
import qualified E2E.WebhookDeliveriesSpec
import qualified E2E.WebhookEmitSpec
import qualified E2E.WebhookOutboxSpec
import qualified E2E.WebhookSubscriptionsSpec
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
    describe "verify database checks" E2E.VerifyDatabaseSpec.spec
    describe "webhook outbox" E2E.WebhookOutboxSpec.spec
    describe "webhook emit from handlers" E2E.WebhookEmitSpec.spec
    describe "email templates CRUD" E2E.EmailTemplatesCrudSpec.spec
    describe "webhook subscriptions CRUD" E2E.WebhookSubscriptionsSpec.spec
    describe "hooks CRUD API" E2E.HooksCrudSpec.spec
    describe "email template cache" E2E.EmailTemplatesLoaderSpec.spec
    describe "webhook deliveries API" E2E.WebhookDeliveriesSpec.spec
