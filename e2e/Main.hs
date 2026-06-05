module Main (main) where

import qualified E2E.AdminSpec
import qualified E2E.AuthSpec
import qualified E2E.CompatibilityPlaceholdersSpec
import qualified E2E.EmailTemplatesCrudSpec
import qualified E2E.EmailTemplatesLoaderSpec
import qualified E2E.EmailTemplatesSchemaSpec
import qualified E2E.EmailTemplatesSpec
import qualified E2E.HealthSpec
import E2E.Helpers (TestEnv, truncateAll, withTestEnv)
import qualified E2E.HooksCrudSpec
import qualified E2E.HooksSpec
import qualified E2E.HooksTypesSpec
import qualified E2E.LogoutScopeSpec
import qualified E2E.MfaSpec
import qualified E2E.MigrateSpec
import qualified E2E.OAuthSpec
import qualified E2E.RecoverySpec
import qualified E2E.UserSpec
import qualified E2E.VerifyDatabaseSpec
import qualified E2E.VerifySpec
import qualified E2E.WebhookDeliveriesSpec
import qualified E2E.WebhookEmitSpec
import qualified E2E.WebhookOutboxSpec
import qualified E2E.WebhookSubscriptionsSpec
import qualified E2E.WebhookWorkerSpec
import qualified E2E.WebhooksSpec
import Test.Hspec (SpecWith, aroundAll, beforeWith, describe, hspec)

main :: IO ()
main = hspec $ aroundAll withTestEnv $ beforeWith truncateBefore allSpecs
  where
    truncateBefore env = truncateAll env >> pure env

allSpecs :: SpecWith TestEnv
allSpecs = do
    describe "auth flow" E2E.AuthSpec.spec
    describe "logout scope semantics" E2E.LogoutScopeSpec.spec
    describe "/user" E2E.UserSpec.spec
    describe "password recovery" E2E.RecoverySpec.spec
    describe "MFA TOTP" E2E.MfaSpec.spec
    describe "migration drift detection" E2E.MigrateSpec.spec
    describe "admin users API" E2E.AdminSpec.spec
    describe "compatibility placeholder routes" E2E.CompatibilityPlaceholdersSpec.spec
    describe "health checks" E2E.HealthSpec.spec
    describe "OAuth (limited)" E2E.OAuthSpec.spec
    describe "hooks types (loadHookConfig)" E2E.HooksTypesSpec.spec
    describe "verify database checks" E2E.VerifyDatabaseSpec.spec
    describe "verify subcommand" E2E.VerifySpec.spec
    describe "webhook outbox" E2E.WebhookOutboxSpec.spec
    describe "webhook emit from handlers" E2E.WebhookEmitSpec.spec
    describe "email templates schema seed" E2E.EmailTemplatesSchemaSpec.spec
    describe "email templates CRUD" E2E.EmailTemplatesCrudSpec.spec
    describe "webhook subscriptions CRUD" E2E.WebhookSubscriptionsSpec.spec
    describe "hooks CRUD API" E2E.HooksCrudSpec.spec
    describe "sync hooks integration" E2E.HooksSpec.spec
    describe "email template cache" E2E.EmailTemplatesLoaderSpec.spec
    describe "webhook deliveries API" E2E.WebhookDeliveriesSpec.spec
    describe "email template hot-reload" E2E.EmailTemplatesSpec.spec
    describe "webhook delivery worker" E2E.WebhookWorkerSpec.spec
    describe "webhooks end-to-end" E2E.WebhooksSpec.spec
