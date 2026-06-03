module Main (main) where

import qualified Spec.API.GoldenSpec
import qualified Spec.APISpec
import qualified Spec.Auth.AalAmrSpec
import qualified Spec.Auth.AdminSpec
import qualified Spec.Auth.CustomAccessTokenSpec
import qualified Spec.Auth.JwtPropertySpec
import qualified Spec.Auth.JwtSpec
import qualified Spec.Auth.LoginSpec
import qualified Spec.Auth.LogoutSpec
import qualified Spec.Auth.RecoverySpec
import qualified Spec.Auth.ServiceRoleSpec
import qualified Spec.Auth.UserUpdateSpec
import qualified Spec.Auth.VerifySpec
import qualified Spec.CLISpec
import qualified Spec.ConfigSpec
import qualified Spec.Crypto.PasswordSpec
import qualified Spec.EmailSpec
import qualified Spec.Hooks.RunnerSpec
import qualified Spec.Hooks.TypesSpec
import qualified Spec.Mfa.TotpSpec
import qualified Spec.Mfa.VerifySpec
import qualified Spec.MigrateSpec
import qualified Spec.OAuth.GithubSpec
import qualified Spec.OAuth.GoogleSpec
import qualified Spec.OAuthSpec
import qualified Spec.RefreshTokenSpec
import qualified Spec.ServerSpec
import qualified Spec.SessionSpec
import qualified Spec.UserSpec
import qualified Spec.Verify.DatabaseSpec
import qualified Spec.Verify.IdentitySpec
import qualified Spec.Verify.OauthSpec
import qualified Spec.Verify.SmtpSpec
import qualified Spec.VerifySpec
import qualified Spec.Webhooks.SigningSpec
import Test.Hspec (Spec, describe, hspec)

main :: IO ()
main = hspec specs

specs :: Spec
specs = do
    describe "API golden encodings" Spec.API.GoldenSpec.spec
    describe "API server" Spec.APISpec.spec
    describe "auth/aal & amr" Spec.Auth.AalAmrSpec.spec
    describe "auth/admin users" Spec.Auth.AdminSpec.spec
    describe "auth/custom-access-token hook" Spec.Auth.CustomAccessTokenSpec.spec
    describe "auth/JWT" Spec.Auth.JwtSpec.spec
    describe "auth/JWT properties" Spec.Auth.JwtPropertySpec.spec
    describe "auth/login" Spec.Auth.LoginSpec.spec
    describe "auth/logout" Spec.Auth.LogoutSpec.spec
    describe "auth/recovery" Spec.Auth.RecoverySpec.spec
    describe "auth/service-role" Spec.Auth.ServiceRoleSpec.spec
    describe "auth/user update" Spec.Auth.UserUpdateSpec.spec
    describe "auth/verify" Spec.Auth.VerifySpec.spec
    describe "CLI" Spec.CLISpec.spec
    describe "config" Spec.ConfigSpec.spec
    describe "crypto/password" Spec.Crypto.PasswordSpec.spec
    describe "email rendering" Spec.EmailSpec.spec
    describe "hooks/runner" Spec.Hooks.RunnerSpec.spec
    describe "hooks/types" Spec.Hooks.TypesSpec.spec
    describe "MFA/TOTP" Spec.Mfa.TotpSpec.spec
    describe "MFA verify" Spec.Mfa.VerifySpec.spec
    describe "migrations" Spec.MigrateSpec.spec
    describe "OAuth/Github" Spec.OAuth.GithubSpec.spec
    describe "OAuth/Google" Spec.OAuth.GoogleSpec.spec
    describe "OAuth handlers" Spec.OAuthSpec.spec
    describe "refresh tokens" Spec.RefreshTokenSpec.spec
    describe "server wiring" Spec.ServerSpec.spec
    describe "session helpers" Spec.SessionSpec.spec
    describe "user identity" Spec.UserSpec.spec
    describe "verify/database" Spec.Verify.DatabaseSpec.spec
    describe "verify/identity" Spec.Verify.IdentitySpec.spec
    describe "verify/oauth" Spec.Verify.OauthSpec.spec
    describe "verify/smtp" Spec.Verify.SmtpSpec.spec
    describe "verify subcommand" Spec.VerifySpec.spec
    describe "webhook signing" Spec.Webhooks.SigningSpec.spec
