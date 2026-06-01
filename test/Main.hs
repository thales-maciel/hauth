module Main (main) where

import qualified Spec.APISpec
import qualified Spec.Auth.AalAmrSpec
import qualified Spec.Auth.AdminSpec
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
import qualified Spec.VerifySpec
import System.Exit (exitSuccess)

main :: IO ()
main = do
    Spec.APISpec.runSpec
    Spec.Auth.AalAmrSpec.runSpec
    Spec.CLISpec.runSpec
    Spec.ConfigSpec.runSpec
    Spec.MigrateSpec.runSpec
    Spec.Crypto.PasswordSpec.runSpec
    Spec.Auth.JwtSpec.runSpec
    Spec.Auth.ServiceRoleSpec.runSpec
    Spec.Auth.LoginSpec.runSpec
    Spec.Auth.LogoutSpec.runSpec
    Spec.Auth.VerifySpec.runSpec
    Spec.Auth.RecoverySpec.runSpec
    Spec.Auth.UserUpdateSpec.runSpec
    Spec.Auth.AdminSpec.runSpec
    Spec.EmailSpec.runSpec
    Spec.SessionSpec.runSpec
    Spec.UserSpec.runSpec
    Spec.OAuth.GoogleSpec.runSpec
    Spec.OAuthSpec.runSpec
    Spec.OAuth.GithubSpec.runSpec
    Spec.Mfa.TotpSpec.runSpec
    Spec.Mfa.VerifySpec.runSpec
    Spec.RefreshTokenSpec.runSpec
    Spec.ServerSpec.runSpec
    Spec.VerifySpec.runSpec
    exitSuccess
