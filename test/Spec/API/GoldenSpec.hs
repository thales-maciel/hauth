{- | Wire-shape coverage for every request and response type referenced by
'Hauth.API.HauthAPI'.

The actual per-surface tests live under "Spec.API.Golden.*"; this module
just composes them so the top-level 'API golden encodings' group in
@test\/Main.hs@ stays a single line. Splitting matches the per-surface
'Hauth.API.Types.*' decomposition done in issue #163.

The shape comparison is structural — keys are compared via 'Aeson.Value'
equality, not byte-for-byte — so the tests don't accidentally lock us to
a specific key ordering, only to the field-name contract. The point of
these tests is to make Generic-derived drift impossible. If anyone reaches
for @deriving anyclass (FromJSON, ToJSON)@ on a wire type again (banned
in AGENTS.md), the encode-shape assertion fails because the Haskell record
field name leaks into the JSON.
-}
module Spec.API.GoldenSpec (spec) where

import qualified Spec.API.Golden.AdminSpec
import qualified Spec.API.Golden.AuthSpec
import qualified Spec.API.Golden.HealthSpec
import qualified Spec.API.Golden.HooksSpec
import qualified Spec.API.Golden.MfaSpec
import qualified Spec.API.Golden.SettingsSpec
import qualified Spec.API.Golden.WebhooksSpec
import Test.Hspec (Spec)

spec :: Spec
spec = do
    Spec.API.Golden.HealthSpec.spec
    Spec.API.Golden.SettingsSpec.spec
    Spec.API.Golden.AuthSpec.spec
    Spec.API.Golden.MfaSpec.spec
    Spec.API.Golden.AdminSpec.spec
    Spec.API.Golden.WebhooksSpec.spec
    Spec.API.Golden.HooksSpec.spec
