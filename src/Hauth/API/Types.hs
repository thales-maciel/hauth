{- | Umbrella module that re-exports every wire-shape type referenced by
'Hauth.API.HauthAPI'.

The actual type definitions live in per-surface sub-modules under
"Hauth.API.Types.*" — see issue #163 for the rationale (review and
merge-conflict bottleneck on a single 1.4k-line file). Consumers that
@import Hauth.API.Types@ keep working unchanged because every type and
helper is re-exported here verbatim.

Wire shapes are intentionally hand-written across all sub-modules; the
@check-derived-json@ Makefile guard scans the whole tree for any stray
@deriving anyclass FromJSON@ / @ToJSON@ that would change the shape.
-}
module Hauth.API.Types (
    module X,
) where

import Hauth.API.Types.Admin as X
import Hauth.API.Types.Auth as X
import Hauth.API.Types.Common as X
import Hauth.API.Types.EmailTemplates as X
import Hauth.API.Types.Health as X
import Hauth.API.Types.Hooks as X
import Hauth.API.Types.Mfa as X
import Hauth.API.Types.OAuth as X
import Hauth.API.Types.Settings as X
import Hauth.API.Types.Webhooks as X
