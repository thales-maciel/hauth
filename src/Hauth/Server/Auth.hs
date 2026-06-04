{- | Umbrella module that re-exports the public auth handlers.

The per-flow implementations live under "Hauth.Server.Auth.*" — see
issue #163 for the rationale (review and merge-conflict bottleneck on a
single ~700-line file). The wiring in "Hauth.Server" continues to import
'tokenHandler', 'signupHandler', 'recoverHandler', 'verifyHandler',
'resendHandler' and 'settingsHandler' from this module unchanged.

Error response shapes follow the historical wire contract per endpoint —
@/token@ emits OAuth2-style bodies, signup emits Supabase-style. See
"Hauth.Server.Errors" for the helpers and a note about that split.
-}
module Hauth.Server.Auth (
    settingsHandler,
    signupHandler,
    tokenHandler,
    recoverHandler,
    verifyHandler,
    resendHandler,
) where

import Hauth.Server.Auth.Recover (recoverHandler)
import Hauth.Server.Auth.Resend (resendHandler)
import Hauth.Server.Auth.Settings (settingsHandler)
import Hauth.Server.Auth.Signup (signupHandler)
import Hauth.Server.Auth.Token (tokenHandler)
import Hauth.Server.Auth.Verify (verifyHandler)
