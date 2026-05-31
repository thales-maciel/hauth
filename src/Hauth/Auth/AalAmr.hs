{- | Pure helpers for deriving AAL and AMR state from a session.

v0.1 simplification: the initiating authentication method is not persisted
on the session row, so we default to @"password"@ when no override is
supplied.  Callers that know the session was created via OAuth, OTP, or
recovery can pass @Just "oauth"@ / @Just "otp"@ / @Just "recovery"@
respectively.  This limitation will be addressed in a future version once
the session schema records the initiating method.
-}
module Hauth.Auth.AalAmr (
    SessionAuthState (..),
    aalForSession,
    buildAmrEntries,
    deriveSessionAuthState,
) where

import Data.Maybe (fromMaybe)
import Data.Text (Text)
import Data.Time.Clock.POSIX (POSIXTime)
import Hauth.Auth.Jwt (AmrEntry (..))
import Hauth.Session (Session (..))

-- | A v0.1 session-derived authentication state.
data SessionAuthState = SessionAuthState
    { sasAal :: Text
    -- ^ Authenticator Assurance Level: @"aal1"@ or @"aal2"@.
    , sasMethods :: [Text]
    -- ^ Ordered list of authentication methods, e.g. @["password"]@ or
    --   @["password", "totp"]@.
    }
    deriving stock (Eq, Show)

{- | Derive the AAL from a 'Session' row.

Returns @"aal2"@ when 'sessionFactorId' is non-null, @"aal1"@ otherwise.
-}
aalForSession :: Session -> Text
aalForSession sess =
    case sessionFactorId sess of
        Just _ -> "aal2"
        Nothing -> "aal1"

{- | Derive the full 'SessionAuthState' from a session row.

The optional @initiatingMethod@ parameter overrides the default @"password"@
assumption for the first entry in the AMR list.  Pass @Nothing@ for the
common password-grant case; pass @Just "oauth"@, @Just "otp"@, or
@Just "recovery"@ when the caller knows the session origin.

When 'sessionFactorId' is non-null, @"totp"@ is appended to the method list
and the AAL is elevated to @"aal2"@.
-}
deriveSessionAuthState :: Maybe Text -> Session -> SessionAuthState
deriveSessionAuthState mInitiatingMethod sess =
    let initiating = fromMaybe "password" mInitiatingMethod
        base = [initiating]
        methods = case sessionFactorId sess of
            Just _ -> base ++ ["totp"]
            Nothing -> base
        aal = aalForSession sess
     in SessionAuthState
            { sasAal = aal
            , sasMethods = methods
            }

{- | Build a list of 'AmrEntry' values from a method list and a timestamp.

Every entry in the returned list carries the same @timestamp@ value — this
matches Supabase Auth v2 behaviour where the AMR timestamp records when the
token was issued, not when each individual step was completed.
-}
buildAmrEntries :: [Text] -> POSIXTime -> [AmrEntry]
buildAmrEntries methods ts =
    let tsSecs = floor ts :: Integer
     in fmap (\m -> AmrEntry{amrMethod = m, amrTimestamp = tsSecs}) methods
