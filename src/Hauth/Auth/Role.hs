{- | Reserved-role policy for user-session JWTs.

A user-session JWT must never carry a control-plane role in its @role@
claim, because 'Hauth.API.Auth.checkServiceRole' (and any future role-gated
middleware) trusts that claim verbatim.  This module centralizes the
reserved set so the admin-write validator and the issuance-side sanitizer
agree on the same source of truth.

The set intentionally excludes Postgres infra roles like @postgres@ and
@authenticator@ — those should never appear in @auth.users.role@ to begin
with, and reserving them here would imply a policy this module cannot
enforce.  Extend 'reservedRoles' when a new control-plane role is
introduced.
-}
module Hauth.Auth.Role (
    reservedRoles,
    isReservedRole,
    sanitizeSessionRole,
) where

import Data.Set (Set)
import qualified Data.Set as Set
import Data.Text (Text)
import qualified Data.Text as T

{- | Roles that must not appear in a user-session JWT.

* @service_role@ — privileged role trusted by 'Hauth.API.Auth.checkServiceRole'.
* @anon@ — Supabase's unauthenticated role; granting it to an authenticated
  session_id would conflict with anonymous-only RLS policies downstream.
* @supabase_admin@, @supabase_auth_admin@ — Postgres-side roles with
  elevated authority in standard Supabase deployments.
-}
reservedRoles :: Set Text
reservedRoles =
    Set.fromList
        [ "service_role"
        , "anon"
        , "supabase_admin"
        , "supabase_auth_admin"
        ]

-- | @True@ iff the given role is a reserved control-plane role.
isReservedRole :: Text -> Bool
isReservedRole = (`Set.member` reservedRoles)

{- | Coerce a role value into one safe to emit in a user-session JWT.

Returns @"authenticated"@ when the input is reserved or blank, otherwise
returns the input verbatim.  Apply at every user-session JWT issuance call
site so a row whose @role@ column was mutated outside the admin validator
(e.g. by direct SQL or pre-existing data) cannot mint control-plane
authority through a normal refresh.
-}
sanitizeSessionRole :: Text -> Text
sanitizeSessionRole role
    | T.null role = "authenticated"
    | isReservedRole role = "authenticated"
    | otherwise = role
