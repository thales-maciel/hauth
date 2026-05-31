{- | Pure helpers for logout / session-revocation logic.

These functions are intentionally pure so they can be unit-tested without a
live database or HTTP server.
-}
module Hauth.Auth.Logout (
    LogoutError (..),
    resolveLogoutSession,
    sessionIdFromClaims,
) where

import Data.Text (Text)
import qualified Data.Text as T
import qualified Data.UUID as UUID
import Hauth.Auth.Jwt (AccessTokenClaims (..), JwtError (..))
import Hauth.Session (SessionId (..))

-- | Errors that can arise while processing a logout request.
data LogoutError
    = -- | The @Authorization@ header was absent or not a Bearer token.
      LogoutMissingAuth
    | -- | The JWT was present but failed signature / claim validation.
      LogoutInvalidJwt Text
    | -- | The @session_id@ claim was present but could not be parsed as a UUID.
      LogoutBadSessionId Text
    deriving stock (Eq, Show)

{- | Parse a 'SessionId' from the @session_id@ claim of validated token claims.

Returns @Left (LogoutBadSessionId reason)@ when the claim text is not a
valid UUID string.
-}
sessionIdFromClaims :: AccessTokenClaims -> Either LogoutError SessionId
sessionIdFromClaims claims =
    let sid = claimSessionId claims
     in case UUID.fromText sid of
            Nothing ->
                Left
                    ( LogoutBadSessionId
                        ("session_id claim is not a valid UUID: " <> sid)
                    )
            Just uuid ->
                Right (SessionId uuid)

{- | Map a JWT validation result to either a 'LogoutError' or a 'SessionId'.

* @Left JwtVerifyError@ / @Left JwtClaimError@ / @Left JwtSignError@
  → @Left (LogoutInvalidJwt msg)@.
* @Right claims@ with a parseable @session_id@
  → @Right SessionId@.
* @Right claims@ with an un-parseable @session_id@
  → @Left (LogoutBadSessionId msg)@.
-}
resolveLogoutSession ::
    Either JwtError AccessTokenClaims ->
    Either LogoutError SessionId
resolveLogoutSession (Left err) =
    Left (LogoutInvalidJwt (T.pack (show err)))
resolveLogoutSession (Right claims) =
    sessionIdFromClaims claims
