{-# OPTIONS_GHC -Wno-orphans #-}

module Hauth.API.Auth (
    AdminUIPrincipal (..),
    AnonymousPrincipal (..),
    AuthRequirement (..),
    RequireAuth,
    ServiceRolePrincipal (..),
    SessionPrincipal (..),
    checkServiceRole,
    extractBearerToken,
) where

import Data.ByteString (ByteString)
import Data.Kind (Type)
import Data.Text (Text)
import qualified Data.Text as T
import qualified Data.Text.Encoding as TE
import GHC.TypeLits (Symbol)
import Hauth.Auth.Jwt (AccessTokenClaims (..), JwtError)
import Network.HTTP.Types (Header)
import Servant.API.Experimental.Auth (AuthProtect)
import Servant.Server.Experimental.Auth (AuthServerData)

data AuthRequirement
    = Anonymous
    | ValidSession
    | ServiceRole
    | AdminSession

type AuthScheme :: AuthRequirement -> Symbol
type family AuthScheme requirement where
    AuthScheme 'Anonymous = "anonymous"
    AuthScheme 'ValidSession = "valid-session"
    AuthScheme 'ServiceRole = "service-role"
    AuthScheme 'AdminSession = "admin-session"

type RequireAuth :: AuthRequirement -> Type
type RequireAuth requirement = AuthProtect (AuthScheme requirement)

data AnonymousPrincipal = AnonymousPrincipal
    deriving stock (Eq, Show)

data SessionPrincipal = SessionPrincipal
    { sessionUserId :: Text
    , sessionRole :: Text
    , sessionAccessTokenId :: Text
    }
    deriving stock (Eq, Show)

newtype ServiceRolePrincipal = ServiceRolePrincipal
    { serviceRoleName :: Text
    }
    deriving stock (Eq, Show)

{- | Proof of a live admin UI session (cookie validated against
@auth.admin_ui_sessions@), distinct from JWT-backed 'SessionPrincipal'.
-}
data AdminUIPrincipal = AdminUIPrincipal
    { adminPrincipalUsername :: Text
    , adminPrincipalTokenHash :: Text
    }
    deriving stock (Eq, Show)

type instance AuthServerData (AuthProtect "anonymous") = AnonymousPrincipal
type instance AuthServerData (AuthProtect "valid-session") = SessionPrincipal
type instance AuthServerData (AuthProtect "service-role") = ServiceRolePrincipal
type instance AuthServerData (AuthProtect "admin-session") = AdminUIPrincipal

{- | Extract a bearer token from a list of HTTP request headers.

Looks up the @Authorization@ header and expects the value to be of the form
@Bearer \<token\>@. Returns the token text on success or an error description
on failure.
-}
extractBearerToken :: [Header] -> Either Text Text
extractBearerToken headers =
    case lookup "Authorization" headers of
        Nothing ->
            Left "Missing Authorization header"
        Just raw ->
            let value = TE.decodeUtf8 (raw :: ByteString)
             in case T.stripPrefix "Bearer " value of
                    Nothing ->
                        Left "Authorization header is not a Bearer token"
                    Just token
                        | T.null token ->
                            Left "Bearer token is empty"
                        | otherwise ->
                            Right token

{- | Check that a validated JWT result carries the @service_role@ role.

Returns a 'ServiceRolePrincipal' when the claims are valid and the role
matches, or an error description otherwise.
-}
checkServiceRole :: Either JwtError AccessTokenClaims -> Either Text ServiceRolePrincipal
checkServiceRole (Left err) =
    Left ("JWT validation failed: " <> T.pack (show err))
checkServiceRole (Right claims)
    | claimRole claims == "service_role" =
        Right ServiceRolePrincipal{serviceRoleName = "service_role"}
    | otherwise =
        Left ("Insufficient role: expected service_role, got " <> claimRole claims)
