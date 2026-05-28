{-# OPTIONS_GHC -Wno-orphans #-}

module Hauth.API.Auth (
    AnonymousPrincipal (..),
    AuthRequirement (..),
    RequireAuth,
    ServiceRolePrincipal (..),
    SessionPrincipal (..),
) where

import Data.Kind (Type)
import Data.Text (Text)
import GHC.TypeLits (Symbol)
import Servant.API.Experimental.Auth (AuthProtect)
import Servant.Server.Experimental.Auth (AuthServerData)

data AuthRequirement
    = Anonymous
    | ValidSession
    | ServiceRole

type AuthScheme :: AuthRequirement -> Symbol
type family AuthScheme requirement where
    AuthScheme 'Anonymous = "anonymous"
    AuthScheme 'ValidSession = "valid-session"
    AuthScheme 'ServiceRole = "service-role"

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

type instance AuthServerData (AuthProtect "anonymous") = AnonymousPrincipal
type instance AuthServerData (AuthProtect "valid-session") = SessionPrincipal
type instance AuthServerData (AuthProtect "service-role") = ServiceRolePrincipal
