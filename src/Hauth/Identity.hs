module Hauth.Identity (
    Identity (..),
    IdentityId (..),
    listUserIdentities,
) where

import Data.Aeson (Value)
import Data.Text (Text)
import Data.Time (UTCTime)
import Data.UUID (UUID)
import Database.PostgreSQL.Simple (Connection, Only (..), query)
import Database.PostgreSQL.Simple.FromRow (FromRow (..), field)

-- | Opaque identity identifier (the @id@ column in @auth.identities@).
newtype IdentityId = IdentityId {unIdentityId :: Text}
    deriving stock (Eq, Show)

{- | A row from @auth.identities@.

Each row ties a @(provider, provider_id)@ pair to an @auth.users@ row.
-}
data Identity = Identity
    { identityIdentityId :: IdentityId
    -- ^ The @id@ column — for v0.1, the @provider_id@ value.
    , identityUserId :: UUID
    , identityProvider :: Text
    , identityProviderId :: Text
    , identityIdentityData :: Value
    , identityEmail :: Maybe Text
    , identityCreatedAt :: UTCTime
    , identityUpdatedAt :: UTCTime
    , identityLastSignInAt :: Maybe UTCTime
    }
    deriving stock (Eq, Show)

instance FromRow Identity where
    fromRow =
        Identity . IdentityId
            <$> field -- id
            <*> field -- user_id
            <*> field -- provider
            <*> field -- provider_id
            <*> field -- identity_data
            <*> field -- email
            <*> field -- created_at
            <*> field -- updated_at
            <*> field -- last_sign_in_at

-- | List all identities for a given user UUID.
listUserIdentities :: Connection -> UUID -> IO [Identity]
listUserIdentities conn uid =
    query
        conn
        "SELECT \
        \  id, user_id, provider, provider_id, identity_data, \
        \  email, created_at, updated_at, last_sign_in_at \
        \FROM auth.identities \
        \WHERE user_id = ?"
        (Only uid)
