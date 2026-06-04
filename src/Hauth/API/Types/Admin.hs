{- | Wire types for the admin surface: user CRUD, identities, invites,
provider configuration, and magic-link generation.
-}
module Hauth.API.Types.Admin (
    ListUsersResponse (..),
    AdminCreateUserRequest (..),
    AdminUpdateUserRequest (..),
    DeletedUserResponse (..),
    IdentityId (..),
    IdentityResponse (..),
    buildIdentityResponse,
    ListIdentitiesResponse (..),
    GenerateLinkRequest (..),
    GenerateLinkResponse (..),
    InviteUserRequest (..),
    ProvidersResponse (..),
    UpdateProvidersRequest (..),
) where

import Data.Aeson (FromJSON (..), ToJSON (toJSON), Value, object, (.=))
import qualified Data.Aeson as Aeson
import Data.Text (Text)
import Data.Time (UTCTime)
import Data.UUID (UUID)
import GHC.Generics (Generic)
import Hauth.API.Types.Common (Email, Password, UserResponse)
import qualified Hauth.Identity as Identity
import Web.HttpApiData (FromHttpApiData, ToHttpApiData)

newtype IdentityId = IdentityId {unIdentityId :: Text}
    deriving stock (Eq, Generic, Ord, Show)
    deriving newtype (FromHttpApiData, FromJSON, ToHttpApiData, ToJSON)

data ListUsersResponse = ListUsersResponse
    { listUsers :: [UserResponse]
    , listUsersAud :: Text
    , listUsersNextPage :: Maybe Int
    }
    deriving stock (Eq, Generic, Show)

instance ToJSON ListUsersResponse where
    toJSON ListUsersResponse{listUsers, listUsersAud, listUsersNextPage} =
        object
            [ "users" .= listUsers
            , "aud" .= listUsersAud
            , "next_page" .= listUsersNextPage
            ]

instance FromJSON ListUsersResponse where
    parseJSON = Aeson.withObject "ListUsersResponse" \o ->
        ListUsersResponse
            <$> o Aeson..: "users"
            <*> o Aeson..: "aud"
            <*> o Aeson..:? "next_page"

data AdminCreateUserRequest = AdminCreateUserRequest
    { adminCreateUserEmail :: Email
    , adminCreateUserPassword :: Maybe Password
    -- ^ Optional: if absent a random temporary password is generated.
    , adminCreateUserConfirmed :: Bool
    -- ^ If 'True', set @email_confirmed_at = now()@.
    , adminCreateUserUserMetadata :: Maybe Value
    , adminCreateUserAppMetadata :: Maybe Value
    }
    deriving stock (Eq, Generic, Show)

instance FromJSON AdminCreateUserRequest where
    parseJSON = Aeson.withObject "AdminCreateUserRequest" \o ->
        AdminCreateUserRequest
            <$> o Aeson..: "email"
            <*> o Aeson..:? "password"
            <*> (o Aeson..:? "email_confirm" Aeson..!= False)
            <*> o Aeson..:? "user_metadata"
            <*> o Aeson..:? "app_metadata"

instance ToJSON AdminCreateUserRequest where
    toJSON AdminCreateUserRequest{..} =
        object
            [ "email" .= adminCreateUserEmail
            , "password" .= adminCreateUserPassword
            , "email_confirm" .= adminCreateUserConfirmed
            , "user_metadata" .= adminCreateUserUserMetadata
            , "app_metadata" .= adminCreateUserAppMetadata
            ]

data AdminUpdateUserRequest = AdminUpdateUserRequest
    { adminUpdateUserEmail :: Maybe Email
    , adminUpdateUserPassword :: Maybe Password
    , adminUpdateUserEmailConfirm :: Maybe Bool
    -- ^ If 'Just True', confirm email; 'Just False' un-confirms; 'Nothing' leaves untouched.
    , adminUpdateUserBannedUntil :: Maybe UTCTime
    , adminUpdateUserRole :: Maybe Text
    , adminUpdateUserUserMetadata :: Maybe Value
    , adminUpdateUserAppMetadata :: Maybe Value
    }
    deriving stock (Eq, Generic, Show)

instance FromJSON AdminUpdateUserRequest where
    parseJSON = Aeson.withObject "AdminUpdateUserRequest" \o ->
        AdminUpdateUserRequest
            <$> o Aeson..:? "email"
            <*> o Aeson..:? "password"
            <*> o Aeson..:? "email_confirm"
            <*> o Aeson..:? "banned_until"
            <*> o Aeson..:? "role"
            <*> o Aeson..:? "user_metadata"
            <*> o Aeson..:? "app_metadata"

instance ToJSON AdminUpdateUserRequest where
    toJSON AdminUpdateUserRequest{..} =
        object
            [ "email" .= adminUpdateUserEmail
            , "password" .= adminUpdateUserPassword
            , "email_confirm" .= adminUpdateUserEmailConfirm
            , "banned_until" .= adminUpdateUserBannedUntil
            , "role" .= adminUpdateUserRole
            , "user_metadata" .= adminUpdateUserUserMetadata
            , "app_metadata" .= adminUpdateUserAppMetadata
            ]

newtype DeletedUserResponse = DeletedUserResponse
    { deletedUser :: UserResponse
    }
    deriving stock (Eq, Generic, Show)

instance ToJSON DeletedUserResponse where
    toJSON DeletedUserResponse{deletedUser} =
        object ["user" .= deletedUser]

instance FromJSON DeletedUserResponse where
    parseJSON = Aeson.withObject "DeletedUserResponse" \o ->
        DeletedUserResponse <$> o Aeson..: "user"

-- | Wire representation of an identity row for API responses.
data IdentityResponse = IdentityResponse
    { identityResponseId :: Text
    , identityResponseUserId :: UUID
    , identityResponseProvider :: Text
    , identityResponseProviderId :: Text
    , identityResponseIdentityData :: Value
    , identityResponseEmail :: Maybe Text
    , identityResponseCreatedAt :: UTCTime
    , identityResponseUpdatedAt :: UTCTime
    , identityResponseLastSignInAt :: Maybe UTCTime
    }
    deriving stock (Eq, Show)

instance ToJSON IdentityResponse where
    toJSON IdentityResponse{..} =
        object
            [ "id" .= identityResponseId
            , "user_id" .= identityResponseUserId
            , "provider" .= identityResponseProvider
            , "provider_id" .= identityResponseProviderId
            , "identity_data" .= identityResponseIdentityData
            , "email" .= identityResponseEmail
            , "created_at" .= identityResponseCreatedAt
            , "updated_at" .= identityResponseUpdatedAt
            , "last_sign_in_at" .= identityResponseLastSignInAt
            ]

instance FromJSON IdentityResponse where
    parseJSON = Aeson.withObject "IdentityResponse" \o ->
        IdentityResponse
            <$> o Aeson..: "id"
            <*> o Aeson..: "user_id"
            <*> o Aeson..: "provider"
            <*> o Aeson..: "provider_id"
            <*> o Aeson..: "identity_data"
            <*> o Aeson..:? "email"
            <*> o Aeson..: "created_at"
            <*> o Aeson..: "updated_at"
            <*> o Aeson..:? "last_sign_in_at"

-- | Build an 'IdentityResponse' from the domain 'Identity.Identity'.
buildIdentityResponse :: Identity.Identity -> IdentityResponse
buildIdentityResponse Identity.Identity{..} =
    IdentityResponse
        { identityResponseId = Identity.unIdentityId identityIdentityId
        , identityResponseUserId = identityUserId
        , identityResponseProvider = identityProvider
        , identityResponseProviderId = identityProviderId
        , identityResponseIdentityData = identityIdentityData
        , identityResponseEmail = identityEmail
        , identityResponseCreatedAt = identityCreatedAt
        , identityResponseUpdatedAt = identityUpdatedAt
        , identityResponseLastSignInAt = identityLastSignInAt
        }

newtype ListIdentitiesResponse = ListIdentitiesResponse
    { listIdentities :: [IdentityResponse]
    }
    deriving stock (Eq, Generic, Show)

instance ToJSON ListIdentitiesResponse where
    toJSON ListIdentitiesResponse{listIdentities} =
        object ["identities" .= listIdentities]

instance FromJSON ListIdentitiesResponse where
    parseJSON = Aeson.withObject "ListIdentitiesResponse" \o ->
        ListIdentitiesResponse <$> o Aeson..: "identities"

data GenerateLinkRequest = GenerateLinkRequest
    { generateLinkEmail :: Email
    , generateLinkType :: Text
    }
    deriving stock (Eq, Generic, Show)

instance FromJSON GenerateLinkRequest where
    parseJSON = Aeson.withObject "GenerateLinkRequest" \o ->
        GenerateLinkRequest
            <$> o Aeson..: "email"
            <*> o Aeson..: "type"

instance ToJSON GenerateLinkRequest where
    toJSON GenerateLinkRequest{generateLinkEmail, generateLinkType} =
        object
            [ "email" .= generateLinkEmail
            , "type" .= generateLinkType
            ]

newtype GenerateLinkResponse = GenerateLinkResponse
    { generateLinkActionLink :: Text
    }
    deriving stock (Eq, Generic, Show)

instance FromJSON GenerateLinkResponse where
    parseJSON = Aeson.withObject "GenerateLinkResponse" \o ->
        GenerateLinkResponse <$> o Aeson..: "action_link"

instance ToJSON GenerateLinkResponse where
    toJSON GenerateLinkResponse{generateLinkActionLink} =
        object ["action_link" .= generateLinkActionLink]

data InviteUserRequest = InviteUserRequest
    { inviteUserEmail :: Email
    , inviteUserData :: Maybe Value
    -- ^ Optional metadata to attach to the invited user.
    }
    deriving stock (Eq, Generic, Show)

instance FromJSON InviteUserRequest where
    parseJSON = Aeson.withObject "InviteUserRequest" \o ->
        InviteUserRequest
            <$> o Aeson..: "email"
            <*> o Aeson..:? "data"

instance ToJSON InviteUserRequest where
    toJSON InviteUserRequest{inviteUserEmail, inviteUserData} =
        object
            [ "email" .= inviteUserEmail
            , "data" .= inviteUserData
            ]

newtype ProvidersResponse = ProvidersResponse
    { providers :: [Text]
    }
    deriving stock (Eq, Generic, Show)

instance FromJSON ProvidersResponse where
    parseJSON = Aeson.withObject "ProvidersResponse" \o ->
        ProvidersResponse <$> o Aeson..: "providers"

instance ToJSON ProvidersResponse where
    toJSON ProvidersResponse{providers} =
        object ["providers" .= providers]

newtype UpdateProvidersRequest = UpdateProvidersRequest
    { updateProviders :: [Text]
    }
    deriving stock (Eq, Generic, Show)

instance FromJSON UpdateProvidersRequest where
    parseJSON = Aeson.withObject "UpdateProvidersRequest" \o ->
        UpdateProvidersRequest <$> o Aeson..: "providers"

instance ToJSON UpdateProvidersRequest where
    toJSON UpdateProvidersRequest{updateProviders} =
        object ["providers" .= updateProviders]
