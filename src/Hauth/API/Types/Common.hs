{- | Shared wire-shape building blocks reused across multiple API surfaces.

These types are imported transitively by every other @Hauth.API.Types.*@
sub-module. Keep this module small and free of surface-specific shapes.
-}
module Hauth.API.Types.Common (
    Email (..),
    Password (..),
    UserId (..),
    MessageResponse (..),
    UserResponse (..),
    buildUserResponse,
) where

import Data.Aeson (FromJSON (..), ToJSON (toJSON), Value, object, (.=))
import qualified Data.Aeson as Aeson
import Data.Text (Text)
import Data.Time (UTCTime)
import Data.UUID (UUID)
import GHC.Generics (Generic)
import qualified Hauth.User as User
import Web.HttpApiData (FromHttpApiData, ToHttpApiData)

newtype UserId = UserId {unUserId :: Text}
    deriving stock (Eq, Generic, Ord, Show)
    deriving newtype (FromHttpApiData, FromJSON, ToHttpApiData, ToJSON)

newtype Email = Email {unEmail :: Text}
    deriving stock (Eq, Generic, Ord, Show)
    deriving newtype (FromJSON, ToJSON, FromHttpApiData, ToHttpApiData)

newtype Password = Password {unPassword :: Text}
    deriving stock (Eq, Generic, Show)
    deriving newtype (FromJSON, ToJSON)

newtype MessageResponse = MessageResponse
    { message :: Text
    }
    deriving stock (Eq, Generic, Show)

instance ToJSON MessageResponse where
    toJSON MessageResponse{message} =
        object ["message" .= message]

instance FromJSON MessageResponse where
    parseJSON = Aeson.withObject "MessageResponse" \o ->
        MessageResponse <$> o Aeson..: "message"

{- | Full user object matching the Supabase @/user@ response contract.

The JSON serialisation uses snake_case keys to match the Supabase wire format.
-}
data UserResponse = UserResponse
    { userResponseId :: UUID
    , userResponseAud :: Text
    , userResponseRole :: Text
    , userResponseEmail :: Maybe Text
    , userResponseEmailConfirmedAt :: Maybe UTCTime
    , userResponseCreatedAt :: UTCTime
    , userResponseUpdatedAt :: UTCTime
    , userResponseAppMetadata :: Value
    , userResponseUserMetadata :: Value
    }
    deriving stock (Eq, Generic, Show)

instance ToJSON UserResponse where
    toJSON UserResponse{..} =
        object
            [ "id" .= userResponseId
            , "aud" .= userResponseAud
            , "role" .= userResponseRole
            , "email" .= userResponseEmail
            , "email_confirmed_at" .= userResponseEmailConfirmedAt
            , "created_at" .= userResponseCreatedAt
            , "updated_at" .= userResponseUpdatedAt
            , "app_metadata" .= userResponseAppMetadata
            , "user_metadata" .= userResponseUserMetadata
            ]

instance FromJSON UserResponse where
    parseJSON = Aeson.withObject "UserResponse" \obj ->
        UserResponse
            <$> obj Aeson..: "id"
            <*> obj Aeson..: "aud"
            <*> obj Aeson..: "role"
            <*> obj Aeson..:? "email"
            <*> obj Aeson..:? "email_confirmed_at"
            <*> obj Aeson..: "created_at"
            <*> obj Aeson..: "updated_at"
            <*> obj Aeson..: "app_metadata"
            <*> obj Aeson..: "user_metadata"

buildUserResponse :: User.User -> UserResponse
buildUserResponse User.User{..} =
    UserResponse
        { userResponseId = User.unUserId userId
        , userResponseAud = userAud
        , userResponseRole = userRole
        , userResponseEmail = userEmail
        , userResponseEmailConfirmedAt = userEmailConfirmedAt
        , userResponseCreatedAt = userCreatedAt
        , userResponseUpdatedAt = userUpdatedAt
        , userResponseAppMetadata = userRawAppMetaData
        , userResponseUserMetadata = userRawUserMetaData
        }
