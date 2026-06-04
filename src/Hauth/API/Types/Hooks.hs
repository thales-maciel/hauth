-- | Wire types for the admin sync-hooks surface.
module Hauth.API.Types.Hooks (
    HookId (..),
    HookRow (..),
    CreateHookRequest (..),
    UpdateHookRequest (..),
    ListHooksResponse (..),
) where

import Data.Aeson (FromJSON (..), ToJSON (toJSON), object, withObject, (.=))
import qualified Data.Aeson as Aeson
import Data.Text (Text)
import qualified Data.Text as T
import Data.UUID (UUID)
import qualified Data.UUID as UUID
import GHC.Generics (Generic)
import Hauth.Hooks.Types (HookPoint, hookPointName, parseHookPoint)
import Web.HttpApiData (FromHttpApiData, ToHttpApiData)

newtype HookId = HookId {unHookId :: Text}
    deriving stock (Eq, Generic, Ord, Show)
    deriving newtype (FromHttpApiData, FromJSON, ToHttpApiData, ToJSON)

data HookRow = HookRow
    { hookRowId :: UUID
    , hookRowPoint :: HookPoint
    , hookRowUrl :: Text
    , hookRowSecret :: Text
    , hookRowTimeoutMs :: Int
    , hookRowFailOpen :: Bool
    , hookRowEnabled :: Bool
    }
    deriving stock (Eq, Show)

instance ToJSON HookRow where
    toJSON HookRow{..} =
        object
            [ "id" .= UUID.toText hookRowId
            , "hook_point" .= hookPointName hookRowPoint
            , "url" .= hookRowUrl
            , "secret" .= hookRowSecret
            , "timeout_ms" .= hookRowTimeoutMs
            , "fail_open" .= hookRowFailOpen
            , "enabled" .= hookRowEnabled
            ]

instance FromJSON HookRow where
    parseJSON = withObject "HookRow" \o -> do
        idText <- o Aeson..: "id"
        hpText <- o Aeson..: "hook_point"
        hp <- case parseHookPoint hpText of
            Nothing -> fail ("unknown hook_point: " <> T.unpack hpText)
            Just p -> pure p
        HookRow
            <$> (case UUID.fromText idText of Nothing -> fail "bad uuid"; Just u -> pure u)
            <*> pure hp
            <*> o Aeson..: "url"
            <*> o Aeson..: "secret"
            <*> o Aeson..: "timeout_ms"
            <*> o Aeson..: "fail_open"
            <*> o Aeson..: "enabled"

data CreateHookRequest = CreateHookRequest
    { createHookPoint :: Text
    , createHookUrl :: Text
    , createHookSecret :: Maybe Text
    , createHookTimeoutMs :: Maybe Int
    , createHookFailOpen :: Maybe Bool
    , createHookEnabled :: Maybe Bool
    }
    deriving stock (Eq, Show)

instance FromJSON CreateHookRequest where
    parseJSON = withObject "CreateHookRequest" \o ->
        CreateHookRequest
            <$> o Aeson..: "hook_point"
            <*> o Aeson..: "url"
            <*> o Aeson..:? "secret"
            <*> o Aeson..:? "timeout_ms"
            <*> o Aeson..:? "fail_open"
            <*> o Aeson..:? "enabled"

data UpdateHookRequest = UpdateHookRequest
    { updateHookUrl :: Maybe Text
    , updateHookSecret :: Maybe Text
    , updateHookTimeoutMs :: Maybe Int
    , updateHookFailOpen :: Maybe Bool
    , updateHookEnabled :: Maybe Bool
    }
    deriving stock (Eq, Show)

instance FromJSON UpdateHookRequest where
    parseJSON = withObject "UpdateHookRequest" \o ->
        UpdateHookRequest
            <$> o Aeson..:? "url"
            <*> o Aeson..:? "secret"
            <*> o Aeson..:? "timeout_ms"
            <*> o Aeson..:? "fail_open"
            <*> o Aeson..:? "enabled"

newtype ListHooksResponse = ListHooksResponse {listHookRows :: [HookRow]}
    deriving stock (Eq, Show)

instance ToJSON ListHooksResponse where
    toJSON ListHooksResponse{listHookRows} =
        object ["hooks" .= listHookRows]
