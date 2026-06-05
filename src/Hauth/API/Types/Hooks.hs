-- | Wire types for the admin sync-hooks surface.
module Hauth.API.Types.Hooks (
    HookId (..),
    HookRow (..),
    HookCreateResponse (..),
    RotateHookSecretRequest (..),
    RotateHookSecretResponse (..),
    CreateHookRequest (..),
    UpdateHookRequest (..),
    ListHooksResponse (..),
    toCreateResponse,
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

{- | Stored hook row. On read (GET/list) responses, the secret field is always
serialised as the redaction sentinel @"***redacted***"@ — the real value is
retained in the record for internal use (signing).
-}
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

-- | Sentinel emitted in place of the real secret on read/list responses.
redactedSecret :: Text
redactedSecret = "***redacted***"

instance ToJSON HookRow where
    toJSON HookRow{..} =
        object
            [ "id" .= UUID.toText hookRowId
            , "hook_point" .= hookPointName hookRowPoint
            , "url" .= hookRowUrl
            , "secret" .= redactedSecret
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

{- | Response type for the create endpoint. Identical shape to 'HookRow' but
serialises the real plaintext secret so operators can configure receivers.
After this one-time response the secret is no longer readable via the API.
-}
data HookCreateResponse = HookCreateResponse
    { hookCreateId :: UUID
    , hookCreatePoint :: HookPoint
    , hookCreateUrl :: Text
    , hookCreateSecret :: Text
    , hookCreateTimeoutMs :: Int
    , hookCreateFailOpen :: Bool
    , hookCreateEnabled :: Bool
    }
    deriving stock (Eq, Show)

instance ToJSON HookCreateResponse where
    toJSON HookCreateResponse{..} =
        object
            [ "id" .= UUID.toText hookCreateId
            , "hook_point" .= hookPointName hookCreatePoint
            , "url" .= hookCreateUrl
            , "secret" .= hookCreateSecret
            , "timeout_ms" .= hookCreateTimeoutMs
            , "fail_open" .= hookCreateFailOpen
            , "enabled" .= hookCreateEnabled
            ]

instance FromJSON HookCreateResponse where
    parseJSON = withObject "HookCreateResponse" \o -> do
        idText <- o Aeson..: "id"
        hpText <- o Aeson..: "hook_point"
        hp <- case parseHookPoint hpText of
            Nothing -> fail ("unknown hook_point: " <> T.unpack hpText)
            Just p -> pure p
        HookCreateResponse
            <$> (case UUID.fromText idText of Nothing -> fail "bad uuid"; Just u -> pure u)
            <*> pure hp
            <*> o Aeson..: "url"
            <*> o Aeson..: "secret"
            <*> o Aeson..: "timeout_ms"
            <*> o Aeson..: "fail_open"
            <*> o Aeson..: "enabled"

{- | Convert an internal 'HookRow' to a 'HookCreateResponse', revealing the
real secret exactly once.
-}
toCreateResponse :: HookRow -> HookCreateResponse
toCreateResponse HookRow{..} =
    HookCreateResponse
        { hookCreateId = hookRowId
        , hookCreatePoint = hookRowPoint
        , hookCreateUrl = hookRowUrl
        , hookCreateSecret = hookRowSecret
        , hookCreateTimeoutMs = hookRowTimeoutMs
        , hookCreateFailOpen = hookRowFailOpen
        , hookCreateEnabled = hookRowEnabled
        }

{- | Optional request body for @POST /admin/hooks\/:id\/rotate-secret@.
If @rotateHookSecret@ is absent the server generates a fresh secret.
-}
newtype RotateHookSecretRequest = RotateHookSecretRequest
    { rotateHookSecret :: Maybe Text
    }
    deriving stock (Eq, Show)

instance FromJSON RotateHookSecretRequest where
    parseJSON = withObject "RotateHookSecretRequest" \o ->
        RotateHookSecretRequest
            <$> o Aeson..:? "secret"

-- | Response for the rotate endpoint: returns the new plaintext secret once.
newtype RotateHookSecretResponse = RotateHookSecretResponse
    { rotateHookNewSecret :: Text
    }
    deriving stock (Eq, Show)

instance ToJSON RotateHookSecretResponse where
    toJSON RotateHookSecretResponse{rotateHookNewSecret} =
        object ["secret" .= rotateHookNewSecret]

instance FromJSON RotateHookSecretResponse where
    parseJSON = withObject "RotateHookSecretResponse" \o ->
        RotateHookSecretResponse <$> o Aeson..: "secret"

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

{- | PUT body. The @secret@ field is intentionally absent — updating other
fields does not rotate the secret. Use @POST \/:id\/rotate-secret@ instead.
-}
data UpdateHookRequest = UpdateHookRequest
    { updateHookUrl :: Maybe Text
    , updateHookTimeoutMs :: Maybe Int
    , updateHookFailOpen :: Maybe Bool
    , updateHookEnabled :: Maybe Bool
    }
    deriving stock (Eq, Show)

instance FromJSON UpdateHookRequest where
    parseJSON = withObject "UpdateHookRequest" \o ->
        UpdateHookRequest
            <$> o Aeson..:? "url"
            <*> o Aeson..:? "timeout_ms"
            <*> o Aeson..:? "fail_open"
            <*> o Aeson..:? "enabled"

newtype ListHooksResponse = ListHooksResponse {listHookRows :: [HookRow]}
    deriving stock (Eq, Show)

instance ToJSON ListHooksResponse where
    toJSON ListHooksResponse{listHookRows} =
        object ["hooks" .= listHookRows]
