-- | Wire types for the @\/settings@ endpoint.
module Hauth.API.Types.Settings (
    SettingsResponse (..),
    buildSettingsResponse,
) where

import Data.Aeson (ToJSON (toJSON), object, (.=))
import Data.Map.Strict (Map)
import qualified Data.Map.Strict as Map
import Data.Text (Text)
import qualified Data.Text as T
import Hauth.Config (Config (..), OAuthConfig (..), OAuthProviderConfig (..))

data SettingsResponse = SettingsResponse
    { settingsExternal :: Map Text Bool
    , settingsExternalEmailEnabled :: Bool
    , settingsExternalPhoneEnabled :: Bool
    , settingsDisableSignup :: Bool
    , settingsMailerAutoconfirm :: Bool
    , settingsPhoneAutoconfirm :: Bool
    , settingsSmsProvider :: Text
    }
    deriving stock (Eq, Show)

instance ToJSON SettingsResponse where
    toJSON SettingsResponse{..} =
        object
            [ "external" .= settingsExternal
            , "external_email_enabled" .= settingsExternalEmailEnabled
            , "external_phone_enabled" .= settingsExternalPhoneEnabled
            , "disable_signup" .= settingsDisableSignup
            , "mailer_autoconfirm" .= settingsMailerAutoconfirm
            , "phone_autoconfirm" .= settingsPhoneAutoconfirm
            , "sms_provider" .= settingsSmsProvider
            ]

buildSettingsResponse :: Config -> SettingsResponse
buildSettingsResponse Config{configOAuth = OAuthConfig{oauthProviders}} =
    SettingsResponse
        { settingsExternal = externalMap
        , settingsExternalEmailEnabled = True
        , settingsExternalPhoneEnabled = False
        , settingsDisableSignup = False
        , settingsMailerAutoconfirm = False
        , settingsPhoneAutoconfirm = False
        , settingsSmsProvider = ""
        }
  where
    providerEntries =
        fmap
            (\OAuthProviderConfig{oauthProviderName} -> (T.toLower oauthProviderName, True))
            oauthProviders
    externalMap =
        Map.fromList $
            [("email", True), ("phone", False)]
                <> providerEntries
