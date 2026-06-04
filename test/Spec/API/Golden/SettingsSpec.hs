-- | Wire-shape coverage for the @\/settings@ endpoint.
module Spec.API.Golden.SettingsSpec (spec) where

import qualified Data.Map.Strict as Map
import Data.Text (Text)
import Hauth.API.Types
import Spec.API.Golden.Helpers (encodeShape)
import Test.Hspec (Spec, describe, it)

spec :: Spec
spec = describe "Settings" $ do
    it "SettingsResponse" $
        encodeShape
            "SettingsResponse"
            SettingsResponse
                { settingsExternal = Map.fromList [("email" :: Text, True), ("phone", False)]
                , settingsExternalEmailEnabled = True
                , settingsExternalPhoneEnabled = False
                , settingsDisableSignup = False
                , settingsMailerAutoconfirm = False
                , settingsPhoneAutoconfirm = False
                , settingsSmsProvider = ""
                }
            "{\"external\":{\"email\":true,\"phone\":false}\
            \,\"external_email_enabled\":true,\"external_phone_enabled\":false\
            \,\"disable_signup\":false,\"mailer_autoconfirm\":false\
            \,\"phone_autoconfirm\":false,\"sms_provider\":\"\"}"
