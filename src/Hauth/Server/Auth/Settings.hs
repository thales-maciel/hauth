-- | Public @\/settings@ endpoint handler.
module Hauth.Server.Auth.Settings (
    settingsHandler,
) where

import Control.Monad.Reader (asks)
import Hauth.API.Auth (AnonymousPrincipal)
import Hauth.API.Types
import Hauth.Env (AppEnv (..))
import Hauth.Server.Auth.Session (AppHandler)

settingsHandler :: AnonymousPrincipal -> AppHandler SettingsResponse
settingsHandler _ =
    asks (buildSettingsResponse . appConfig)
