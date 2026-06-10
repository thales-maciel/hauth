{- | HTTP handlers for the operator-facing admin UI.

Pure page builders live in "Hauth.AdminUI"; this module is the
'AppHandler'-typed wiring served via Servant. Until #206 lands, the route
is anonymous-gated so the build is exercisable end-to-end without a login
flow.
-}
module Hauth.Server.AdminUI (
    adminUIPlaceholderHandler,
) where

import Control.Monad.Reader (ReaderT)
import Hauth.API.Auth (AnonymousPrincipal)
import Hauth.AdminUI (placeholderPage)
import Hauth.Env (AppEnv)
import Servant.Server (Handler)
import Text.Blaze.Html5 (Html)

adminUIPlaceholderHandler :: AnonymousPrincipal -> ReaderT AppEnv Handler Html
adminUIPlaceholderHandler _ = pure placeholderPage
