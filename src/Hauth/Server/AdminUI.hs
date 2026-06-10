{- | HTTP handlers for the operator-facing admin UI.

Pure page builders live in "Hauth.AdminUI"; this module is the
'AppHandler'-typed wiring served via Servant. Pages require an admin UI
session cookie (validated in "Hauth.Server"'s auth context); login and
logout follow post-redirect-get with 303 responses.
-}
module Hauth.Server.AdminUI (
    adminUIHomeHandler,
    adminUILoginPageHandler,
    adminUILoginSubmitHandler,
    adminUILogoutHandler,
) where

import Control.Exception (evaluate)
import Control.Monad.IO.Class (liftIO)
import Control.Monad.Reader (ReaderT, ask)
import Data.List (find)
import Data.Maybe (isJust)
import Data.Text (Text)
import Hauth.API (AdminUIRedirect)
import Hauth.API.Auth (AdminUIPrincipal (..), AnonymousPrincipal)
import Hauth.API.Types (AdminLoginForm (..))
import Hauth.AdminUI (homePage, loginPage)
import Hauth.AdminUI.Session (
    buildSessionCookie,
    clearSessionCookie,
    createAdminUISession,
    deleteAdminUISession,
    deleteExpiredAdminUISessions,
    hashSessionToken,
    newSessionToken,
 )
import Hauth.Config (AdminUIConfig (..), AdminUICredential (..), Config (..))
import Hauth.Crypto.Password (verifyPassword)
import Hauth.Env (AppEnv (..), withDatabaseConnection)
import Servant.API.ResponseHeaders (addHeader, noHeader)
import Servant.Server (Handler)
import Text.Blaze.Html5 (Html)

adminUIHomeHandler :: AdminUIPrincipal -> ReaderT AppEnv Handler Html
adminUIHomeHandler AdminUIPrincipal{adminPrincipalUsername} =
    pure (homePage adminPrincipalUsername)

adminUILoginPageHandler :: AnonymousPrincipal -> Maybe Text -> ReaderT AppEnv Handler Html
adminUILoginPageHandler _ mError =
    pure (loginPage (isJust mError))

adminUILoginSubmitHandler :: AnonymousPrincipal -> AdminLoginForm -> ReaderT AppEnv Handler AdminUIRedirect
adminUILoginSubmitHandler _ AdminLoginForm{loginFormUsername, loginFormPassword} = do
    env <- ask
    let AdminUIConfig{adminUICredentials, adminUISessionTtlSeconds} =
            configAdminUI (appConfig env)
        mCredential =
            find ((== loginFormUsername) . adminUIUsername) adminUICredentials
    -- Unknown usernames still pay one argon2id verification so response
    -- timing does not reveal which usernames are configured; 'evaluate' in
    -- IO keeps the decoy work opaque to the optimizer.
    accepted <- case mCredential of
        Just AdminUICredential{adminUIPasswordHash} ->
            pure (verifyPassword adminUIPasswordHash loginFormPassword)
        Nothing -> do
            _ <- liftIO (evaluate (verifyPassword decoyPasswordHash loginFormPassword))
            pure False
    if accepted
        then do
            token <- liftIO newSessionToken
            liftIO $ withDatabaseConnection env \conn -> do
                deleteExpiredAdminUISessions conn
                createAdminUISession conn (hashSessionToken token) loginFormUsername adminUISessionTtlSeconds
            pure
                ( addHeader "/admin/ui" $
                    addHeader (buildSessionCookie token adminUISessionTtlSeconds) mempty
                )
        else
            pure (addHeader "/admin/ui/login?error=1" (noHeader mempty))

adminUILogoutHandler :: AdminUIPrincipal -> ReaderT AppEnv Handler AdminUIRedirect
adminUILogoutHandler AdminUIPrincipal{adminPrincipalTokenHash} = do
    env <- ask
    liftIO $ withDatabaseConnection env (`deleteAdminUISession` adminPrincipalTokenHash)
    pure (addHeader "/admin/ui/login" (addHeader clearSessionCookie mempty))

-- | Timing-equalisation decoy; the unknown-username branch is hardwired to reject.
decoyPasswordHash :: Text
decoyPasswordHash =
    "$argon2id$v=19$m=65536,t=3,p=4$AAAAAAAAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
