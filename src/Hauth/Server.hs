{- | HTTP entrypoint: Warp bootstrap, Servant API stitching, and the auth
context wiring.

Per-endpoint handler logic lives in the domain-specific siblings:

* "Hauth.Server.Health"   — @/healthz@ and @/healthz/deep@
* "Hauth.Server.Auth"     — public auth endpoints (signup, token, recover, verify, resend, settings)
* "Hauth.Server.Session"  — @/user@ session-scoped endpoints (get, update, logout)
* "Hauth.Server.Admin", "Hauth.Server.Mfa", "Hauth.Server.OAuth",
  "Hauth.Server.Hooks", "Hauth.Server.EmailTemplates",
  "Hauth.Server.WebhookSubscriptions", "Hauth.Server.WebhookDeliveries"

This module is composition only. Re-exports 'aggregateStatus' and 'isUnhealthy'
from "Hauth.Server.Health" because "Spec.ServerSpec" imports them from here.
-}
module Hauth.Server (
    aggregateStatus,
    app,
    isUnhealthy,
    runServer,
    server,
) where

import Control.Exception (bracket)
import Control.Monad.Except (throwError)
import Control.Monad.IO.Class (liftIO)
import Control.Monad.Reader (ReaderT, runReaderT)
import qualified Data.ByteString.Lazy.Char8 as BSLC
import Data.Proxy (Proxy (Proxy))
import Data.String (fromString)
import qualified Data.Text as T
import Hauth.API
import Hauth.API.Auth
import Hauth.Auth.Jwt (AccessTokenClaims (..), validateAccessToken)
import Hauth.Config (Config (..), ServerConfig (..))
import Hauth.Env (
    AppEnv (..),
    LogLevel (..),
    createAppEnv,
    destroyAppEnv,
    logMessage,
    startBackgroundServices,
    stopBackgroundServices,
 )
import Hauth.Server.Admin (
    adminCreateUserHandler,
    adminDeleteUserHandler,
    adminGetUserHandler,
    adminInviteUserHandler,
    adminListIdentitiesHandler,
    adminListUsersHandler,
    adminUpdateUserHandler,
 )
import Hauth.Server.Auth (
    recoverHandler,
    resendHandler,
    settingsHandler,
    signupHandler,
    tokenHandler,
    verifyHandler,
 )
import Hauth.Server.EmailTemplates (
    deleteEmailTemplateHandler,
    getEmailTemplateHandler,
    listEmailTemplatesHandler,
    putEmailTemplateHandler,
 )
import Hauth.Server.Errors (supabaseErrorBody)
import Hauth.Server.Health (aggregateStatus, deepHealthHandler, healthHandler, isUnhealthy)
import Hauth.Server.Hooks (
    createHookHandler,
    deleteHookHandler,
    getHookHandler,
    listHooksHandler,
    updateHookHandler,
 )
import Hauth.Server.Mfa (
    challengeFactorHandler,
    enrollFactorHandler,
    listFactorsHandler,
    verifyFactorHandler,
 )
import Hauth.Server.OAuth (authorizeHandler, callbackHandler)
import Hauth.Server.Session (getUserHandler, logoutHandler, updateUserHandler)
import Hauth.Server.WebhookDeliveries (
    getDeliveryHandler,
    listDeliveriesBySubscriptionHandler,
    retryDeliveryHandler,
 )
import Hauth.Server.WebhookSubscriptions (
    createWebhookSubscriptionHandler,
    deleteWebhookSubscriptionHandler,
    getWebhookSubscriptionHandler,
    listWebhookSubscriptionsHandler,
    updateWebhookSubscriptionHandler,
 )
import Network.Wai (Application, Request, requestHeaders)
import qualified Network.Wai.Handler.Warp as Warp
import Servant.API (NoContent (..), type (:<|>) ((:<|>)))
import Servant.Server (
    Context (EmptyContext, (:.)),
    Handler,
    ServerError (errBody),
    ServerT,
    err401,
    err501,
    hoistServerWithContext,
    serveWithContext,
 )
import Servant.Server.Experimental.Auth (AuthHandler, mkAuthHandler)

type AppHandler = ReaderT AppEnv Handler

type AuthContext =
    '[ AuthHandler Request AnonymousPrincipal
     , AuthHandler Request SessionPrincipal
     , AuthHandler Request ServiceRolePrincipal
     ]

runServer :: Config -> IO ()
runServer config =
    bracket (createAppEnv config) destroyAppEnv \env@AppEnv{appConfig, appLogger} ->
        bracket (startBackgroundServices env) stopBackgroundServices \_ -> do
            let Config{configServer = ServerConfig{serverHost, serverPort}} = appConfig
            logMessage appLogger LogInfo ("hauth listening on http://" <> serverHost <> ":" <> T.pack (show serverPort))
            Warp.runSettings
                ( Warp.setHost (fromString (T.unpack serverHost)) $
                    Warp.setPort serverPort Warp.defaultSettings
                )
                (app env)

app :: AppEnv -> Application
app env =
    serveWithContext
        hauthAPI
        (authContext env)
        ( hoistServerWithContext
            hauthAPI
            (Proxy :: Proxy AuthContext)
            (runAppHandler env)
            server
        )

runAppHandler :: AppEnv -> AppHandler a -> Handler a
runAppHandler env handler =
    runReaderT handler env

-- ---------------------------------------------------------------------------
-- API stitching
-- ---------------------------------------------------------------------------

server :: ServerT HauthAPI AppHandler
server =
    operatorServer
        :<|> publicAuthServer
        :<|> sessionServer
        :<|> mfaServer
        :<|> adminServer

operatorServer :: ServerT OperatorAPI AppHandler
operatorServer =
    healthHandler
        :<|> deepHealthHandler

publicAuthServer :: ServerT PublicAuthAPI AppHandler
publicAuthServer =
    settingsHandler
        :<|> signupHandler
        :<|> tokenHandler
        :<|> recoverHandler
        :<|> verifyHandler
        :<|> resendHandler
        :<|> authorizeHandler
        :<|> callbackHandler

sessionServer :: ServerT SessionAPI AppHandler
sessionServer =
    getUserHandler
        :<|> updateUserHandler
        :<|> logoutHandler

mfaServer :: ServerT MfaAPI AppHandler
mfaServer =
    listFactorsHandler
        :<|> enrollFactorHandler
        :<|> challengeFactorHandler
        :<|> verifyFactorHandler
        :<|> notImplemented2

adminServer :: ServerT AdminAPI AppHandler
adminServer =
    adminUsersServer
        :<|> adminConfigServer
        :<|> adminWebhookServer
        :<|> adminEmailTemplateServer
        :<|> adminWebhookSubscriptionsServer
        :<|> adminHooksServer
        :<|> adminWebhookDeliveriesServer

adminUsersServer :: ServerT AdminUsersAPI AppHandler
adminUsersServer =
    adminListUsersHandler
        :<|> adminCreateUserHandler
        :<|> adminGetUserHandler
        :<|> adminUpdateUserHandler
        :<|> adminDeleteUserHandler
        :<|> adminListIdentitiesHandler
        :<|> notImplemented3
        :<|> notImplemented2
        :<|> adminInviteUserHandler

adminConfigServer :: ServerT AdminConfigAPI AppHandler
adminConfigServer =
    notImplemented1
        :<|> notImplemented2
        :<|> notImplemented1
        :<|> notImplemented2

adminWebhookServer :: ServerT AdminWebhookAPI AppHandler
adminWebhookServer =
    notImplemented2
        :<|> notImplemented2
        :<|> notImplemented2

adminEmailTemplateServer :: ServerT AdminEmailTemplateAPI AppHandler
adminEmailTemplateServer =
    listEmailTemplatesHandler
        :<|> getEmailTemplateHandler
        :<|> putEmailTemplateHandler
        :<|> deleteAndNoContent
  where
    deleteAndNoContent p name = deleteEmailTemplateHandler p name >> pure NoContent

adminWebhookSubscriptionsServer :: ServerT AdminWebhookSubscriptionsAPI AppHandler
adminWebhookSubscriptionsServer =
    createWebhookSubscriptionHandler
        :<|> listWebhookSubscriptionsHandler
        :<|> getWebhookSubscriptionHandler
        :<|> updateWebhookSubscriptionHandler
        :<|> deleteWebhookSubscriptionHandler

adminHooksServer :: ServerT AdminHooksAPI AppHandler
adminHooksServer =
    createHookHandler
        :<|> listHooksHandler
        :<|> getHookHandler
        :<|> updateHookHandler
        :<|> deleteHookHandler

adminWebhookDeliveriesServer :: ServerT AdminWebhookDeliveriesAPI AppHandler
adminWebhookDeliveriesServer =
    listDeliveriesBySubscriptionHandler
        :<|> getDeliveryHandler
        :<|> retryDeliveryHandler

-- ---------------------------------------------------------------------------
-- Servant auth context
-- ---------------------------------------------------------------------------

authContext :: AppEnv -> Context AuthContext
authContext env =
    anonymousAuth
        :. validSessionAuth env
        :. serviceRoleAuth env
        :. EmptyContext

anonymousAuth :: AuthHandler Request AnonymousPrincipal
anonymousAuth =
    mkAuthHandler \_request ->
        pure AnonymousPrincipal

validSessionAuth :: AppEnv -> AuthHandler Request SessionPrincipal
validSessionAuth env =
    mkAuthHandler \request -> do
        let AppEnv{appConfig} = env
            Config{configJwt} = appConfig
        token <- case extractBearerToken (requestHeaders request) of
            Left msg -> throwError err401{errBody = BSLC.pack (T.unpack msg)}
            Right t -> pure t
        result <- liftIO (validateAccessToken configJwt token)
        case result of
            Left err ->
                throwError
                    err401
                        { errBody = supabaseErrorBody "no_authorization" (T.pack (show err))
                        }
            Right claims ->
                pure
                    SessionPrincipal
                        { sessionUserId = claimSub claims
                        , sessionRole = claimRole claims
                        , sessionAccessTokenId = claimSessionId claims
                        }

serviceRoleAuth :: AppEnv -> AuthHandler Request ServiceRolePrincipal
serviceRoleAuth env =
    mkAuthHandler \request -> do
        let AppEnv{appConfig} = env
            Config{configJwt} = appConfig
        token <- case extractBearerToken (requestHeaders request) of
            Left msg -> throwError err401{errBody = BSLC.pack (T.unpack msg)}
            Right t -> pure t
        result <- liftIO (validateAccessToken configJwt token)
        case checkServiceRole result of
            Left msg -> throwError err401{errBody = BSLC.pack (T.unpack msg)}
            Right principal -> pure principal

-- ---------------------------------------------------------------------------
-- Stub handlers for not-yet-implemented endpoints
-- ---------------------------------------------------------------------------

notImplemented :: AppHandler a
notImplemented =
    throwError err501{errBody = supabaseErrorBody "not_implemented" "Not implemented"}

notImplemented1 :: a -> AppHandler b
notImplemented1 _ =
    notImplemented

notImplemented2 :: a -> b -> AppHandler c
notImplemented2 _ _ =
    notImplemented

notImplemented3 :: a -> b -> c -> AppHandler d
notImplemented3 _ _ _ =
    notImplemented
