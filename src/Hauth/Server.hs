module Hauth.Server (
    app,
    runServer,
    server,
) where

import Control.Exception (bracket)
import Control.Monad.Except (throwError)
import Control.Monad.Reader (ReaderT, ask, runReaderT)
import qualified Data.ByteString as BS
import Data.Proxy (Proxy (Proxy))
import Data.String (fromString)
import qualified Data.Text as T
import Hauth.API
import Hauth.API.Auth
import Hauth.API.Types
import Hauth.Config (Config (..), ServerConfig (..))
import Hauth.Env (AppEnv (..), LogLevel (..), createAppEnv, destroyAppEnv, logMessage)
import Network.Wai (Application, Request, requestHeaders)
import qualified Network.Wai.Handler.Warp as Warp
import Servant.API (type (:<|>) ((:<|>)))
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
    bracket (createAppEnv config) destroyAppEnv \env@AppEnv{appConfig, appLogger} -> do
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
        authContext
        ( hoistServerWithContext
            hauthAPI
            (Proxy :: Proxy AuthContext)
            (runAppHandler env)
            server
        )

runAppHandler :: AppEnv -> AppHandler a -> Handler a
runAppHandler env handler =
    runReaderT handler env

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
    notImplemented1
        :<|> notImplemented2
        :<|> notImplemented3
        :<|> notImplemented2
        :<|> notImplemented2
        :<|> notImplemented2
        :<|> notImplemented3
        :<|> notImplemented3

sessionServer :: ServerT SessionAPI AppHandler
sessionServer =
    notImplemented1
        :<|> notImplemented2
        :<|> notImplemented2

mfaServer :: ServerT MfaAPI AppHandler
mfaServer =
    notImplemented1
        :<|> notImplemented2
        :<|> notImplemented3
        :<|> notImplemented3
        :<|> notImplemented2

adminServer :: ServerT AdminAPI AppHandler
adminServer =
    adminUsersServer
        :<|> adminConfigServer
        :<|> adminWebhookServer

adminUsersServer :: ServerT AdminUsersAPI AppHandler
adminUsersServer =
    notImplemented3
        :<|> notImplemented2
        :<|> notImplemented2
        :<|> notImplemented3
        :<|> notImplemented2
        :<|> notImplemented2
        :<|> notImplemented3
        :<|> notImplemented2
        :<|> notImplemented2

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

healthHandler :: AnonymousPrincipal -> AppHandler HealthResponse
healthHandler _ = do
    _env <- ask
    pure HealthResponse{healthStatus = "ok"}

deepHealthHandler :: AnonymousPrincipal -> AppHandler DeepHealthResponse
deepHealthHandler _ = do
    _env <- ask
    pure
        DeepHealthResponse
            { deepHealthStatus = "ok"
            , deepHealthChecks = ["process", "config", "postgres-pool"]
            }

notImplemented :: AppHandler a
notImplemented =
    throwError err501{errBody = "Not implemented"}

notImplemented1 :: a -> AppHandler b
notImplemented1 _ =
    notImplemented

notImplemented2 :: a -> b -> AppHandler c
notImplemented2 _ _ =
    notImplemented

notImplemented3 :: a -> b -> c -> AppHandler d
notImplemented3 _ _ _ =
    notImplemented

authContext ::
    Context AuthContext
authContext =
    anonymousAuth
        :. validSessionAuth
        :. serviceRoleAuth
        :. EmptyContext

anonymousAuth :: AuthHandler Request AnonymousPrincipal
anonymousAuth =
    mkAuthHandler \_request ->
        pure AnonymousPrincipal

validSessionAuth :: AuthHandler Request SessionPrincipal
validSessionAuth =
    mkAuthHandler \request -> do
        requireAuthorization request
        pure
            SessionPrincipal
                { sessionUserId = "authenticated-user"
                , sessionRole = "authenticated"
                , sessionAccessTokenId = "authorization-header"
                }

serviceRoleAuth :: AuthHandler Request ServiceRolePrincipal
serviceRoleAuth =
    mkAuthHandler \request -> do
        requireAuthorization request
        pure ServiceRolePrincipal{serviceRoleName = "service_role"}

requireAuthorization :: Request -> Handler ()
requireAuthorization request =
    case lookup "Authorization" (requestHeaders request) of
        Just value
            | not (BS.null value) -> pure ()
        _ ->
            throwError err401{errBody = "Missing Authorization header"}
