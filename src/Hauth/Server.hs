module Hauth.Server (
    app,
    runServer,
    server,
) where

import Control.Monad.Except (throwError)
import qualified Data.ByteString as BS
import Data.String (fromString)
import qualified Data.Text as T
import Hauth.API
import Hauth.API.Auth
import Hauth.API.Types
import Hauth.Config (Config (..), ServerConfig (..))
import Network.Wai (Application, Request, requestHeaders)
import qualified Network.Wai.Handler.Warp as Warp
import Servant.API (type (:<|>) ((:<|>)))
import Servant.Server (
    Context (EmptyContext, (:.)),
    Handler,
    Server,
    ServerError (errBody),
    err401,
    err501,
    serveWithContext,
 )
import Servant.Server.Experimental.Auth (AuthHandler, mkAuthHandler)

runServer :: Config -> IO ()
runServer Config{configServer = ServerConfig{serverHost, serverPort}} = do
    putStrLn ("hauth listening on http://" <> T.unpack serverHost <> ":" <> show serverPort)
    Warp.runSettings
        ( Warp.setHost (fromString (T.unpack serverHost)) $
            Warp.setPort serverPort Warp.defaultSettings
        )
        app

app :: Application
app =
    serveWithContext hauthAPI authContext server

server :: Server HauthAPI
server =
    operatorServer
        :<|> publicAuthServer
        :<|> sessionServer
        :<|> mfaServer
        :<|> adminServer

operatorServer :: Server OperatorAPI
operatorServer =
    healthHandler
        :<|> deepHealthHandler

publicAuthServer :: Server PublicAuthAPI
publicAuthServer =
    notImplemented1
        :<|> notImplemented2
        :<|> notImplemented3
        :<|> notImplemented2
        :<|> notImplemented2
        :<|> notImplemented2
        :<|> notImplemented3
        :<|> notImplemented3

sessionServer :: Server SessionAPI
sessionServer =
    notImplemented1
        :<|> notImplemented2
        :<|> notImplemented2

mfaServer :: Server MfaAPI
mfaServer =
    notImplemented1
        :<|> notImplemented2
        :<|> notImplemented3
        :<|> notImplemented3
        :<|> notImplemented2

adminServer :: Server AdminAPI
adminServer =
    adminUsersServer
        :<|> adminConfigServer
        :<|> adminWebhookServer

adminUsersServer :: Server AdminUsersAPI
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

adminConfigServer :: Server AdminConfigAPI
adminConfigServer =
    notImplemented1
        :<|> notImplemented2
        :<|> notImplemented1
        :<|> notImplemented2

adminWebhookServer :: Server AdminWebhookAPI
adminWebhookServer =
    notImplemented2
        :<|> notImplemented2
        :<|> notImplemented2

healthHandler :: AnonymousPrincipal -> Handler HealthResponse
healthHandler _ =
    pure HealthResponse{healthStatus = "ok"}

deepHealthHandler :: AnonymousPrincipal -> Handler DeepHealthResponse
deepHealthHandler _ =
    pure
        DeepHealthResponse
            { deepHealthStatus = "ok"
            , deepHealthChecks = ["process"]
            }

notImplemented :: Handler a
notImplemented =
    throwError err501{errBody = "Not implemented"}

notImplemented1 :: a -> Handler b
notImplemented1 _ =
    notImplemented

notImplemented2 :: a -> b -> Handler c
notImplemented2 _ _ =
    notImplemented

notImplemented3 :: a -> b -> c -> Handler d
notImplemented3 _ _ _ =
    notImplemented

authContext ::
    Context
        '[ AuthHandler Request AnonymousPrincipal
         , AuthHandler Request SessionPrincipal
         , AuthHandler Request ServiceRolePrincipal
         ]
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
