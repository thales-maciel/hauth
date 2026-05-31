module Hauth.Server (
    aggregateStatus,
    app,
    isUnhealthy,
    runServer,
    server,
) where

import Control.Exception (SomeException, bracket, try)
import Control.Monad (when)
import Control.Monad.Except (throwError)
import Control.Monad.IO.Class (liftIO)
import Control.Monad.Reader (ReaderT, ask, asks, runReaderT)
import qualified Data.Aeson as Aeson
import qualified Data.ByteString as BS
import qualified Data.ByteString.Lazy as BSL
import qualified Data.ByteString.Lazy.Char8 as BSLC
import Data.Maybe (fromMaybe)
import Data.Proxy (Proxy (Proxy))
import Data.String (fromString)
import qualified Data.Text as T
import Database.PostgreSQL.Simple (execute_, withTransaction)
import GHC.Clock (getMonotonicTimeNSec)
import Hauth.API
import Hauth.API.Auth
import Hauth.API.Types
import Hauth.Auth.Jwt (validateAccessToken)
import Hauth.Config (Config (..), DatabaseConfig (..), JwtConfig (..), ServerConfig (..))
import Hauth.Crypto.Password (defaultArgon2Settings, hashPassword)
import Hauth.Env (AppEnv (..), LogLevel (..), createAppEnv, destroyAppEnv, logMessage, withDatabaseConnection)
import Hauth.User (SignupError (..), generateConfirmationToken, validateSignupEmail, validateSignupPassword)
import qualified Hauth.User as User
import Network.Wai (Application, Request, requestHeaders)
import qualified Network.Wai.Handler.Warp as Warp
import Servant.API (type (:<|>) ((:<|>)))
import Servant.Server (
    Context (EmptyContext, (:.)),
    Handler,
    ServerError (errBody),
    ServerT,
    err400,
    err401,
    err422,
    err501,
    err503,
    hoistServerWithContext,
    serveWithContext,
 )
import Servant.Server.Experimental.Auth (AuthHandler, mkAuthHandler)
import System.Timeout (timeout)

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
healthHandler _ =
    pure HealthResponse{healthStatus = "ok"}

deepHealthHandler :: AnonymousPrincipal -> AppHandler DeepHealthResponse
deepHealthHandler _ = do
    env <- ask
    checks <- liftIO (runDeepChecks env)
    let response =
            DeepHealthResponse
                { deepHealthStatus = aggregateStatus (fmap deepHealthCheckOutcome checks)
                , deepHealthChecks = checks
                }
    when (isUnhealthy response) $
        throwError err503{errBody = Aeson.encode response}
    pure response

aggregateStatus :: [CheckOutcome] -> T.Text
aggregateStatus outcomes =
    if any isFailed outcomes
        then "unhealthy"
        else "ok"
  where
    isFailed (CheckFailed _) = True
    isFailed CheckOk = False

isUnhealthy :: DeepHealthResponse -> Bool
isUnhealthy DeepHealthResponse{deepHealthStatus} =
    deepHealthStatus /= "ok"

runDeepChecks :: AppEnv -> IO [DeepHealthCheck]
runDeepChecks env = do
    processCheck <- checkProcess
    configCheck <- checkConfig env
    postgresCheck <- checkPostgres env
    pure [processCheck, configCheck, postgresCheck]

checkProcess :: IO DeepHealthCheck
checkProcess =
    pure
        DeepHealthCheck
            { deepHealthCheckName = "process"
            , deepHealthCheckOutcome = CheckOk
            , deepHealthCheckLatencyMs = Nothing
            }

checkConfig :: AppEnv -> IO DeepHealthCheck
checkConfig AppEnv{appConfig} =
    let Config{configDatabase = DatabaseConfig{databaseUrl}, configJwt = JwtConfig{jwtSecret}} = appConfig
        outcome =
            if T.null databaseUrl || T.null jwtSecret
                then CheckFailed "config fields are empty"
                else CheckOk
     in pure
            DeepHealthCheck
                { deepHealthCheckName = "config"
                , deepHealthCheckOutcome = outcome
                , deepHealthCheckLatencyMs = Nothing
                }

checkPostgres :: AppEnv -> IO DeepHealthCheck
checkPostgres env = do
    startNs <- getMonotonicTimeNSec
    result <- try (timeout 2000000 (withDatabaseConnection env (`execute_` "SELECT 1")))
    endNs <- getMonotonicTimeNSec
    let latencyMs = Just (fromIntegral ((endNs - startNs) `div` 1000000))
    let outcome = case result of
            Left (err :: SomeException) ->
                CheckFailed (T.pack (show err))
            Right Nothing ->
                CheckFailed "postgres check timed out"
            Right (Just _) ->
                CheckOk
    pure
        DeepHealthCheck
            { deepHealthCheckName = "postgres"
            , deepHealthCheckOutcome = outcome
            , deepHealthCheckLatencyMs = latencyMs
            }

settingsHandler :: AnonymousPrincipal -> AppHandler SettingsResponse
settingsHandler _ =
    asks (buildSettingsResponse . appConfig)

signupHandler :: AnonymousPrincipal -> SignupRequest -> AppHandler SignupResponse
signupHandler _ SignupRequest{signupEmail, signupPassword, signupData} = do
    env <- ask
    let emailText = unEmail signupEmail
        passwordText = unPassword signupPassword
    validatedEmail <- case validateSignupEmail emailText of
        Left _ ->
            throwError
                err400
                    { errBody = signupErrorBody "invalid_email" "Email address is invalid"
                    }
        Right e -> pure e
    validatedPassword <- case validateSignupPassword passwordText of
        Left (SignupPasswordTooShort minLen _) ->
            throwError
                err422
                    { errBody =
                        signupErrorBody
                            "weak_password"
                            ("Password must be at least " <> T.pack (show minLen) <> " characters")
                    }
        Left _ ->
            throwError
                err422{errBody = signupErrorBody "weak_password" "Password is too weak"}
        Right p -> pure p
    user <- liftIO $
        withDatabaseConnection env \conn ->
            withTransaction conn do
                existing <- User.getUserByEmail conn validatedEmail
                case existing of
                    Just _ ->
                        pure (Left SignupEmailExists)
                    Nothing -> do
                        encrypted <- hashPassword defaultArgon2Settings validatedPassword
                        token <- generateConfirmationToken
                        let metadata = fromMaybe (Aeson.object []) signupData
                            newUser =
                                User.NewUser
                                    { User.newUserEmail = validatedEmail
                                    , User.newUserEncryptedPassword = encrypted
                                    , User.newUserConfirmationToken = Just token
                                    , User.newUserUserMetadata = metadata
                                    , User.newUserAud = "authenticated"
                                    }
                        created <- User.createUser conn newUser
                        pure (Right created)
    case user of
        Left SignupEmailExists ->
            throwError
                err422
                    { errBody = signupErrorBody "email_exists" "Email address already in use"
                    }
        Left _ ->
            throwError
                err400{errBody = signupErrorBody "signup_failed" "Signup failed"}
        Right created ->
            pure (buildSignupResponse created)

signupErrorBody :: T.Text -> T.Text -> BSL.ByteString
signupErrorBody code msg =
    Aeson.encode $
        Aeson.object
            [ "code" Aeson..= code
            , "msg" Aeson..= msg
            ]

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
    AppEnv -> Context AuthContext
authContext env =
    anonymousAuth
        :. validSessionAuth
        :. serviceRoleAuth env
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

requireAuthorization :: Request -> Handler ()
requireAuthorization request =
    case lookup "Authorization" (requestHeaders request) of
        Just value
            | not (BS.null value) -> pure ()
        _ ->
            throwError err401{errBody = "Missing Authorization header"}
