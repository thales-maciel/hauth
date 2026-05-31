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
import qualified Data.Aeson.KeyMap as KeyMap
import qualified Data.ByteString as BS
import qualified Data.ByteString.Lazy as BSL
import qualified Data.ByteString.Lazy.Char8 as BSLC
import Data.Maybe (fromMaybe)
import Data.Proxy (Proxy (Proxy))
import Data.String (fromString)
import Data.Text (Text)
import qualified Data.Text as T
import Data.Time.Clock (addUTCTime, getCurrentTime)
import Data.Time.Clock.POSIX (posixSecondsToUTCTime, utcTimeToPOSIXSeconds)
import Data.UUID (UUID)
import qualified Data.UUID as UUID
import Database.PostgreSQL.Simple (Connection, Only (..), execute_, query, withTransaction)
import GHC.Clock (getMonotonicTimeNSec)
import Hauth.API
import Hauth.API.Auth
import Hauth.API.Types
import Hauth.Auth.Jwt (AccessTokenClaims (..), AmrEntry (..), signAccessToken, validateAccessToken)
import Hauth.Auth.Logout (LogoutError (..), resolveLogoutSession)
import Hauth.Config (Config (..), DatabaseConfig (..), JwtConfig (..), ServerConfig (..))
import Hauth.Crypto.Password (defaultArgon2Settings, hashPassword)
import Hauth.Env (AppEnv (..), LogLevel (..), createAppEnv, destroyAppEnv, logMessage, withDatabaseConnection)
import Hauth.Session (
    RefreshToken (..),
    SessionId (..),
    createRefreshToken,
    lookupRefreshTokenRaw,
    revokeRefreshToken,
    revokeSession,
    revokeSessionRefreshTokens,
    touchSessionRefreshedAt,
 )
import Hauth.User (SignupError (..), generateConfirmationToken, validateSignupEmail, validateSignupPassword)
import qualified Hauth.User as User
import Network.Wai (Application, Request, requestHeaders)
import qualified Network.Wai.Handler.Warp as Warp
import Servant.API (NoContent (..), type (:<|>) ((:<|>)))
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
        :<|> tokenHandler
        :<|> notImplemented2
        :<|> notImplemented2
        :<|> notImplemented2
        :<|> notImplemented3
        :<|> notImplemented3

sessionServer :: ServerT SessionAPI AppHandler
sessionServer =
    notImplemented1
        :<|> notImplemented2
        :<|> logoutHandler

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

-- ---------------------------------------------------------------------------
-- Token endpoint
-- ---------------------------------------------------------------------------

{- | Handler for @POST /token?grant_type=<grant>@.

Dispatches on @grant_type@:

- @refresh_token@: rotates the supplied refresh token and returns a new
  access token + refresh token.  Implements full reuse detection: if a
  previously-rotated (revoked) token is replayed, the entire session is
  terminated.

- @password@: placeholder — returns 400 @unsupported_grant_type@ until
  issue #12 lands.

- Anything else: 400 @unsupported_grant_type@.
-}
tokenHandler :: AnonymousPrincipal -> Text -> TokenRequest -> AppHandler TokenResponse
tokenHandler _ grantType req =
    case parseGrantType (Just grantType) of
        GrantRefreshToken ->
            handleRefreshTokenGrant req
        GrantPassword ->
            throwError
                err400
                    { errBody =
                        Aeson.encode $
                            Aeson.object
                                [ "error" Aeson..= ("unsupported_grant_type" :: T.Text)
                                , "error_description" Aeson..= ("password grant not yet implemented" :: T.Text)
                                ]
                    }
        GrantUnsupported _ ->
            throwError
                err400
                    { errBody =
                        Aeson.encode $
                            Aeson.object
                                ["error" Aeson..= ("unsupported_grant_type" :: T.Text)]
                    }

handleRefreshTokenGrant :: TokenRequest -> AppHandler TokenResponse
handleRefreshTokenGrant TokenRequest{tokenRequestRefreshToken} = do
    tokenText <- case tokenRequestRefreshToken of
        Nothing ->
            throwError
                err400
                    { errBody =
                        Aeson.encode $
                            Aeson.object
                                [ "error" Aeson..= ("invalid_request" :: T.Text)
                                , "error_description" Aeson..= ("refresh_token is required" :: T.Text)
                                ]
                    }
        Just t -> pure t
    env <- ask
    let AppEnv{appConfig} = env
        Config{configJwt} = appConfig
        JwtConfig{jwtAccessTokenTtlSeconds} = configJwt
    -- Look up the token including revoked rows so we can detect reuse.
    mRawToken <- liftIO (withDatabaseConnection env (`lookupRefreshTokenRaw` tokenText))
    case classifyRefreshTokenLookup mRawToken of
        Left InvalidGrant ->
            throwError
                err401
                    { errBody =
                        Aeson.encode $
                            Aeson.object
                                [ "error" Aeson..= ("invalid_grant" :: T.Text)
                                , "error_description" Aeson..= ("Invalid Refresh Token" :: T.Text)
                                ]
                    }
        Left RefreshTokenReuseDetected -> do
            -- Token was already rotated. Revoke the whole family + session.
            let sid = refreshTokenSessionId (fromMaybeRawToken mRawToken)
            liftIO $ withDatabaseConnection env \conn -> do
                _ <- revokeSessionRefreshTokens conn sid
                revokeSession conn sid
            throwError
                err401
                    { errBody =
                        Aeson.encode $
                            Aeson.object
                                [ "error" Aeson..= ("invalid_grant" :: T.Text)
                                , "error_description" Aeson..= ("Invalid Refresh Token: reuse detected" :: T.Text)
                                ]
                    }
        Right (ValidRefreshToken rt) -> do
            now <- liftIO getCurrentTime
            let sid = refreshTokenSessionId rt
                uid = refreshTokenUserId rt
                ttl = fromIntegral jwtAccessTokenTtlSeconds
                expiry = addUTCTime ttl now
                iatSecs = floor (utcTimeToPOSIXSeconds now) :: Integer
            -- Look up minimal user data.
            mUserVal <- liftIO (withDatabaseConnection env (`fetchMinimalUser` uid))
            userVal <- case mUserVal of
                Nothing ->
                    throwError
                        err401
                            { errBody =
                                Aeson.encode $
                                    Aeson.object
                                        [ "error" Aeson..= ("invalid_grant" :: T.Text)
                                        , "error_description" Aeson..= ("user not found" :: T.Text)
                                        ]
                            }
                Just v -> pure v
            let (userEmail', userRole') = extractEmailRole userVal
                claims =
                    AccessTokenClaims
                        { claimSub = UUID.toText uid
                        , claimRole = userRole'
                        , claimEmail = userEmail'
                        , claimPhone = Nothing
                        , claimAppMetadata = Aeson.object []
                        , claimUserMetadata = Aeson.object []
                        , claimAal = "aal1"
                        , claimAmr =
                            [ AmrEntry
                                { amrMethod = "token_refresh"
                                , amrTimestamp = iatSecs
                                }
                            ]
                        , claimSessionId = UUID.toText (unSessionId sid)
                        , claimIssuedAt = now
                        , claimExpiresAt = expiry
                        }
            -- Perform rotation in one connection: revoke old, mint new, touch session.
            newToken <- liftIO $ withDatabaseConnection env \conn -> do
                revokeRefreshToken conn (refreshTokenId rt)
                newRt <- createRefreshToken conn sid (Just tokenText)
                touchSessionRefreshedAt conn sid
                pure newRt
            signResult <- liftIO (signAccessToken configJwt claims)
            accessToken <- case signResult of
                Left err ->
                    throwError
                        err401
                            { errBody =
                                Aeson.encode $
                                    Aeson.object
                                        [ "error" Aeson..= ("server_error" :: T.Text)
                                        , "error_description" Aeson..= T.pack (show err)
                                        ]
                            }
                Right t -> pure t
            pure
                TokenResponse
                    { tokenResponseAccessToken = accessToken
                    , tokenResponseTokenType = "bearer"
                    , tokenResponseExpiresIn = jwtAccessTokenTtlSeconds
                    , tokenResponseRefreshToken = refreshTokenToken newToken
                    , tokenResponseUser = userVal
                    }
  where
    -- Safe: called only in the ReuseDetected branch where mRawToken is Just.
    fromMaybeRawToken (Just rt) = rt
    fromMaybeRawToken Nothing = error "fromMaybeRawToken: impossible"

{- | Fetch a minimal user JSON value for embedding in 'TokenResponse'.

Queries @auth.users@ for the columns needed by the Supabase token response.
Returns a JSON @Value@ so the handler can embed it without introducing a
dedicated @User@ module dependency.

TODO: Replace with @Hauth.User.getUserById@ once that module is available
(tracked in issue #11).
-}
fetchMinimalUser :: Connection -> UUID -> IO (Maybe Aeson.Value)
fetchMinimalUser conn uid = do
    rows <-
        query
            conn
            "SELECT id::text, email, aud, role \
            \FROM auth.users \
            \WHERE id = ?"
            (Only uid)
    pure $ case rows of
        [(idText, email, aud, role) :: (T.Text, Maybe T.Text, T.Text, T.Text)] ->
            Just $
                Aeson.object
                    [ "id" Aeson..= idText
                    , "aud" Aeson..= aud
                    , "role" Aeson..= role
                    , "email" Aeson..= email
                    ]
        _ -> Nothing

-- | Extract @email@ and @role@ fields from the minimal user JSON object.
extractEmailRole :: Aeson.Value -> (Maybe T.Text, T.Text)
extractEmailRole (Aeson.Object obj) =
    let email = case KeyMap.lookup "email" obj of
            Just (Aeson.String e) -> Just e
            _ -> Nothing
        role = case KeyMap.lookup "role" obj of
            Just (Aeson.String r) -> r
            _ -> "authenticated"
     in (email, role)
extractEmailRole _ = (Nothing, "authenticated")

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
                        { errBody =
                            Aeson.encode
                                ( Aeson.object
                                    [ "code" Aeson..= ("no_authorization" :: T.Text)
                                    , "msg" Aeson..= T.pack (show err)
                                    ]
                                )
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

{- | Handle @POST /logout@.

Validates the Bearer JWT carried in the @Authorization@ header (already
checked by 'validSessionAuth'), extracts the @session_id@ claim, and
revokes the corresponding session row via 'revokeSession'.  Associated
refresh tokens are removed automatically by the @ON DELETE CASCADE@
constraint on @auth.refresh_tokens.session_id@.

The optional @scope@ query parameter is accepted but ignored for v0.1
(only the "local" scope — revoke the current session — is supported).
-}
logoutHandler ::
    SessionPrincipal ->
    Maybe T.Text ->
    AppHandler NoContent
logoutHandler principal _scope = do
    env <- ask
    -- sessionAccessTokenId carries the claimSessionId text set by
    -- validSessionAuth; parse it directly as a UUID.
    let sidText = sessionAccessTokenId principal
        dummyClaims =
            AccessTokenClaims
                { claimSub = sessionUserId principal
                , claimRole = sessionRole principal
                , claimEmail = Nothing
                , claimPhone = Nothing
                , claimAppMetadata = Aeson.object []
                , claimUserMetadata = Aeson.object []
                , claimAal = "aal1"
                , claimAmr = []
                , claimSessionId = sidText
                , claimIssuedAt = posixSecondsToUTCTime 0
                , claimExpiresAt = posixSecondsToUTCTime 0
                }
    sid <- case resolveLogoutSession (Right dummyClaims) of
        Left (LogoutBadSessionId msg) ->
            throwError
                err401
                    { errBody =
                        Aeson.encode
                            ( Aeson.object
                                [ "code" Aeson..= ("invalid_session_id" :: T.Text)
                                , "msg" Aeson..= msg
                                ]
                            )
                    }
        Left other ->
            throwError
                err401
                    { errBody =
                        Aeson.encode
                            ( Aeson.object
                                [ "code" Aeson..= ("no_authorization" :: T.Text)
                                , "msg" Aeson..= T.pack (show other)
                                ]
                            )
                    }
        Right s -> pure s
    liftIO (withDatabaseConnection env (`revokeSession` sid))
    pure NoContent
