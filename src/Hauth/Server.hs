module Hauth.Server (
    aggregateStatus,
    app,
    isUnhealthy,
    runServer,
    server,
) where

import Control.Exception (SomeException, bracket, try)
import Control.Monad (unless, when)
import Control.Monad.Except (throwError)
import Control.Monad.IO.Class (liftIO)
import Control.Monad.Reader (ReaderT, ask, asks, runReaderT)
import qualified Data.Aeson as Aeson
import qualified Data.Aeson.KeyMap as KeyMap
import qualified Data.ByteString.Lazy as BSL
import qualified Data.ByteString.Lazy.Char8 as BSLC
import Data.Maybe (fromMaybe, isJust)
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
import Hauth.Auth.Login (LoginError (..), authorizeLogin, buildLoginClaims, extractCredentials)
import Hauth.Auth.Logout (LogoutError (..), resolveLogoutSession)
import Hauth.Auth.Recovery (RecoveryError (..), recoverySentMessage, validateRecoverRequest, validateRecoveryVerify)
import Hauth.Auth.UserUpdate (UpdateUserError (..), validateUpdateRequest)
import Hauth.Auth.Verify (OtpType (..), VerifyError (..), classifyVerifyRequest, parseOtpType)
import Hauth.Config (Config (..), DatabaseConfig (..), EmailConfig (..), JwtConfig (..), ServerConfig (..), SiteConfig (..))
import Hauth.Crypto.Password (defaultArgon2Settings, hashPassword)
import qualified Hauth.Crypto.Password as Pwd
import Hauth.Email (EmailSender (..), TemplateData (..), TemplateKind (..), renderEmail, sendEmail, stubSender)
import Hauth.Env (AppEnv (..), LogLevel (..), createAppEnv, destroyAppEnv, logMessage, withDatabaseConnection)
import Hauth.Mfa.Totp (encodeBase32, generateTotpSecret, otpAuthUri, unTotpSecret)
import qualified Hauth.MfaFactor as MfaFactor
import Hauth.Server.Admin (
    adminCreateUserHandler,
    adminDeleteUserHandler,
    adminGetUserHandler,
    adminInviteUserHandler,
    adminListIdentitiesHandler,
    adminListUsersHandler,
    adminUpdateUserHandler,
 )
import Hauth.Server.OAuth (authorizeHandler, callbackHandler)
import Hauth.Session (
    NewSession (..),
    RefreshToken (..),
    Session (sessionId),
    SessionId (..),
    createRefreshToken,
    createSession,
    generateOpaqueToken,
    lookupRefreshTokenRaw,
    revokeRefreshToken,
    revokeSession,
    revokeSessionRefreshTokens,
    sessionId,
    touchSessionRefreshedAt,
 )
import Hauth.User (
    SignupError (..),
    generateConfirmationToken,
    validateSignupEmail,
    validateSignupPassword,
 )
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
    err404,
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

tokenHandler :: AnonymousPrincipal -> Text -> TokenRequest -> AppHandler TokenResponse
tokenHandler _ grantType req =
    case parseGrantType (Just grantType) of
        GrantRefreshToken ->
            handleRefreshTokenGrant req
        GrantPassword ->
            handlePasswordGrant req
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
    fromMaybeRawToken (Just rt) = rt
    fromMaybeRawToken Nothing = error "fromMaybeRawToken: impossible"

handlePasswordGrant :: TokenRequest -> AppHandler TokenResponse
handlePasswordGrant req = do
    (emailText, passwordText) <- case extractCredentials req of
        Left LoginMissingFields ->
            throwError
                err400
                    { errBody =
                        Aeson.encode $
                            Aeson.object
                                [ "error" Aeson..= ("invalid_request" :: T.Text)
                                , "error_description" Aeson..= ("email and password are required" :: T.Text)
                                ]
                    }
        Left err ->
            throwError
                err400
                    { errBody =
                        Aeson.encode $
                            Aeson.object
                                ["error" Aeson..= T.pack (show err)]
                    }
        Right creds -> pure creds
    env <- ask
    let AppEnv{appConfig} = env
        Config{configJwt} = appConfig
        JwtConfig{jwtAccessTokenTtlSeconds} = configJwt
    mUser <- liftIO (withDatabaseConnection env (`User.getUserByEmail` emailText))
    user <- case mUser of
        Nothing -> throwError invalidGrantError
        Just u -> pure u
    let verified = case User.userEncryptedPassword user of
            Nothing -> False
            Just phc -> Pwd.verifyPassword phc passwordText
    case authorizeLogin verified (User.userEmailConfirmedAt user) of
        Left LoginInvalidGrant -> throwError invalidGrantError
        Left LoginEmailNotConfirmed ->
            throwError
                err400
                    { errBody =
                        Aeson.encode $
                            Aeson.object
                                [ "error" Aeson..= ("email_not_confirmed" :: T.Text)
                                , "msg" Aeson..= ("Email not confirmed" :: T.Text)
                                ]
                    }
        Left LoginMissingFields ->
            throwError invalidGrantError
        Right () -> pure ()
    let User.UserId userUUID = User.userId user
        newSess =
            NewSession
                { newSessionUserId = userUUID
                , newSessionAal = "aal1"
                , newSessionFactorId = Nothing
                , newSessionUserAgent = Nothing
                , newSessionIp = Nothing
                , newSessionNotAfter = Nothing
                }
    (sess, refreshTok) <- liftIO $
        withDatabaseConnection env \conn -> do
            s <- createSession conn newSess
            rt <- createRefreshToken conn (sessionId s) Nothing
            pure (s, rt)
    now <- liftIO getCurrentTime
    let claims = buildLoginClaims configJwt user (sessionId sess) now
    signResult <- liftIO (signAccessToken configJwt claims)
    accessToken <- case signResult of
        Left err ->
            throwError
                err400
                    { errBody =
                        Aeson.encode $
                            Aeson.object
                                [ "error" Aeson..= ("server_error" :: T.Text)
                                , "error_description" Aeson..= T.pack (show err)
                                ]
                    }
        Right t -> pure t
    let userVal =
            Aeson.object
                [ "id" Aeson..= UUID.toText userUUID
                , "aud" Aeson..= User.userAud user
                , "role" Aeson..= User.userRole user
                , "email" Aeson..= User.userEmail user
                ]
    pure
        TokenResponse
            { tokenResponseAccessToken = accessToken
            , tokenResponseTokenType = "bearer"
            , tokenResponseExpiresIn = jwtAccessTokenTtlSeconds
            , tokenResponseRefreshToken = refreshTokenToken refreshTok
            , tokenResponseUser = userVal
            }
  where
    invalidGrantError :: ServerError
    invalidGrantError =
        err400
            { errBody =
                Aeson.encode $
                    Aeson.object
                        [ "error" Aeson..= ("invalid_grant" :: T.Text)
                        , "error_description" Aeson..= ("Invalid login credentials" :: T.Text)
                        ]
            }

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

-- ---------------------------------------------------------------------------
-- Recover endpoint
-- ---------------------------------------------------------------------------

recoverHandler :: AnonymousPrincipal -> RecoverRequest -> AppHandler MessageResponse
recoverHandler _ req = do
    env <- ask
    let AppEnv{appConfig, appLogger} = env
        Config{configEmail, configSite = SiteConfig{siteUrl}} = appConfig
        EmailConfig{emailFrom} = configEmail
    emailText <- case validateRecoverRequest req of
        Left _ ->
            pure ""
        Right e -> pure e
    unless (T.null emailText) $ do
        mUser <- liftIO (withDatabaseConnection env (`User.getUserByEmail` emailText))
        case mUser of
            Nothing -> pure ()
            Just user ->
                case User.userEncryptedPassword user of
                    Nothing -> pure ()
                    Just _ -> do
                        token <- liftIO generateOpaqueToken
                        liftIO $ withDatabaseConnection env \conn ->
                            User.setRecoveryToken conn (User.userId user) token
                        let actionUrl = siteUrl <> "/auth/v1/verify?token=" <> token <> "&type=recovery"
                            tdata =
                                TemplateData
                                    { templateRecipientEmail = emailText
                                    , templateActionUrl = actionUrl
                                    , templateSiteUrl = siteUrl
                                    , templateTokenHash = token
                                    }
                        case renderEmail Recovery emailFrom tdata of
                            Left err ->
                                liftIO $
                                    logMessage appLogger LogWarn $
                                        "recoverHandler: renderEmail failed: " <> T.pack (show err)
                            Right msg -> do
                                result <- liftIO (sendEmail stubSender msg)
                                case result of
                                    Left err ->
                                        liftIO $
                                            logMessage appLogger LogWarn $
                                                "recoverHandler: email send failed: " <> T.pack (show err)
                                    Right () -> pure ()
    pure MessageResponse{message = recoverySentMessage}

-- ---------------------------------------------------------------------------
-- Verify endpoint
-- ---------------------------------------------------------------------------

verifyHandler :: AnonymousPrincipal -> VerifyRequest -> AppHandler SessionResponse
verifyHandler _ req =
    case classifyVerifyRequest req of
        Left VerifyMissingToken ->
            throwError
                err400
                    { errBody =
                        Aeson.encode $
                            Aeson.object
                                [ "error" Aeson..= ("otp_expired" :: T.Text)
                                , "msg" Aeson..= ("Token has expired or is invalid" :: T.Text)
                                ]
                    }
        Left (VerifyUnsupportedOtpType t) ->
            throwError
                err400
                    { errBody =
                        Aeson.encode $
                            Aeson.object
                                [ "error" Aeson..= ("unsupported_otp_type" :: T.Text)
                                , "msg" Aeson..= ("Unsupported OTP type: " <> t)
                                ]
                    }
        Left VerifyOtpExpired ->
            throwError
                err401
                    { errBody =
                        Aeson.encode $
                            Aeson.object
                                [ "error" Aeson..= ("otp_expired" :: T.Text)
                                , "msg" Aeson..= ("Token has expired or is invalid" :: T.Text)
                                ]
                    }
        Right OtpSignup ->
            handleSignupVerify req
        Right OtpRecovery ->
            handleRecoveryVerify req
        Right _ ->
            throwError
                err400
                    { errBody =
                        Aeson.encode $
                            Aeson.object
                                [ "error" Aeson..= ("unsupported_otp_type" :: T.Text)
                                , "msg" Aeson..= ("OTP type not yet implemented" :: T.Text)
                                ]
                    }

handleSignupVerify :: VerifyRequest -> AppHandler SessionResponse
handleSignupVerify VerifyRequest{verifyToken} = do
    env <- ask
    mUser <- liftIO (withDatabaseConnection env (`User.getUserByConfirmationToken` verifyToken))
    user <- case mUser of
        Nothing ->
            throwError
                err401
                    { errBody =
                        Aeson.encode $
                            Aeson.object
                                [ "error" Aeson..= ("otp_expired" :: T.Text)
                                , "msg" Aeson..= ("Token has expired or is invalid" :: T.Text)
                                ]
                    }
        Just u -> pure u
    liftIO (withDatabaseConnection env (`User.markEmailConfirmed` User.userId user))
    issueSessionForUser user "otp"

handleRecoveryVerify :: VerifyRequest -> AppHandler SessionResponse
handleRecoveryVerify req = do
    (token, password) <- case validateRecoveryVerify req of
        Left RecoveryMissingToken ->
            throwError
                err401
                    { errBody =
                        Aeson.encode $
                            Aeson.object
                                [ "error" Aeson..= ("otp_expired" :: T.Text)
                                , "error_description" Aeson..= ("Token is missing" :: T.Text)
                                ]
                    }
        Left (RecoveryPasswordTooShort minLen _) ->
            throwError
                err422
                    { errBody =
                        Aeson.encode $
                            Aeson.object
                                [ "error" Aeson..= ("weak_password" :: T.Text)
                                , "error_description" Aeson..= ("Password must be at least " <> T.pack (show minLen) <> " characters" :: T.Text)
                                ]
                    }
        Left RecoveryMissingEmail ->
            throwError
                err400
                    { errBody =
                        Aeson.encode $
                            Aeson.object
                                [ "error" Aeson..= ("invalid_request" :: T.Text)
                                , "error_description" Aeson..= ("Invalid request" :: T.Text)
                                ]
                    }
        Right pair -> pure pair
    env <- ask
    mUser <- liftIO (withDatabaseConnection env (`User.getUserByRecoveryToken` token))
    user <- case mUser of
        Nothing ->
            throwError
                err401
                    { errBody =
                        Aeson.encode $
                            Aeson.object
                                [ "error" Aeson..= ("otp_expired" :: T.Text)
                                , "error_description" Aeson..= ("Token has expired or is invalid" :: T.Text)
                                ]
                    }
        Just u -> pure u
    phc <- liftIO (hashPassword defaultArgon2Settings password)
    liftIO $ withDatabaseConnection env \conn ->
        User.applyPasswordReset conn (User.userId user) phc
    issueSessionForUser user "recovery"

issueSessionForUser :: User.User -> T.Text -> AppHandler SessionResponse
issueSessionForUser user methodName = do
    env <- ask
    let AppEnv{appConfig} = env
        Config{configJwt} = appConfig
        JwtConfig{jwtAccessTokenTtlSeconds} = configJwt
    now <- liftIO getCurrentTime
    let uid = User.unUserId (User.userId user)
        ttl = fromIntegral jwtAccessTokenTtlSeconds
        expiry = addUTCTime ttl now
        iatSecs = floor (utcTimeToPOSIXSeconds now) :: Integer
        newSess =
            NewSession
                { newSessionUserId = uid
                , newSessionAal = "aal1"
                , newSessionFactorId = Nothing
                , newSessionUserAgent = Nothing
                , newSessionIp = Nothing
                , newSessionNotAfter = Nothing
                }
    session <- liftIO (withDatabaseConnection env (`createSession` newSess))
    let sid = sessionId session
    refreshTok <- liftIO (withDatabaseConnection env (\conn -> createRefreshToken conn sid Nothing))
    let claims =
            AccessTokenClaims
                { claimSub = UUID.toText uid
                , claimRole = User.userRole user
                , claimEmail = User.userEmail user
                , claimPhone = Nothing
                , claimAppMetadata = User.userRawAppMetaData user
                , claimUserMetadata = User.userRawUserMetaData user
                , claimAal = "aal1"
                , claimAmr =
                    [ AmrEntry
                        { amrMethod = methodName
                        , amrTimestamp = iatSecs
                        }
                    ]
                , claimSessionId = UUID.toText (unSessionId sid)
                , claimIssuedAt = now
                , claimExpiresAt = expiry
                }
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
        SessionResponse
            { sessionAccessToken = accessToken
            , sessionExpiresIn = jwtAccessTokenTtlSeconds
            , sessionRefreshToken = refreshTokenToken refreshTok
            , sessionUser = buildUserResponse user
            }

-- ---------------------------------------------------------------------------
-- Resend endpoint
-- ---------------------------------------------------------------------------

resendHandler :: AnonymousPrincipal -> ResendRequest -> AppHandler MessageResponse
resendHandler _ ResendRequest{resendEmail, resendType} =
    case parseOtpType resendType of
        Left (VerifyUnsupportedOtpType t) ->
            throwError
                err400
                    { errBody =
                        Aeson.encode $
                            Aeson.object
                                [ "error" Aeson..= ("unsupported_otp_type" :: T.Text)
                                , "msg" Aeson..= ("Unsupported OTP type: " <> t)
                                ]
                    }
        Left _ ->
            throwError
                err400
                    { errBody =
                        Aeson.encode $
                            Aeson.object
                                [ "error" Aeson..= ("unsupported_otp_type" :: T.Text)
                                ]
                    }
        Right OtpSignup ->
            handleSignupResend (unEmail resendEmail)
        Right _ ->
            throwError
                err400
                    { errBody =
                        Aeson.encode $
                            Aeson.object
                                [ "error" Aeson..= ("unsupported_otp_type" :: T.Text)
                                , "msg" Aeson..= ("OTP type not yet implemented" :: T.Text)
                                ]
                    }

handleSignupResend :: T.Text -> AppHandler MessageResponse
handleSignupResend emailText = do
    env <- ask
    let AppEnv{appConfig, appLogger} = env
        Config{configEmail, configSite} = appConfig
        antiEnumMsg = MessageResponse "Verification email sent if needed"
    mUser <- liftIO (withDatabaseConnection env (`User.getUserByEmail` emailText))
    case mUser of
        Nothing ->
            pure antiEnumMsg
        Just user
            | isJust (User.userEmailConfirmedAt user) ->
                pure antiEnumMsg
            | otherwise -> do
                newToken <- liftIO generateConfirmationToken
                liftIO $
                    withDatabaseConnection env \conn ->
                        User.setConfirmationToken conn (User.userId user) newToken
                let tdata =
                        TemplateData
                            { templateRecipientEmail = emailText
                            , templateActionUrl =
                                siteUrl configSite
                                    <> "/auth/confirm?token="
                                    <> newToken
                            , templateSiteUrl = siteUrl configSite
                            , templateTokenHash = newToken
                            }
                case renderEmail Confirmation (emailFrom configEmail) tdata of
                    Left _ ->
                        liftIO (logMessage appLogger LogWarn "resend: failed to render confirmation email")
                    Right msg -> do
                        sendResult <- liftIO (sendEmail stubSender msg)
                        case sendResult of
                            Left err ->
                                liftIO $
                                    logMessage
                                        appLogger
                                        LogWarn
                                        ("resend: email delivery failed: " <> T.pack (show err))
                            Right () -> pure ()
                pure antiEnumMsg

-- ---------------------------------------------------------------------------
-- MFA handlers
-- ---------------------------------------------------------------------------

listFactorsHandler :: SessionPrincipal -> AppHandler ListFactorsResponse
listFactorsHandler principal = do
    env <- ask
    uid <- parseSessionUuid principal
    factors <- liftIO (withDatabaseConnection env (`MfaFactor.listFactorsForUser` uid))
    let toFactorResp f =
            FactorResponse
                { factorResponseId = FactorId (UUID.toText (MfaFactor.unMfaFactorId (MfaFactor.mfaFactorId f)))
                , factorResponseType = "totp"
                , factorResponseFriendlyName = MfaFactor.mfaFactorFriendlyName f
                , factorResponseStatus = factorStatusText (MfaFactor.mfaFactorStatus f)
                , factorResponseTotp = Nothing
                }
        allFactors = fmap toFactorResp factors
        verifiedTotp =
            filter
                ( \f ->
                    factorResponseStatus f == "verified"
                        && factorResponseType f == "totp"
                )
                allFactors
    pure
        ListFactorsResponse
            { listFactorsAll = allFactors
            , listFactorsTotp = verifiedTotp
            , listFactorsPhone = []
            }

enrollFactorHandler :: SessionPrincipal -> EnrollFactorRequest -> AppHandler FactorResponse
enrollFactorHandler principal req@EnrollFactorRequest{enrollFactorFriendlyName, enrollFactorIssuer} = do
    case validateEnrollRequest req of
        Left (EnrollUnsupportedFactorType ft) ->
            throwError
                err400
                    { errBody =
                        Aeson.encode $
                            Aeson.object
                                [ "error" Aeson..= ("unsupported_factor_type" :: T.Text)
                                , "error_description" Aeson..= ("Unsupported factor type: " <> ft)
                                ]
                    }
        Right () -> pure ()
    env <- ask
    let AppEnv{appConfig} = env
        Config{configJwt = JwtConfig{jwtIssuer}} = appConfig
        issuer = fromMaybe jwtIssuer enrollFactorIssuer
    uid <- parseSessionUuid principal
    mUser <- liftIO (withDatabaseConnection env (`User.getUserById` User.UserId uid))
    let label = case mUser >>= User.userEmail of
            Just email -> email
            Nothing -> UUID.toText uid
    secret <- liftIO generateTotpSecret
    let secretB32 = encodeBase32 (unTotpSecret secret)
        uri = otpAuthUri issuer label secret
    let newFactor =
            MfaFactor.NewMfaFactor
                { MfaFactor.newMfaFactorUserId = uid
                , MfaFactor.newMfaFactorFriendlyName = enrollFactorFriendlyName
                , MfaFactor.newMfaFactorType = MfaFactor.FactorTypeTotp
                , MfaFactor.newMfaFactorSecret = secretB32
                }
    factor <- liftIO (withDatabaseConnection env (`MfaFactor.createFactor` newFactor))
    pure
        FactorResponse
            { factorResponseId = FactorId (UUID.toText (MfaFactor.unMfaFactorId (MfaFactor.mfaFactorId factor)))
            , factorResponseType = "totp"
            , factorResponseFriendlyName = MfaFactor.mfaFactorFriendlyName factor
            , factorResponseStatus = factorStatusText (MfaFactor.mfaFactorStatus factor)
            , factorResponseTotp =
                Just
                    FactorTotpData
                        { factorTotpQrCode = uri
                        , factorTotpSecret = secretB32
                        , factorTotpUri = uri
                        }
            }

parseSessionUuid :: SessionPrincipal -> AppHandler UUID
parseSessionUuid principal =
    case UUID.fromText (sessionUserId principal) of
        Nothing ->
            throwError
                err401
                    { errBody =
                        Aeson.encode $
                            Aeson.object
                                [ "code" Aeson..= ("invalid_user_id" :: T.Text)
                                , "msg" Aeson..= ("malformed user id in token" :: T.Text)
                                ]
                    }
        Just u -> pure u

factorStatusText :: MfaFactor.FactorStatus -> T.Text
factorStatusText MfaFactor.FactorUnverified = "unverified"
factorStatusText MfaFactor.FactorVerified = "verified"

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

-- ---------------------------------------------------------------------------
-- GET /user and PUT /user handlers
-- ---------------------------------------------------------------------------

getUserHandler :: SessionPrincipal -> AppHandler UserResponse
getUserHandler principal = do
    env <- ask
    let uidText = sessionUserId principal
    uid <- case UUID.fromText uidText of
        Nothing ->
            throwError
                err401
                    { errBody =
                        Aeson.encode $
                            Aeson.object
                                [ "code" Aeson..= ("invalid_user_id" :: T.Text)
                                , "msg" Aeson..= ("malformed user id in token" :: T.Text)
                                ]
                    }
        Just u -> pure u
    mUser <- liftIO (withDatabaseConnection env (`User.getUserById` User.UserId uid))
    case mUser of
        Nothing ->
            throwError
                err404
                    { errBody =
                        Aeson.encode $
                            Aeson.object
                                [ "code" Aeson..= ("user_not_found" :: T.Text)
                                , "msg" Aeson..= ("user not found" :: T.Text)
                                ]
                    }
        Just u -> pure (buildUserResponse u)

updateUserHandler :: SessionPrincipal -> UpdateUserRequest -> AppHandler UserResponse
updateUserHandler principal req = do
    env <- ask
    let uidText = sessionUserId principal
    uid <- case UUID.fromText uidText of
        Nothing ->
            throwError
                err401
                    { errBody =
                        Aeson.encode $
                            Aeson.object
                                [ "code" Aeson..= ("invalid_user_id" :: T.Text)
                                , "msg" Aeson..= ("malformed user id in token" :: T.Text)
                                ]
                    }
        Just u -> pure u
    (mEmail, mPassword, mData) <- case validateUpdateRequest req of
        Left (UpdateUserEmailInvalid e) ->
            throwError
                err422
                    { errBody =
                        Aeson.encode $
                            Aeson.object
                                [ "code" Aeson..= ("invalid_email" :: T.Text)
                                , "msg" Aeson..= ("Email address is invalid: " <> e)
                                ]
                    }
        Left (UpdateUserPasswordTooShort minLen _) ->
            throwError
                err422
                    { errBody =
                        Aeson.encode $
                            Aeson.object
                                [ "code" Aeson..= ("weak_password" :: T.Text)
                                , "msg" Aeson..= ("Password must be at least " <> T.pack (show minLen) <> " characters")
                                ]
                    }
        Right triple -> pure triple
    mEncrypted <- case mPassword of
        Nothing -> pure Nothing
        Just pw -> liftIO (Just <$> hashPassword defaultArgon2Settings pw)
    mToken <- case mEmail of
        Nothing -> pure Nothing
        Just _ -> liftIO (Just <$> generateConfirmationToken)
    let upd =
            User.emptyUserUpdate
                { User.updateEmailChange = mEmail
                , User.updateEncryptedPassword = mEncrypted
                , User.updateRawUserMetaData = mData
                , User.updateEmailChangeToken = mToken
                }
    mUser <- liftIO (withDatabaseConnection env (\conn -> User.applyUserUpdate conn (User.UserId uid) upd))
    case mUser of
        Nothing ->
            throwError
                err404
                    { errBody =
                        Aeson.encode $
                            Aeson.object
                                [ "code" Aeson..= ("user_not_found" :: T.Text)
                                , "msg" Aeson..= ("user not found" :: T.Text)
                                ]
                    }
        Just u -> pure (buildUserResponse u)

logoutHandler ::
    SessionPrincipal ->
    Maybe T.Text ->
    AppHandler NoContent
logoutHandler principal _scope = do
    env <- ask
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
