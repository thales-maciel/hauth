{- | Public auth handlers: settings, signup, token (OAuth2 grants), recover,
verify, resend.

These are the unauthenticated endpoints behind @/auth/v1@'s public surface.
The shared session-issuance helper 'issueSessionForUser' lives here because it
is called by both the password grant and the verify flows, and only by them.

Error response shapes follow the historical wire contract per endpoint —
@/token@ emits OAuth2-style bodies, signup emits Supabase-style. See
"Hauth.Server.Errors" for the helpers and a note about that split.
-}
module Hauth.Server.Auth (
    settingsHandler,
    signupHandler,
    tokenHandler,
    recoverHandler,
    verifyHandler,
    resendHandler,
) where

import Control.Monad (unless)
import Control.Monad.Except (throwError)
import Control.Monad.IO.Class (liftIO)
import Control.Monad.Reader (ReaderT, ask, asks)
import qualified Data.Aeson as Aeson
import qualified Data.Aeson.KeyMap as KeyMap
import Data.Maybe (fromMaybe, isJust)
import Data.Text (Text)
import qualified Data.Text as T
import Data.Time.Clock (addUTCTime, getCurrentTime)
import Data.Time.Clock.POSIX (utcTimeToPOSIXSeconds)
import Data.UUID (UUID)
import qualified Data.UUID as UUID
import Database.PostgreSQL.Simple (Connection, Only (..), query, withTransaction)
import Hauth.API.Auth (AnonymousPrincipal)
import Hauth.API.Types
import Hauth.Auth.AalAmr (SessionAuthState (..), buildAmrEntries, deriveSessionAuthState)
import Hauth.Auth.Jwt (AccessTokenClaims (..), AmrEntry (..), issueAccessToken)
import Hauth.Auth.Login (LoginError (..), authorizeLogin, buildLoginClaims, extractCredentials)
import Hauth.Auth.Recovery (RecoveryError (..), recoverySentMessage, validateRecoverRequest, validateRecoveryVerify)
import Hauth.Auth.Role (sanitizeSessionRole)
import Hauth.Auth.Verify (OtpType (..), VerifyError (..), classifyVerifyRequest, parseOtpType)
import Hauth.Config (Config (..), EmailConfig (..), JwtConfig (..), SiteConfig (..))
import Hauth.Crypto.Password (defaultArgon2Settings, hashPassword)
import qualified Hauth.Crypto.Password as Pwd
import Hauth.Email (EmailSender (..), TemplateData (..), TemplateKind (..), renderEmailCached, sendEmail, stubSender)
import Hauth.Env (AppEnv (..), LogLevel (..), logMessage, withDatabaseConnection)
import Hauth.Hooks.Runner (HookDecision (..), runHook)
import Hauth.Hooks.Types (HookPoint (..), loadHookConfig)
import Hauth.Server.Errors (oauth2ErrorBody, oauth2ErrorOnly, supabaseErrorBody)
import Hauth.Server.Session (userPayloadFromUser)
import Hauth.Session (
    NewSession (..),
    RefreshToken (..),
    Session (sessionId),
    SessionId (..),
    createRefreshToken,
    createSession,
    generateOpaqueToken,
    getSession,
    lookupRefreshTokenRawForUpdate,
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
import Hauth.Webhooks.Events (SessionPayload (..), WebhookEvent (..))
import qualified Hauth.Webhooks.Outbox as Outbox
import Servant.Server (Handler, ServerError (errBody), err400, err401, err422, err500)

type AppHandler = ReaderT AppEnv Handler

-- ---------------------------------------------------------------------------
-- Settings endpoint
-- ---------------------------------------------------------------------------

settingsHandler :: AnonymousPrincipal -> AppHandler SettingsResponse
settingsHandler _ =
    asks (buildSettingsResponse . appConfig)

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
            throwError err400{errBody = oauth2ErrorOnly "unsupported_grant_type"}

-- | Outcome of the atomic refresh-token rotation transaction.
data RotateOutcome
    = ROInvalidGrant
    | ROReuseDetected
    | ROUserNotFound
    | ROSessionNotFound
    | -- | New refresh token, minimal user JSON, session row, user UUID.
      RORotated RefreshToken Aeson.Value Session UUID

handleRefreshTokenGrant :: TokenRequest -> AppHandler TokenResponse
handleRefreshTokenGrant TokenRequest{tokenRequestRefreshToken} = do
    tokenText <- case tokenRequestRefreshToken of
        Nothing ->
            throwError
                err400
                    { errBody = oauth2ErrorBody "invalid_request" "refresh_token is required"
                    }
        Just t -> pure t
    env <- ask
    let AppEnv{appConfig} = env
        Config{configJwt} = appConfig
        JwtConfig{jwtAccessTokenTtlSeconds} = configJwt
    now <- liftIO getCurrentTime
    outcome <- liftIO $ withDatabaseConnection env \conn -> withTransaction conn do
        mRawToken <- lookupRefreshTokenRawForUpdate conn tokenText
        case classifyRefreshTokenLookup mRawToken of
            Left InvalidGrant -> pure ROInvalidGrant
            Left RefreshTokenReuseDetected -> do
                let rt = case mRawToken of
                        Just r -> r
                        Nothing -> error "handleRefreshTokenGrant: reuse path saw Nothing"
                    sid = refreshTokenSessionId rt
                    uid = refreshTokenUserId rt
                _ <- revokeSessionRefreshTokens conn sid
                revokeSession conn sid
                Outbox.enqueue
                    conn
                    (SessionRevoked SessionPayload{spSessionId = unSessionId sid, spUserId = uid})
                pure ROReuseDetected
            Right (ValidRefreshToken rt) -> do
                let sid = refreshTokenSessionId rt
                    uid = refreshTokenUserId rt
                mUserVal <- fetchMinimalUser conn uid
                mSess <- getSession conn sid
                case (mUserVal, mSess) of
                    (Nothing, _) -> pure ROUserNotFound
                    (_, Nothing) -> pure ROSessionNotFound
                    (Just userVal, Just sess) -> do
                        revokeRefreshToken conn (refreshTokenId rt)
                        newRt <- createRefreshToken conn sid (Just tokenText)
                        touchSessionRefreshedAt conn sid
                        pure (RORotated newRt userVal sess uid)
    case outcome of
        ROInvalidGrant ->
            throwError
                err401
                    { errBody = oauth2ErrorBody "invalid_grant" "Invalid Refresh Token"
                    }
        ROReuseDetected ->
            throwError
                err401
                    { errBody = oauth2ErrorBody "invalid_grant" "Invalid Refresh Token: reuse detected"
                    }
        ROUserNotFound ->
            throwError
                err401
                    { errBody = oauth2ErrorBody "invalid_grant" "user not found"
                    }
        ROSessionNotFound ->
            throwError
                err401
                    { errBody = oauth2ErrorBody "invalid_grant" "session not found"
                    }
        RORotated newToken userVal sess uid -> do
            let sid = sessionId sess
                ttl = fromIntegral jwtAccessTokenTtlSeconds
                expiry = addUTCTime ttl now
                iatPosix = utcTimeToPOSIXSeconds now
                (userEmail', userRole') = extractEmailRole userVal
                sas = deriveSessionAuthState Nothing sess
                claims =
                    AccessTokenClaims
                        { claimSub = UUID.toText uid
                        , claimRole = sanitizeSessionRole userRole'
                        , claimEmail = userEmail'
                        , claimPhone = Nothing
                        , claimAppMetadata = Aeson.object []
                        , claimUserMetadata = Aeson.object []
                        , claimAal = sasAal sas
                        , claimAmr = buildAmrEntries (sasMethods sas) iatPosix
                        , claimSessionId = UUID.toText (unSessionId sid)
                        , claimIssuedAt = now
                        , claimExpiresAt = expiry
                        }
            signResult <- liftIO (issueAccessToken env claims)
            accessToken <- case signResult of
                Left err ->
                    throwError
                        err500
                            { errBody = oauth2ErrorBody "token_issuance_blocked" (T.pack (show err))
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

handlePasswordGrant :: TokenRequest -> AppHandler TokenResponse
handlePasswordGrant req = do
    (emailText, passwordText) <- case extractCredentials req of
        Left LoginMissingFields ->
            throwError
                err400
                    { errBody = oauth2ErrorBody "invalid_request" "email and password are required"
                    }
        Left err ->
            throwError err400{errBody = oauth2ErrorOnly (T.pack (show err))}
        Right creds -> pure creds
    env <- ask
    let AppEnv{appConfig} = env
        Config{configJwt} = appConfig
        JwtConfig{jwtAccessTokenTtlSeconds} = configJwt
    mUser <- liftIO (withDatabaseConnection env (`User.getUserByEmail` emailText))
    user <- case mUser of
        Nothing -> throwError invalidGrantError
        Just u -> pure u
    -- Fire password-verification-attempt hook BEFORE the crypto check so a
    -- hook-reject doesn't reveal whether the password would have been correct.
    let User.UserId userUUID' = User.userId user
        loginHookPayload =
            Aeson.object
                [ "email" Aeson..= emailText
                , "user_id" Aeson..= UUID.toText userUUID'
                , "ip" Aeson..= ("" :: T.Text)
                ]
    mLoginHookCfg <- liftIO (withDatabaseConnection env (`loadHookConfig` HookPasswordVerificationAttempt))
    case mLoginHookCfg of
        Nothing -> pure ()
        Just loginHookCfg -> do
            loginDecision <- liftIO (runHook loginHookCfg loginHookPayload)
            case loginDecision of
                HookAllow -> pure ()
                HookAllowWith _ -> pure ()
                HookReject _ ->
                    throwError
                        err400
                            { errBody = oauth2ErrorBody "mfa_or_password_blocked" "Login attempt blocked"
                            }
    let verified = case User.userEncryptedPassword user of
            Nothing -> False
            Just phc -> Pwd.verifyPassword phc passwordText
    case authorizeLogin verified (User.userEmailConfirmedAt user) of
        Left LoginInvalidGrant -> throwError invalidGrantError
        Left LoginEmailNotConfirmed ->
            -- Historical wire shape here mixes OAuth2 "error" with Supabase
            -- "msg" — preserved verbatim to avoid breaking existing clients.
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
    signResult <- liftIO (issueAccessToken env claims)
    accessToken <- case signResult of
        Left err ->
            throwError
                err500
                    { errBody = oauth2ErrorBody "token_issuance_blocked" (T.pack (show err))
                    }
        Right t -> pure t
    let userVal =
            Aeson.object
                [ "id" Aeson..= UUID.toText userUUID
                , "aud" Aeson..= User.userAud user
                , "role" Aeson..= sanitizeSessionRole (User.userRole user)
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
        err400{errBody = oauth2ErrorBody "invalid_grant" "Invalid login credentials"}

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
                    , "role" Aeson..= sanitizeSessionRole role
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

-- ---------------------------------------------------------------------------
-- Signup endpoint
-- ---------------------------------------------------------------------------

signupHandler :: AnonymousPrincipal -> SignupRequest -> AppHandler SignupResponse
signupHandler _ SignupRequest{signupEmail, signupPassword, signupData} = do
    env <- ask
    let emailText = unEmail signupEmail
        passwordText = unPassword signupPassword
    validatedEmail <- case validateSignupEmail emailText of
        Left _ ->
            throwError
                err400
                    { errBody = supabaseErrorBody "invalid_email" "Email address is invalid"
                    }
        Right e -> pure e
    validatedPassword <- case validateSignupPassword passwordText of
        Left (SignupPasswordTooShort minLen _) ->
            throwError
                err422
                    { errBody =
                        supabaseErrorBody
                            "weak_password"
                            ("Password must be at least " <> T.pack (show minLen) <> " characters")
                    }
        Left _ ->
            throwError err422{errBody = supabaseErrorBody "weak_password" "Password is too weak"}
        Right p -> pure p
    let proposedMetadata = fromMaybe (Aeson.object []) signupData
    -- Run before-user-created hook outside the transaction (hook can't see the new row).
    effectiveMetadata <- do
        mHookCfg <- liftIO $ withDatabaseConnection env (`loadHookConfig` HookBeforeUserCreated)
        case mHookCfg of
            Nothing -> pure proposedMetadata
            Just hookCfg -> do
                let hookPayload =
                        Aeson.object
                            [ "email" Aeson..= emailText
                            , "phone" Aeson..= (Nothing :: Maybe T.Text)
                            , "user_metadata" Aeson..= proposedMetadata
                            , "ip" Aeson..= (Nothing :: Maybe T.Text)
                            ]
                decision <- liftIO (runHook hookCfg hookPayload)
                case decision of
                    HookAllow -> pure proposedMetadata
                    HookAllowWith (Aeson.Object overlay) ->
                        -- Merge overlay.user_metadata into proposed metadata; ignore other fields.
                        case KeyMap.lookup "user_metadata" overlay of
                            Just (Aeson.Object extra) ->
                                case proposedMetadata of
                                    Aeson.Object base -> pure (Aeson.Object (KeyMap.union extra base))
                                    _ -> pure (Aeson.Object extra)
                            _ -> pure proposedMetadata
                    HookAllowWith _ -> pure proposedMetadata
                    HookReject reason ->
                        -- One-off wire shape: {"error", "message"}. Documented
                        -- as inconsistency follow-up; left inline because no
                        -- other site emits it.
                        throwError
                            err400
                                { errBody =
                                    Aeson.encode $
                                        Aeson.object
                                            [ "error" Aeson..= ("hook_rejected" :: T.Text)
                                            , "message" Aeson..= reason
                                            ]
                                }
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
                        let newUser =
                                User.NewUser
                                    { User.newUserEmail = validatedEmail
                                    , User.newUserEncryptedPassword = encrypted
                                    , User.newUserConfirmationToken = Just token
                                    , User.newUserUserMetadata = effectiveMetadata
                                    , User.newUserAud = "authenticated"
                                    }
                        created <- User.createUser conn newUser
                        Outbox.enqueue conn (UserSignedUp (userPayloadFromUser created))
                        pure (Right created)
    case user of
        Left SignupEmailExists ->
            throwError
                err422
                    { errBody = supabaseErrorBody "email_exists" "Email address already in use"
                    }
        Left _ ->
            throwError err400{errBody = supabaseErrorBody "signup_failed" "Signup failed"}
        Right created ->
            pure (buildSignupResponse created)

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
                        rendered <- liftIO (renderEmailCached (appTemplateCache env) Recovery emailFrom tdata)
                        case rendered of
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

{- | Historical wire shape for verify errors: @{"error", "msg"}@ — neither
OAuth2 nor Supabase canonical. Preserved verbatim; tracked as a follow-up.
-}
verifyErrorBody :: Text -> Text -> Aeson.Value
verifyErrorBody code msg =
    Aeson.object
        [ "error" Aeson..= code
        , "msg" Aeson..= msg
        ]

verifyHandler :: AnonymousPrincipal -> VerifyRequest -> AppHandler SessionResponse
verifyHandler _ req =
    case classifyVerifyRequest req of
        Left VerifyMissingToken ->
            throwError
                err400
                    { errBody = Aeson.encode (verifyErrorBody "otp_expired" "Token has expired or is invalid")
                    }
        Left (VerifyUnsupportedOtpType t) ->
            throwError
                err400
                    { errBody = Aeson.encode (verifyErrorBody "unsupported_otp_type" ("Unsupported OTP type: " <> t))
                    }
        Left VerifyOtpExpired ->
            throwError
                err401
                    { errBody = Aeson.encode (verifyErrorBody "otp_expired" "Token has expired or is invalid")
                    }
        Right OtpSignup ->
            handleSignupVerify req
        Right OtpRecovery ->
            handleRecoveryVerify req
        Right _ ->
            throwError
                err400
                    { errBody = Aeson.encode (verifyErrorBody "unsupported_otp_type" "OTP type not yet implemented")
                    }

handleSignupVerify :: VerifyRequest -> AppHandler SessionResponse
handleSignupVerify VerifyRequest{verifyToken} = do
    env <- ask
    mUser <- liftIO (withDatabaseConnection env (`User.getUserByConfirmationToken` verifyToken))
    user <- case mUser of
        Nothing ->
            throwError
                err401
                    { errBody = Aeson.encode (verifyErrorBody "otp_expired" "Token has expired or is invalid")
                    }
        Just u -> pure u
    liftIO $ withDatabaseConnection env \conn -> withTransaction conn do
        User.markEmailConfirmed conn (User.userId user)
        Outbox.enqueue conn (UserEmailConfirmed (userPayloadFromUser user))
    issueSessionForUser user "otp"

handleRecoveryVerify :: VerifyRequest -> AppHandler SessionResponse
handleRecoveryVerify req = do
    (token, password) <- case validateRecoveryVerify req of
        Left RecoveryMissingToken ->
            throwError
                err401
                    { errBody = oauth2ErrorBody "otp_expired" "Token is missing"
                    }
        Left (RecoveryPasswordTooShort minLen _) ->
            throwError
                err422
                    { errBody =
                        oauth2ErrorBody
                            "weak_password"
                            ("Password must be at least " <> T.pack (show minLen) <> " characters")
                    }
        Left RecoveryMissingEmail ->
            throwError
                err400
                    { errBody = oauth2ErrorBody "invalid_request" "Invalid request"
                    }
        Right pair -> pure pair
    env <- ask
    mUser <- liftIO (withDatabaseConnection env (`User.getUserByRecoveryToken` token))
    user <- case mUser of
        Nothing ->
            throwError
                err401
                    { errBody = oauth2ErrorBody "otp_expired" "Token has expired or is invalid"
                    }
        Just u -> pure u
    phc <- liftIO (hashPassword defaultArgon2Settings password)
    liftIO $ withDatabaseConnection env \conn -> withTransaction conn do
        User.applyPasswordReset conn (User.userId user) phc
        Outbox.enqueue conn (UserRecovered (userPayloadFromUser user))
    issueSessionForUser user "recovery"

-- ---------------------------------------------------------------------------
-- Shared session-issuance helper
-- ---------------------------------------------------------------------------

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
                , claimRole = sanitizeSessionRole (User.userRole user)
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
    signResult <- liftIO (issueAccessToken env claims)
    accessToken <- case signResult of
        Left err ->
            throwError
                err500
                    { errBody = oauth2ErrorBody "token_issuance_blocked" (T.pack (show err))
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
                    { errBody = Aeson.encode (verifyErrorBody "unsupported_otp_type" ("Unsupported OTP type: " <> t))
                    }
        Left _ ->
            throwError err400{errBody = oauth2ErrorOnly "unsupported_otp_type"}
        Right OtpSignup ->
            handleSignupResend (unEmail resendEmail)
        Right _ ->
            throwError
                err400
                    { errBody = Aeson.encode (verifyErrorBody "unsupported_otp_type" "OTP type not yet implemented")
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
                rendered <- liftIO (renderEmailCached (appTemplateCache env) Confirmation (emailFrom configEmail) tdata)
                case rendered of
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
