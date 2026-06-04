{- | @\/token@ endpoint handler: dispatches between the @refresh_token@ and
@password@ grant flows.

The refresh-token grant rotates the user's refresh token atomically inside
a SELECT FOR UPDATE transaction so concurrent rotation attempts cannot
both win; the password grant runs the password-verification-attempt hook
before the crypto check so a hook-reject can't reveal whether the
password was correct.
-}
module Hauth.Server.Auth.Token (
    tokenHandler,
    handlePasswordGrant,
    handleRefreshTokenGrant,
    fetchMinimalUser,
    extractEmailRole,
) where

import Control.Monad.Except (throwError)
import Control.Monad.IO.Class (liftIO)
import Control.Monad.Reader (ask)
import qualified Data.Aeson as Aeson
import qualified Data.Aeson.KeyMap as KeyMap
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
import Hauth.Auth.Jwt (AccessTokenClaims (..), issueAccessToken)
import Hauth.Auth.Login (LoginError (..), authorizeLogin, buildLoginClaims, extractCredentials)
import Hauth.Auth.Role (sanitizeSessionRole)
import Hauth.Config (Config (..), JwtConfig (..))
import qualified Hauth.Crypto.Password as Pwd
import Hauth.Env (AppEnv (..), withDatabaseConnection)
import Hauth.Hooks.Runner (HookDecision (..), runHook)
import Hauth.Hooks.Types (HookPoint (..), loadHookConfig)
import Hauth.Server.Auth.Session (AppHandler)
import Hauth.Server.Errors (oauth2ErrorBody, oauth2ErrorOnly)
import Hauth.Session (
    NewSession (..),
    RefreshToken (..),
    Session (sessionId),
    SessionId (..),
    createRefreshToken,
    createSession,
    getSession,
    lookupRefreshTokenRawForUpdate,
    revokeRefreshToken,
    revokeSession,
    revokeSessionRefreshTokens,
    sessionId,
    touchSessionRefreshedAt,
 )
import qualified Hauth.User as User
import Hauth.Webhooks.Events (SessionPayload (..), WebhookEvent (..))
import qualified Hauth.Webhooks.Outbox as Outbox
import Servant.Server (ServerError (errBody), err400, err401, err500)

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
            loginDecision <- liftIO (runHook (appHookHttpManager env) loginHookCfg loginHookPayload)
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
