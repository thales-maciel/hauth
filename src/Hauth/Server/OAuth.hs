module Hauth.Server.OAuth (
    authorizeHandler,
    callbackHandler,
) where

import Control.Monad.Except (throwError)
import Control.Monad.IO.Class (liftIO)
import Control.Monad.Reader (ReaderT, ask)
import qualified Data.Aeson as Aeson
import Data.Text (Text)
import qualified Data.Text as T
import Data.Time.Clock (addUTCTime, getCurrentTime)
import Data.Time.Clock.POSIX (utcTimeToPOSIXSeconds)
import qualified Data.UUID as UUID
import Hauth.API.Auth (AnonymousPrincipal)
import Hauth.API.Types (
    OAuthAuthorizeResponse (..),
    SessionResponse (..),
    buildSessionResponse,
    buildUserResponse,
 )
import Hauth.Auth.Jwt (AccessTokenClaims (..), AmrEntry (..), issueAccessToken)
import Hauth.Config (Config (..), JwtConfig (..), SiteConfig (..))
import Hauth.Env (AppEnv (..), withDatabaseConnection)
import Hauth.OAuth (
    FlowState (..),
    IdentityClaims,
    OAuthError (..),
    ProviderName (..),
    buildStubAuthorizeUrl,
    consumeFlowState,
    createFlowState,
    findOrCreateIdentity,
    generateState,
    lookupProvider,
    validateRedirectTo,
 )
import Hauth.OAuth.Github (githubProviderName)
import Hauth.OAuth.Google (googleProviderName)
import Hauth.OAuth.ProviderExchange (ProviderExchange (..))
import Hauth.Session (
    NewSession (..),
    SessionId (..),
    createRefreshToken,
    createSession,
    refreshTokenToken,
    sessionId,
 )
import qualified Hauth.User as User
import Servant.Server (Handler, ServerError (errBody), err400, err401, err500, err501)

type AppHandler = ReaderT AppEnv Handler

authorizeHandler ::
    AnonymousPrincipal ->
    Maybe T.Text ->
    Maybe T.Text ->
    AppHandler OAuthAuthorizeResponse
authorizeHandler _ mProvider mRedirectTo = do
    env <- ask
    let AppEnv{appConfig} = env
        Config{configOAuth, configSite} = appConfig
        SiteConfig{siteUrl} = configSite
    providerText <- case mProvider of
        Nothing ->
            throwError
                err400
                    { errBody =
                        Aeson.encode $
                            Aeson.object ["error" Aeson..= ("missing_provider" :: T.Text)]
                    }
        Just p -> pure p
    providerCfg <- case lookupProvider configOAuth providerText of
        Left _ ->
            throwError
                err400
                    { errBody =
                        Aeson.encode $
                            Aeson.object ["error" Aeson..= ("unsupported_provider" :: T.Text)]
                    }
        Right cfg -> pure cfg
    redirectTo <- case mRedirectTo of
        Nothing ->
            throwError
                err400
                    { errBody =
                        Aeson.encode $
                            Aeson.object ["error" Aeson..= ("invalid_redirect_to" :: T.Text)]
                    }
        Just r -> pure r
    case validateRedirectTo configSite redirectTo of
        Left _ ->
            throwError
                err400
                    { errBody =
                        Aeson.encode $
                            Aeson.object ["error" Aeson..= ("invalid_redirect_to" :: T.Text)]
                    }
        Right _ -> pure ()
    stateToken <- liftIO generateState
    let callbackUrl = siteUrl <> "/auth/v1/callback"
    _ <- liftIO $
        withDatabaseConnection env \conn ->
            createFlowState conn (ProviderName providerText) stateToken
    let authorizeUrl = buildStubAuthorizeUrl providerCfg stateToken callbackUrl redirectTo
    pure
        OAuthAuthorizeResponse
            { oauthAuthorizeUrl = authorizeUrl
            , oauthAuthorizeState = stateToken
            }

callbackHandler ::
    AnonymousPrincipal ->
    Maybe T.Text ->
    Maybe T.Text ->
    AppHandler SessionResponse
callbackHandler _ mCode mState = do
    env <- ask
    stateToken <- case mState of
        Nothing ->
            throwError
                err400
                    { errBody =
                        Aeson.encode $
                            Aeson.object
                                [ "error" Aeson..= ("invalid_request" :: T.Text)
                                , "msg" Aeson..= ("state parameter is required" :: T.Text)
                                ]
                    }
        Just s -> pure s
    code <- case mCode of
        Nothing ->
            throwError
                err400
                    { errBody =
                        Aeson.encode $
                            Aeson.object
                                [ "error" Aeson..= ("invalid_request" :: T.Text)
                                , "msg" Aeson..= ("code parameter is required" :: T.Text)
                                ]
                    }
        Just c -> pure c
    result <-
        liftIO $
            withDatabaseConnection env (`consumeFlowState` stateToken)
    case result of
        Left OAuthStateInvalid ->
            throwError
                err400
                    { errBody =
                        Aeson.encode $
                            Aeson.object
                                [ "error" Aeson..= ("invalid_state" :: T.Text)
                                , "msg" Aeson..= ("OAuth state is invalid or already consumed" :: T.Text)
                                ]
                    }
        Left OAuthStateExpired ->
            throwError
                err400
                    { errBody =
                        Aeson.encode $
                            Aeson.object
                                [ "error" Aeson..= ("state_expired" :: T.Text)
                                , "msg" Aeson..= ("OAuth state has expired" :: T.Text)
                                ]
                    }
        Left _ ->
            throwError
                err400
                    { errBody =
                        Aeson.encode $
                            Aeson.object ["error" Aeson..= ("invalid_state" :: T.Text)]
                    }
        Right flowState ->
            case flowStateProviderType flowState of
                p
                    | p == googleProviderName ->
                        handleProviderCallback env (exchangeGoogle (appProviderExchange env)) code flowState
                    | p == githubProviderName ->
                        handleProviderCallback env (exchangeGithub (appProviderExchange env)) code flowState
                other ->
                    throwError (unsupportedProviderError other)

unsupportedProviderError :: Text -> ServerError
unsupportedProviderError providerName =
    err501
        { errBody =
            Aeson.encode $
                Aeson.object
                    [ "error" Aeson..= ("provider_not_implemented" :: T.Text)
                    , "msg" Aeson..= ("OAuth code exchange not yet implemented for provider: " <> providerName)
                    ]
        }

-- ---------------------------------------------------------------------------
-- Unified provider callback (dispatched via injected ProviderExchange)
-- ---------------------------------------------------------------------------

handleProviderCallback ::
    AppEnv ->
    -- | Injected exchange function for the matched provider.
    (Text -> IO (Either OAuthError IdentityClaims)) ->
    Text ->
    FlowState ->
    AppHandler SessionResponse
handleProviderCallback env exchange code _flowState = do
    let AppEnv{appConfig} = env
        Config{configJwt} = appConfig
        JwtConfig{jwtAccessTokenTtlSeconds} = configJwt
    claimsResult <- liftIO (exchange code)
    identityClaims <- case claimsResult of
        Left (OAuthUnknownProvider p) ->
            throwError
                err400
                    { errBody =
                        Aeson.encode $
                            Aeson.object
                                [ "error" Aeson..= ("unsupported_provider" :: T.Text)
                                , "msg" Aeson..= ("Provider not configured: " <> p)
                                ]
                    }
        Left err ->
            throwError
                err401
                    { errBody =
                        Aeson.encode $
                            Aeson.object
                                [ "error" Aeson..= ("oauth_exchange_failed" :: T.Text)
                                , "msg" Aeson..= oauthErrorMessage err
                                ]
                    }
        Right ic -> pure ic
    issueOAuthSession env jwtAccessTokenTtlSeconds identityClaims

oauthErrorMessage :: OAuthError -> T.Text
oauthErrorMessage = \case
    OAuthUnknownProvider p -> "unknown provider: " <> p
    OAuthStateExpired -> "OAuth state has expired"
    OAuthStateInvalid -> "OAuth state is invalid or already consumed"
    OAuthMissingParam msg -> msg
    OAuthIdentityMissing msg -> "identity missing after insert: " <> msg

-- ---------------------------------------------------------------------------
-- Shared session-issuance for OAuth providers
-- ---------------------------------------------------------------------------

issueOAuthSession ::
    AppEnv ->
    Int ->
    IdentityClaims ->
    AppHandler SessionResponse
issueOAuthSession env jwtAccessTokenTtlSeconds claims = do
    (userId, _isNewUser) <-
        liftIO (withDatabaseConnection env (`findOrCreateIdentity` claims))
    mUser <- liftIO (withDatabaseConnection env (`User.getUserById` userId))
    user <- case mUser of
        Nothing ->
            throwError
                err401
                    { errBody =
                        Aeson.encode $
                            Aeson.object
                                [ "error" Aeson..= ("oauth_exchange_failed" :: T.Text)
                                , "msg" Aeson..= ("user not found after identity creation" :: T.Text)
                                ]
                    }
        Just u -> pure u
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
    let iatSecs = floor (utcTimeToPOSIXSeconds now) :: Integer
        ttl = fromIntegral jwtAccessTokenTtlSeconds
        expiry = addUTCTime ttl now
        SessionId sid = sessionId sess
        accessClaims =
            AccessTokenClaims
                { claimSub = UUID.toText userUUID
                , claimRole = "authenticated"
                , claimEmail = User.userEmail user
                , claimPhone = Nothing
                , claimAppMetadata = User.userRawAppMetaData user
                , claimUserMetadata = User.userRawUserMetaData user
                , claimAal = "aal1"
                , claimAmr =
                    [ AmrEntry
                        { amrMethod = "oauth"
                        , amrTimestamp = iatSecs
                        }
                    ]
                , claimSessionId = UUID.toText sid
                , claimIssuedAt = now
                , claimExpiresAt = expiry
                }
    signResult <- liftIO (issueAccessToken env accessClaims)
    accessToken <- case signResult of
        Left err ->
            throwError
                err500
                    { errBody =
                        Aeson.encode $
                            Aeson.object
                                [ "error" Aeson..= ("token_issuance_blocked" :: T.Text)
                                , "msg" Aeson..= T.pack (show err)
                                ]
                    }
        Right t -> pure t
    pure $
        buildSessionResponse
            accessToken
            (refreshTokenToken refreshTok)
            jwtAccessTokenTtlSeconds
            (buildUserResponse user)
