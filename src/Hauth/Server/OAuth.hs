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
import Hauth.OAuth.Github (
    GithubExchangeError (..),
    githubExchangeCode,
    githubProviderName,
 )
import Hauth.OAuth.Google (
    GoogleExchangeError (..),
    googleExchangeCode,
    googleProviderName,
 )
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
                        handleGoogleCallback env code flowState
                    | p == githubProviderName ->
                        handleGithubCallback env code flowState
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
-- Google callback
-- ---------------------------------------------------------------------------

handleGoogleCallback ::
    AppEnv ->
    Text ->
    FlowState ->
    AppHandler SessionResponse
handleGoogleCallback env code flowState = do
    let AppEnv{appConfig} = env
        Config{configOAuth, configSite, configJwt} = appConfig
        SiteConfig{siteUrl} = configSite
        JwtConfig{jwtAccessTokenTtlSeconds} = configJwt
        callbackUrl = siteUrl <> "/auth/v1/callback"
        providerName = flowStateProviderType flowState
    providerCfg <- case lookupProvider configOAuth providerName of
        Left _ ->
            throwError
                err400
                    { errBody =
                        Aeson.encode $
                            Aeson.object
                                [ "error" Aeson..= ("unsupported_provider" :: T.Text)
                                , "msg" Aeson..= ("Provider not configured: " <> providerName)
                                ]
                    }
        Right cfg -> pure cfg
    claimsResult <- liftIO (googleExchangeCode providerCfg callbackUrl code)
    identityClaims <- case claimsResult of
        Left err ->
            throwError
                err401
                    { errBody =
                        Aeson.encode $
                            Aeson.object
                                [ "error" Aeson..= ("oauth_exchange_failed" :: T.Text)
                                , "msg" Aeson..= googleErrorMessage err
                                ]
                    }
        Right ic -> pure ic
    issueOAuthSession env jwtAccessTokenTtlSeconds identityClaims

googleErrorMessage :: GoogleExchangeError -> T.Text
googleErrorMessage = \case
    GoogleHttpError msg -> msg
    GoogleTokenResponseInvalid msg -> msg
    GoogleUserinfoInvalid msg -> msg
    GoogleMissingSub -> "Google userinfo response missing sub claim"

-- ---------------------------------------------------------------------------
-- GitHub callback
-- ---------------------------------------------------------------------------

handleGithubCallback ::
    AppEnv ->
    T.Text ->
    FlowState ->
    AppHandler SessionResponse
handleGithubCallback env code _flowState = do
    let AppEnv{appConfig} = env
        Config{configOAuth, configSite = SiteConfig{siteUrl}, configJwt} = appConfig
        JwtConfig{jwtAccessTokenTtlSeconds} = configJwt
    providerCfg <- case lookupProvider configOAuth githubProviderName of
        Left _ ->
            throwError
                err401
                    { errBody =
                        Aeson.encode $
                            Aeson.object
                                [ "error" Aeson..= ("oauth_exchange_failed" :: T.Text)
                                , "msg" Aeson..= ("GitHub provider not configured" :: T.Text)
                                ]
                    }
        Right cfg -> pure cfg
    let callbackUrl = siteUrl <> "/auth/v1/callback"
    claimsResult <- liftIO (githubExchangeCode providerCfg callbackUrl code)
    claims <- case claimsResult of
        Left err ->
            throwError
                err401
                    { errBody =
                        Aeson.encode $
                            Aeson.object
                                [ "error" Aeson..= ("oauth_exchange_failed" :: T.Text)
                                , "msg" Aeson..= githubErrorMessage err
                                ]
                    }
        Right c -> pure c
    issueOAuthSession env jwtAccessTokenTtlSeconds claims

githubErrorMessage :: GithubExchangeError -> T.Text
githubErrorMessage = \case
    GithubHttpError msg -> msg
    GithubTokenResponseInvalid msg -> msg
    GithubUserInvalid msg -> msg
    GithubEmailsInvalid msg -> msg
    GithubMissingId -> "GitHub user has no id"

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
