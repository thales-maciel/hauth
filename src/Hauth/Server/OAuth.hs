module Hauth.Server.OAuth (
    authorizeHandler,
    callbackHandler,
) where

import Control.Monad.Except (throwError)
import Control.Monad.IO.Class (liftIO)
import Control.Monad.Reader (ReaderT, ask)
import qualified Data.Aeson as Aeson
import qualified Data.Text as T
import Hauth.API.Auth (AnonymousPrincipal)
import Hauth.API.Types (OAuthAuthorizeResponse (..), SessionResponse)
import Hauth.Config (Config (..), SiteConfig (..))
import Hauth.Env (AppEnv (..), withDatabaseConnection)
import Hauth.OAuth (
    OAuthError (..),
    ProviderName (..),
    buildStubAuthorizeUrl,
    consumeFlowState,
    createFlowState,
    generateState,
    lookupProvider,
    validateRedirectTo,
 )
import Servant.Server (Handler, ServerError (errBody), err400, err501)

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
    _ <- case mCode of
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
        Right _ ->
            throwError
                err501
                    { errBody =
                        Aeson.encode $
                            Aeson.object
                                [ "error" Aeson..= ("provider_not_implemented" :: T.Text)
                                , "msg" Aeson..= ("OAuth code exchange not yet wired for this provider" :: T.Text)
                                ]
                    }
