{-# LANGUAGE OverloadedStrings #-}

{- | Fake 'ProviderExchange' for e2e tests.

Returns canned 'IdentityClaims' without touching the network, allowing the
OAuth callback happy path to be covered without real Google/GitHub credentials.
-}
module E2E.OAuthFake (
    fakeGoogleClaims,
    fakeGithubClaims,
    happyExchange,
    failingExchange,
    withFakeProviders,
) where

import qualified Data.Aeson as Aeson
import Data.Text (Text)
import E2E.Helpers (TestEnv (..))
import Hauth.Config (
    Config (..),
    OAuthConfig (..),
    OAuthProviderConfig (..),
 )
import Hauth.Env (AppEnv (..))
import Hauth.OAuth (IdentityClaims (..), OAuthError (..))
import Hauth.OAuth.ProviderExchange (ProviderExchange (..))

-- | Canned Google identity returned by the happy-path fake.
fakeGoogleClaims :: IdentityClaims
fakeGoogleClaims =
    IdentityClaims
        { identityProvider = "google"
        , identityProviderId = "fake-google-sub-001"
        , identityEmail = Just "googleuser@example.com"
        , identityData =
            Aeson.object
                [ "sub" Aeson..= ("fake-google-sub-001" :: Text)
                , "email" Aeson..= ("googleuser@example.com" :: Text)
                ]
        }

-- | Canned GitHub identity returned by the happy-path fake.
fakeGithubClaims :: IdentityClaims
fakeGithubClaims =
    IdentityClaims
        { identityProvider = "github"
        , identityProviderId = "42"
        , identityEmail = Just "githubuser@example.com"
        , identityData =
            Aeson.object
                [ "id" Aeson..= (42 :: Int)
                , "email" Aeson..= ("githubuser@example.com" :: Text)
                ]
        }

-- | A 'ProviderExchange' that always succeeds with canned claims.
happyExchange :: ProviderExchange
happyExchange =
    ProviderExchange
        { exchangeGoogle = \_code -> pure (Right fakeGoogleClaims)
        , exchangeGithub = \_code -> pure (Right fakeGithubClaims)
        }

-- | A 'ProviderExchange' that always fails with a provider error.
failingExchange :: ProviderExchange
failingExchange =
    ProviderExchange
        { exchangeGoogle = \_code -> pure (Left (OAuthMissingParam "fake google exchange failure"))
        , exchangeGithub = \_code -> pure (Left (OAuthMissingParam "fake github exchange failure"))
        }

{- | Derive a 'TestEnv' with fake providers injected.

Inserts stub Google and GitHub provider configs so 'authorizeHandler' can
look them up, and overrides 'appProviderExchange' with the given fake so
the callback handler never touches the network.
-}
withFakeProviders :: ProviderExchange -> TestEnv -> TestEnv
withFakeProviders px env =
    env
        { testAppEnv =
            (testAppEnv env)
                { appProviderExchange = px
                , appConfig = updatedConfig
                }
        , testConfig = updatedConfig
        }
  where
    updatedConfig =
        (testConfig env)
            { configOAuth =
                OAuthConfig
                    { oauthProviders =
                        [ fakeGoogleProviderConfig
                        , fakeGithubProviderConfig
                        ]
                    }
            }

fakeGoogleProviderConfig :: OAuthProviderConfig
fakeGoogleProviderConfig =
    OAuthProviderConfig
        { oauthProviderName = "google"
        , oauthProviderClientId = "fake-google-client-id"
        , oauthProviderClientSecret = "fake-google-client-secret"
        , oauthProviderDiscoveryUrl = "https://accounts.google.com/o/oauth2/v2/auth"
        }

fakeGithubProviderConfig :: OAuthProviderConfig
fakeGithubProviderConfig =
    OAuthProviderConfig
        { oauthProviderName = "github"
        , oauthProviderClientId = "fake-github-client-id"
        , oauthProviderClientSecret = "fake-github-client-secret"
        , oauthProviderDiscoveryUrl = "https://github.com/login/oauth/authorize"
        }
