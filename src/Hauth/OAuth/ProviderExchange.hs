{- | Injectable provider-exchange record for the OAuth code-exchange step.

Wrapping the exchange functions in a record makes the callback handlers
independent of the concrete HTTP implementation, which lets e2e tests inject
a fake without touching network config or global state.
-}
module Hauth.OAuth.ProviderExchange (
    ProviderExchange (..),
    productionProviderExchange,
) where

import Data.Text (Text)
import Hauth.Config (Config (..), SiteConfig (..))
import Hauth.OAuth (IdentityClaims, OAuthError (..), lookupProvider)
import Hauth.OAuth.Github (GithubExchangeError (..), githubExchangeCode, githubProviderName)
import Hauth.OAuth.Google (GoogleExchangeError (..), googleExchangeCode, googleProviderName)

{- | One exchange function per supported provider.

Each field takes an authorization code and returns either an 'OAuthError' or
the resolved 'IdentityClaims'.  The production implementation calls the real
provider HTTP endpoints; tests inject a fake.
-}
data ProviderExchange = ProviderExchange
    { exchangeGoogle :: Text -> IO (Either OAuthError IdentityClaims)
    , exchangeGithub :: Text -> IO (Either OAuthError IdentityClaims)
    }

{- | Build the production 'ProviderExchange' from the application config.

The config and callback URL are captured at construction time so the record
fields match the simpler @Text -> IO (Either OAuthError IdentityClaims)@
shape that the callback handlers expect.
-}
productionProviderExchange :: Config -> ProviderExchange
productionProviderExchange Config{configOAuth, configSite = SiteConfig{siteUrl}} =
    ProviderExchange
        { exchangeGoogle = \code ->
            case lookupProvider configOAuth googleProviderName of
                Left _ -> pure (Left (OAuthUnknownProvider googleProviderName))
                Right providerCfg -> do
                    result <- googleExchangeCode providerCfg callbackUrl code
                    pure (either (Left . googleToOAuthError) Right result)
        , exchangeGithub = \code ->
            case lookupProvider configOAuth githubProviderName of
                Left _ -> pure (Left (OAuthUnknownProvider githubProviderName))
                Right providerCfg -> do
                    result <- githubExchangeCode providerCfg callbackUrl code
                    pure (either (Left . githubToOAuthError) Right result)
        }
  where
    callbackUrl = siteUrl <> "/auth/v1/callback"

googleToOAuthError :: GoogleExchangeError -> OAuthError
googleToOAuthError = \case
    GoogleHttpError msg -> OAuthMissingParam msg
    GoogleTokenResponseInvalid msg -> OAuthMissingParam msg
    GoogleUserinfoInvalid msg -> OAuthMissingParam msg
    GoogleMissingSub -> OAuthMissingParam "Google userinfo response missing sub claim"

githubToOAuthError :: GithubExchangeError -> OAuthError
githubToOAuthError = \case
    GithubHttpError msg -> OAuthMissingParam msg
    GithubTokenResponseInvalid msg -> OAuthMissingParam msg
    GithubUserInvalid msg -> OAuthMissingParam msg
    GithubEmailsInvalid msg -> OAuthMissingParam msg
    GithubMissingId -> OAuthMissingParam "GitHub user has no id"
