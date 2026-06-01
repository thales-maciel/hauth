-- | Verify checks for configured OAuth providers.
module Hauth.Verify.Oauth (
    checks,
) where

import Control.Exception (SomeException, try)
import Data.Text (Text)
import qualified Data.Text as T
import Hauth.Config (
    Config (..),
    OAuthConfig (..),
    OAuthProviderConfig (..),
    SiteConfig (..),
 )
import Hauth.Verify.Types (Check (..), CheckOutcome (..))
import Network.HTTP.Client (
    Manager,
    httpLbs,
    newManager,
    parseRequest,
    responseStatus,
 )
import Network.HTTP.Client.TLS (tlsManagerSettings)
import Network.HTTP.Types (statusCode)
import System.Timeout (timeout)

{- | Produce one discovery check + one callback-allowlist check per provider.
Returns empty list when no providers are configured.
-}
checks :: Config -> [Check]
checks cfg =
    concatMap (providerChecks cfg) (oauthProviders (configOAuth cfg))

providerChecks :: Config -> OAuthProviderConfig -> [Check]
providerChecks cfg provider =
    [ discoveryCheck provider
    , callbackAllowlistCheck cfg provider
    ]

-- ---------------------------------------------------------------------------
-- Discovery check
-- ---------------------------------------------------------------------------

discoveryCheck :: OAuthProviderConfig -> Check
discoveryCheck provider =
    Check
        { checkName = "oauth." <> oauthProviderName provider <> ".discovery"
        , checkLabel = "OAuth " <> oauthProviderName provider <> " discovery endpoint"
        , checkRun = \_env -> runDiscoveryCheck provider
        }

runDiscoveryCheck :: OAuthProviderConfig -> IO CheckOutcome
runDiscoveryCheck provider = do
    manager <- newManager tlsManagerSettings
    let url = T.unpack (oauthProviderDiscoveryUrl provider)
    result <- timeout fiveSeconds (probeDiscovery manager url)
    pure $ case result of
        Nothing ->
            CheckFail "discovery endpoint timed out after 5 seconds"
        Just (Left err) ->
            CheckFail ("discovery endpoint error: " <> T.pack (show err))
        Just (Right code)
            | code >= 200 && code < 400 ->
                CheckOk
            | otherwise ->
                CheckFail ("discovery endpoint returned HTTP " <> T.pack (show code))

fiveSeconds :: Int
fiveSeconds = 5000000

probeDiscovery :: Manager -> String -> IO (Either SomeException Int)
probeDiscovery manager url =
    try $ do
        req <- parseRequest url
        resp <- httpLbs req manager
        pure (statusCode (responseStatus resp))

-- ---------------------------------------------------------------------------
-- Callback allowlist check
-- ---------------------------------------------------------------------------

callbackAllowlistCheck :: Config -> OAuthProviderConfig -> Check
callbackAllowlistCheck cfg provider =
    Check
        { checkName = "oauth." <> oauthProviderName provider <> ".callback_allowlist"
        , checkLabel = "OAuth " <> oauthProviderName provider <> " callback URL in site allowlist"
        , checkRun = \_env -> pure (runCallbackAllowlistCheck cfg provider)
        }

-- | The canonical OAuth callback path for this service.
callbackPath :: Text
callbackPath = "/auth/v1/callback"

runCallbackAllowlistCheck :: Config -> OAuthProviderConfig -> CheckOutcome
runCallbackAllowlistCheck cfg _provider =
    let allowlist = siteAllowedRedirectUrls (configSite cfg)
        base = T.dropWhileEnd (== '/') (siteUrl (configSite cfg))
        callbackUrl = base <> callbackPath
     in if callbackUrl `elem` allowlist
            then CheckOk
            else
                CheckWarn
                    ( "callback URL "
                        <> callbackUrl
                        <> " not found in site.allowed_redirect_urls"
                    )
