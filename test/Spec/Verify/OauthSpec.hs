module Spec.Verify.OauthSpec (spec) where

import Control.Concurrent (forkIO, killThread, threadDelay)
import Control.Exception (SomeException, bracket, try)
import Data.Text (Text)
import qualified Data.Text as T
import Hauth.Config (
    Config (..),
    DatabaseConfig (..),
    EmailConfig (..),
    JwtConfig (..),
    OAuthConfig (..),
    OAuthProviderConfig (..),
    ServerConfig (..),
    SiteConfig (..),
 )
import Hauth.Verify.Oauth (checks)
import Hauth.Verify.Types (Check (..), CheckOutcome (..))
import Network.HTTP.Client (
    defaultManagerSettings,
    httpLbs,
    newManager,
    parseRequest,
 )
import Network.HTTP.Types (status200, status500)
import Network.Wai (Application, responseLBS)
import qualified Network.Wai.Handler.Warp as Warp
import Test.Hspec (Spec, describe, expectationFailure, it, shouldBe, shouldSatisfy)

-- ---------------------------------------------------------------------------
-- Helpers
-- ---------------------------------------------------------------------------

-- | Run a fake HTTP server on a random port, hand its port to an action, then stop it.
withFakeServer :: Application -> (Int -> IO a) -> IO a
withFakeServer app action = do
    (port, socket) <- Warp.openFreePort
    bracket
        (forkIO (Warp.runSettingsSocket Warp.defaultSettings socket app))
        killThread
        (\_ -> waitForServer port >> action port)

-- | Retry until the server responds or give up after ~2 s.
waitForServer :: Int -> IO ()
waitForServer port = go (20 :: Int)
  where
    go 0 = pure ()
    go n = do
        result <- try @SomeException $ do
            manager <- newManager defaultManagerSettings
            req <- parseRequest ("http://127.0.0.1:" <> show port <> "/")
            _ <- httpLbs req manager
            pure ()
        case result of
            Right _ -> pure ()
            Left _ -> threadDelay 100000 >> go (n - 1)

okApp :: Application
okApp _req respond =
    respond (responseLBS status200 [] "{}")

errorApp :: Application
errorApp _req respond =
    respond (responseLBS status500 [] "internal error")

-- | Build a minimal Config pointing a single provider at the given URL.
configWith :: Text -> [Text] -> OAuthProviderConfig -> Config
configWith siteUrl' allowlist provider =
    Config
        { configDatabase =
            DatabaseConfig
                { databaseUrl = "postgresql://hauth:hauth@localhost:5432/hauth"
                , databasePoolSize = 1
                }
        , configJwt =
            JwtConfig
                { jwtSecret = "0123456789abcdef0123456789abcdef"
                , jwtIssuer = "hauth"
                , jwtAudience = "authenticated"
                , jwtAccessTokenTtlSeconds = 3600
                , jwtRefreshTokenTtlSeconds = 2592000
                }
        , configSite =
            SiteConfig
                { siteUrl = siteUrl'
                , siteAllowedRedirectUrls = allowlist
                }
        , configEmail =
            EmailConfig
                { emailFrom = "noreply@example.com"
                , emailSmtpHost = "localhost"
                , emailSmtpPort = 1025
                , emailUsername = Nothing
                , emailPassword = Nothing
                }
        , configOAuth = OAuthConfig [provider]
        , configServer =
            ServerConfig
                { serverHost = "127.0.0.1"
                , serverPort = 8080
                }
        }

fakeProvider :: Text -> Text -> OAuthProviderConfig
fakeProvider name discoveryUrl =
    OAuthProviderConfig
        { oauthProviderName = name
        , oauthProviderClientId = "fake-client-id"
        , oauthProviderClientSecret = "fake-client-secret"
        , oauthProviderDiscoveryUrl = discoveryUrl
        }

-- | Run a single named check from a list, failing if not found.
runNamedCheck :: Config -> Text -> IO CheckOutcome
runNamedCheck cfg name = do
    let cs = checks cfg
    case filter (\c -> checkName c == name) cs of
        [] -> fail ("check not found: " <> T.unpack name)
        (c : _) -> checkRun c (error "env not used by oauth checks")

-- ---------------------------------------------------------------------------
-- Tests
-- ---------------------------------------------------------------------------

spec :: Spec
spec = do
    describe "no providers" $ do
        it "no providers: empty checks" $ do
            let cfg =
                    Config
                        { configDatabase = DatabaseConfig "postgresql://x:x@localhost/x" 1
                        , configJwt = JwtConfig "0123456789abcdef0123456789abcdef" "h" "a" 3600 2592000
                        , configSite = SiteConfig "http://localhost:3000" []
                        , configEmail = EmailConfig "n@e.com" "localhost" 1025 Nothing Nothing
                        , configOAuth = OAuthConfig []
                        , configServer = ServerConfig "127.0.0.1" 8080
                        }
            length (checks cfg) `shouldBe` 0

    describe "discovery" $ do
        it "discovery ok: outcome" $
            withFakeServer okApp $ \port -> do
                let url = "http://127.0.0.1:" <> T.pack (show port) <> "/openid-configuration"
                    provider = fakeProvider "testprovider" url
                    cfg = configWith "http://localhost:3000" [] provider
                outcome <- runNamedCheck cfg "oauth.testprovider.discovery"
                outcome `shouldBe` CheckOk

        it "discovery fail: returns CheckFail with 500 in message" $
            withFakeServer errorApp $ \port -> do
                let url = "http://127.0.0.1:" <> T.pack (show port) <> "/openid-configuration"
                    provider = fakeProvider "failprovider" url
                    cfg = configWith "http://localhost:3000" [] provider
                outcome <- runNamedCheck cfg "oauth.failprovider.discovery"
                case outcome of
                    CheckFail msg ->
                        msg `shouldSatisfy` T.isInfixOf "500"
                    other ->
                        expectationFailure ("expected CheckFail, got " <> show other)

    describe "callback allowlist" $ do
        it "allowlist ok: outcome" $ do
            let provider = fakeProvider "google" "http://127.0.0.1:1/unused"
                allowlist = ["http://localhost:3000/auth/v1/callback"]
                cfg = configWith "http://localhost:3000" allowlist provider
            outcome <- runNamedCheck cfg "oauth.google.callback_allowlist"
            outcome `shouldBe` CheckOk

        it "allowlist warn: returns CheckWarn with callback URL in message" $ do
            let provider = fakeProvider "github" "http://127.0.0.1:1/unused"
                allowlist = ["http://localhost:3000/other"]
                cfg = configWith "http://localhost:3000" allowlist provider
            outcome <- runNamedCheck cfg "oauth.github.callback_allowlist"
            case outcome of
                CheckWarn msg ->
                    msg `shouldSatisfy` T.isInfixOf "callback URL"
                other ->
                    expectationFailure ("expected CheckWarn, got " <> show other)
