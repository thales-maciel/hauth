module Spec.Verify.IdentitySpec (spec) where

import Data.Text (Text)
import qualified Data.Text as T
import Hauth.Config (
    Config (..),
    DatabaseConfig (..),
    EmailConfig (..),
    JwtConfig (..),
    OAuthConfig (..),
    ServerConfig (..),
    SiteConfig (..),
 )
import Hauth.Env (AppEnv (..), Logger (..))
import Hauth.Verify.Identity (checks, placeholderJwtSecret)
import Hauth.Verify.Types (Check (..), CheckOutcome (..))
import Test.Hspec (Spec, describe, expectationFailure, it, shouldBe)

spec :: Spec
spec = do
    describe "jwt.secret check" $ do
        it "too-short secret -> FAIL" $ do
            r <- runNamed "jwt.secret" (withJwtSecret "shortshortshorts")
            isFail r `shouldBe` True

        it "placeholder secret -> FAIL" $ do
            r <- runNamed "jwt.secret" (withJwtSecret placeholderJwtSecret)
            isFail r `shouldBe` True

        it "strong secret -> OK" $ do
            r <- runNamed "jwt.secret" (withJwtSecret "aabbccddeeff00112233445566778899")
            r `shouldBe` CheckOk

    describe "site.url check" $ do
        it "malformed -> FAIL" $ do
            r <- runNamed "site.url" (withSiteUrl "not-a-url")
            isFail r `shouldBe` True

        it "http://example.com -> WARN" $ do
            r <- runNamed "site.url" (withSiteUrl "http://example.com")
            isWarn r `shouldBe` True

        it "https://example.com -> OK" $ do
            r <- runNamed "site.url" (withSiteUrl "https://example.com")
            r `shouldBe` CheckOk

        it "http://localhost:3000 -> OK" $ do
            r <- runNamed "site.url" (withSiteUrl "http://localhost:3000")
            r `shouldBe` CheckOk

    describe "site.redirect_allowlist check" $ do
        it "empty -> WARN" $ do
            r <- runNamed "site.redirect_allowlist" (withRedirectUrls [])
            isWarn r `shouldBe` True

        it "duplicate entries -> WARN" $ do
            r <-
                runNamed
                    "site.redirect_allowlist"
                    (withRedirectUrls ["https://example.com/cb", "https://example.com/cb"])
            isWarn r `shouldBe` True

        it "unparseable URL -> FAIL" $ do
            r <- runNamed "site.redirect_allowlist" (withRedirectUrls ["not-a-url"])
            isFail r `shouldBe` True

-- | Fake AppEnv that never touches the DB.
fakeEnv :: Config -> AppEnv
fakeEnv cfg =
    AppEnv
        { appConfig = cfg
        , appLogger = Logger \_level _msg -> pure ()
        , appConnectionPool = error "connection pool not used in identity checks"
        , appTemplateCache = error "template cache not used in identity checks"
        , appBackgroundServiceStatuses = error "background services not used in identity checks"
        }

baseConfig :: Config
baseConfig =
    Config
        { configDatabase =
            DatabaseConfig
                { databaseUrl = "postgresql://hauth:hauth@localhost:5432/hauth"
                , databasePoolSize = 5
                }
        , configJwt =
            JwtConfig
                { jwtSecret = "aabbccddeeff00112233445566778899"
                , jwtIssuer = "hauth"
                , jwtAudience = "authenticated"
                , jwtAccessTokenTtlSeconds = 3600
                , jwtRefreshTokenTtlSeconds = 2592000
                }
        , configSite =
            SiteConfig
                { siteUrl = "https://example.com"
                , siteAllowedRedirectUrls = ["https://example.com/callback"]
                }
        , configEmail =
            EmailConfig
                { emailFrom = "noreply@example.com"
                , emailSmtpHost = "localhost"
                , emailSmtpPort = 1025
                , emailUsername = Nothing
                , emailPassword = Nothing
                }
        , configOAuth = OAuthConfig{oauthProviders = []}
        , configServer = ServerConfig{serverHost = "127.0.0.1", serverPort = 8080}
        }

withJwtSecret :: Text -> Config
withJwtSecret s = baseConfig{configJwt = (configJwt baseConfig){jwtSecret = s}}

withSiteUrl :: Text -> Config
withSiteUrl u = baseConfig{configSite = (configSite baseConfig){siteUrl = u}}

withRedirectUrls :: [Text] -> Config
withRedirectUrls us = baseConfig{configSite = (configSite baseConfig){siteAllowedRedirectUrls = us}}

runNamed :: Text -> Config -> IO CheckOutcome
runNamed name cfg =
    case filter (\c -> checkName c == name) checks of
        [] -> do
            expectationFailure ("check not found: " <> T.unpack name)
            error "unreachable"
        (c : _) -> checkRun c (fakeEnv cfg)

isFail :: CheckOutcome -> Bool
isFail (CheckFail _) = True
isFail _ = False

isWarn :: CheckOutcome -> Bool
isWarn (CheckWarn _) = True
isWarn _ = False
