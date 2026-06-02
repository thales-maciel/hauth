module Spec.Verify.IdentitySpec (runSpec) where

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
import Spec.TestUtils (assertEqual)

runSpec :: IO ()
runSpec = do
    testJwtSecret
    testSiteUrl
    testRedirectAllowlist

-- | Fake AppEnv that never touches the DB.
fakeEnv :: Config -> AppEnv
fakeEnv cfg =
    AppEnv
        { appConfig = cfg
        , appLogger = Logger \_level _msg -> pure ()
        , appConnectionPool = error "connection pool not used in identity checks"
        , appTemplateCache = error "template cache not used in identity checks"
        , appEnvWebhookWorker = Nothing
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
        [] -> fail ("check not found: " <> T.unpack name)
        (c : _) -> checkRun c (fakeEnv cfg)

isFail :: CheckOutcome -> Bool
isFail (CheckFail _) = True
isFail _ = False

isWarn :: CheckOutcome -> Bool
isWarn (CheckWarn _) = True
isWarn _ = False

-- jwt.secret checks

testJwtSecret :: IO ()
testJwtSecret = do
    r1 <- runNamed "jwt.secret" (withJwtSecret "shortshortshorts")
    assertEqual "jwt.secret: too short -> FAIL" True (isFail r1)

    r2 <- runNamed "jwt.secret" (withJwtSecret placeholderJwtSecret)
    assertEqual "jwt.secret: placeholder -> FAIL" True (isFail r2)

    r3 <- runNamed "jwt.secret" (withJwtSecret "aabbccddeeff00112233445566778899")
    assertEqual "jwt.secret: strong -> OK" CheckOk r3

-- site.url checks

testSiteUrl :: IO ()
testSiteUrl = do
    r1 <- runNamed "site.url" (withSiteUrl "not-a-url")
    assertEqual "site.url: malformed -> FAIL" True (isFail r1)

    r2 <- runNamed "site.url" (withSiteUrl "http://example.com")
    assertEqual "site.url: http://example.com -> WARN" True (isWarn r2)

    r3 <- runNamed "site.url" (withSiteUrl "https://example.com")
    assertEqual "site.url: https -> OK" CheckOk r3

    r4 <- runNamed "site.url" (withSiteUrl "http://localhost:3000")
    assertEqual "site.url: http://localhost -> OK" CheckOk r4

-- redirect_allowlist checks

testRedirectAllowlist :: IO ()
testRedirectAllowlist = do
    r1 <- runNamed "site.redirect_allowlist" (withRedirectUrls [])
    assertEqual "redirect_allowlist: empty -> WARN" True (isWarn r1)

    r2 <- runNamed "site.redirect_allowlist" (withRedirectUrls ["https://example.com/cb", "https://example.com/cb"])
    assertEqual "redirect_allowlist: dupes -> WARN" True (isWarn r2)

    r3 <- runNamed "site.redirect_allowlist" (withRedirectUrls ["not-a-url"])
    assertEqual "redirect_allowlist: unparseable -> FAIL" True (isFail r3)
