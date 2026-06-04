module Spec.ConfigRedactionSpec (spec) where

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
import Test.Hspec (Spec, describe, it, shouldBe, shouldSatisfy)

-- | Sentinel value reused across cases so test failures point at the secret that leaked.
databaseSecret :: Text
databaseSecret = "postgresql://hauth:CORRECT_HORSE_BATTERY_STAPLE@localhost:5432/hauth"

jwtSecretLiteral :: Text
jwtSecretLiteral = "PEW-PEW-PEW-JWT-SECRET-THAT-MUST-NOT-LEAK-12345"

emailPasswordLiteral :: Text
emailPasswordLiteral = "smtp-hunter2-do-not-leak"

oauthSecretLiteral :: Text
oauthSecretLiteral = "oauth-client-secret-do-not-leak"

sampleDatabase :: DatabaseConfig
sampleDatabase =
    DatabaseConfig
        { databaseUrl = databaseSecret
        , databasePoolSize = 4
        }

sampleJwt :: JwtConfig
sampleJwt =
    JwtConfig
        { jwtSecret = jwtSecretLiteral
        , jwtIssuer = "hauth"
        , jwtAudience = "hauth"
        , jwtAccessTokenTtlSeconds = 3600
        , jwtRefreshTokenTtlSeconds = 86400
        }

sampleEmail :: EmailConfig
sampleEmail =
    EmailConfig
        { emailFrom = "noreply@example.com"
        , emailSmtpHost = "smtp.example.com"
        , emailSmtpPort = 587
        , emailUsername = Just "smtp-user"
        , emailPassword = Just emailPasswordLiteral
        }

sampleOAuthProvider :: OAuthProviderConfig
sampleOAuthProvider =
    OAuthProviderConfig
        { oauthProviderName = "google"
        , oauthProviderClientId = "client-id"
        , oauthProviderClientSecret = oauthSecretLiteral
        , oauthProviderDiscoveryUrl = "https://accounts.google.com/.well-known/openid-configuration"
        }

sampleOAuth :: OAuthConfig
sampleOAuth = OAuthConfig{oauthProviders = [sampleOAuthProvider]}

sampleSite :: SiteConfig
sampleSite =
    SiteConfig
        { siteUrl = "https://example.com"
        , siteAllowedRedirectUrls = ["https://example.com/callback"]
        }

sampleServer :: ServerConfig
sampleServer =
    ServerConfig
        { serverHost = "127.0.0.1"
        , serverPort = 8080
        }

sampleConfig :: Config
sampleConfig =
    Config
        { configDatabase = sampleDatabase
        , configJwt = sampleJwt
        , configSite = sampleSite
        , configEmail = sampleEmail
        , configOAuth = sampleOAuth
        , configServer = sampleServer
        }

containsRedacted :: String -> Bool
containsRedacted = T.isInfixOf "<redacted>" . T.pack

leaks :: Text -> String -> Bool
leaks secret rendered = T.isInfixOf secret (T.pack rendered)

spec :: Spec
spec = do
    describe "DatabaseConfig Show" $ do
        let rendered = show sampleDatabase
        it "renders <redacted> in place of databaseUrl" $
            rendered `shouldSatisfy` containsRedacted
        it "does not leak the database URL" $
            leaks databaseSecret rendered `shouldBe` False
        it "still prints non-secret fields" $
            T.isInfixOf "databasePoolSize = 4" (T.pack rendered) `shouldBe` True

    describe "JwtConfig Show" $ do
        let rendered = show sampleJwt
        it "renders <redacted> in place of jwtSecret" $
            rendered `shouldSatisfy` containsRedacted
        it "does not leak the JWT secret" $
            leaks jwtSecretLiteral rendered `shouldBe` False
        it "still prints non-secret fields" $
            T.isInfixOf "jwtIssuer = \"hauth\"" (T.pack rendered) `shouldBe` True

    describe "EmailConfig Show" $ do
        let renderedWithPassword = show sampleEmail
            renderedWithoutPassword = show sampleEmail{emailPassword = Nothing}
        it "renders <redacted> when emailPassword is set" $
            renderedWithPassword `shouldSatisfy` containsRedacted
        it "does not leak the SMTP password" $
            leaks emailPasswordLiteral renderedWithPassword `shouldBe` False
        it "preserves Nothing for emailPassword when unset" $
            T.isInfixOf "emailPassword = Nothing" (T.pack renderedWithoutPassword) `shouldBe` True
        it "still prints non-secret fields" $
            T.isInfixOf "emailSmtpHost = \"smtp.example.com\"" (T.pack renderedWithPassword) `shouldBe` True

    describe "OAuthProviderConfig Show" $ do
        let rendered = show sampleOAuthProvider
        it "renders <redacted> in place of oauthProviderClientSecret" $
            rendered `shouldSatisfy` containsRedacted
        it "does not leak the OAuth client secret" $
            leaks oauthSecretLiteral rendered `shouldBe` False
        it "still prints non-secret fields" $
            T.isInfixOf "oauthProviderClientId = \"client-id\"" (T.pack rendered) `shouldBe` True

    describe "Config Show (aggregate)" $ do
        let rendered = show sampleConfig
        it "renders <redacted> for every nested secret field" $
            rendered `shouldSatisfy` containsRedacted
        it "does not leak any underlying secret" $ do
            leaks databaseSecret rendered `shouldBe` False
            leaks jwtSecretLiteral rendered `shouldBe` False
            leaks emailPasswordLiteral rendered `shouldBe` False
            leaks oauthSecretLiteral rendered `shouldBe` False
