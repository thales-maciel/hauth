module Spec.ConfigSpec (runSpec) where

import Data.Aeson (encode)
import qualified Data.Aeson as Aeson
import qualified Data.Aeson.KeyMap as KeyMap
import qualified Data.ByteString.Lazy as BSL
import qualified Data.Map.Strict as Map
import Hauth.API.Types (
    SettingsResponse (..),
    buildSettingsResponse,
 )
import Hauth.Config (
    Config (..),
    DatabaseConfig (..),
    EmailConfig (EmailConfig),
    JwtConfig (..),
    OAuthConfig (..),
    OAuthProviderConfig (..),
    ServerConfig (..),
    SiteConfig (..),
    decodeConfigBytes,
 )
import Hauth.Env (
    AppEnv (..),
    createAppEnvWithLogger,
    destroyAppEnv,
 )
import Spec.TestUtils (
    assertConfigFields,
    assertEqual,
    invalidConfigBytes,
    testLogger,
    validConfigBytes,
 )

runSpec :: IO ()
runSpec = do
    case decodeConfigBytes "valid.json" validConfigBytes of
        Left err ->
            fail ("valid config failed: " <> show err)
        Right config -> do
            assertEqual "config database url" "postgresql://hauth:hauth@localhost:5432/hauth" (databaseUrl (configDatabase config))
            assertEqual "config server port" 8080 (serverPort (configServer config))
            env <- createAppEnvWithLogger testLogger config
            assertEqual "env config" config (appConfig env)
            destroyAppEnv env
    assertConfigFields
        "missing config sections"
        ["database", "jwt", "site", "email", "oauth", "server"]
        (decodeConfigBytes "missing.json" "{}")
    assertConfigFields
        "invalid config fields"
        [ "database.url"
        , "database.pool_size"
        , "jwt.secret"
        , "jwt.issuer"
        , "jwt.audience"
        , "jwt.access_token_ttl_seconds"
        , "jwt.refresh_token_ttl_seconds"
        , "site.url"
        , "site.allowed_redirect_urls[0]"
        , "email.from"
        , "email.smtp_host"
        , "email.smtp_port"
        , "oauth.providers[0].name"
        , "oauth.providers[0].client_id"
        , "oauth.providers[0].client_secret"
        , "oauth.providers[0].discovery_url"
        , "server.host"
        , "server.port"
        ]
        (decodeConfigBytes "invalid.json" invalidConfigBytes)
    -- SettingsResponse tests
    let twoProviderConfig =
            settingsTestConfig
                [ OAuthProviderConfig
                    { oauthProviderName = "github"
                    , oauthProviderClientId = "gh-id"
                    , oauthProviderClientSecret = "gh-secret"
                    , oauthProviderDiscoveryUrl = "https://github.com/.well-known/openid-configuration"
                    }
                , OAuthProviderConfig
                    { oauthProviderName = "google"
                    , oauthProviderClientId = "g-id"
                    , oauthProviderClientSecret = "g-secret"
                    , oauthProviderDiscoveryUrl = "https://accounts.google.com/.well-known/openid-configuration"
                    }
                ]
        twoProviderSettings = buildSettingsResponse twoProviderConfig
    assertEqual "settings external email" (Just True) (Map.lookup "email" (settingsExternal twoProviderSettings))
    assertEqual "settings external phone" (Just False) (Map.lookup "phone" (settingsExternal twoProviderSettings))
    assertEqual "settings external github" (Just True) (Map.lookup "github" (settingsExternal twoProviderSettings))
    assertEqual "settings external google" (Just True) (Map.lookup "google" (settingsExternal twoProviderSettings))
    assertEqual "settings external_email_enabled" True (settingsExternalEmailEnabled twoProviderSettings)
    assertEqual "settings external_phone_enabled" False (settingsExternalPhoneEnabled twoProviderSettings)
    assertEqual "settings disable_signup" False (settingsDisableSignup twoProviderSettings)
    assertEqual "settings mailer_autoconfirm" False (settingsMailerAutoconfirm twoProviderSettings)
    assertEqual "settings phone_autoconfirm" False (settingsPhoneAutoconfirm twoProviderSettings)
    assertEqual "settings sms_provider" "" (settingsSmsProvider twoProviderSettings)
    -- JSON round-trip: top-level keys must match Supabase contract
    let settingsJson = BSL.toStrict (encode twoProviderSettings)
    case Aeson.decodeStrict' settingsJson of
        Nothing -> fail "settings JSON: decode failed"
        Just (obj :: Aeson.Object) -> do
            let requiredKeys = ["external", "external_email_enabled", "external_phone_enabled", "disable_signup", "mailer_autoconfirm", "phone_autoconfirm", "sms_provider"]
            mapM_
                ( \k ->
                    if KeyMap.member k obj
                        then pure ()
                        else fail ("settings JSON: missing key: " <> show k)
                )
                requiredKeys
    -- Provider name case-folding: "GitHub" becomes "github" in external map
    let mixedCaseConfig =
            settingsTestConfig
                [ OAuthProviderConfig
                    { oauthProviderName = "GitHub"
                    , oauthProviderClientId = "gh-id"
                    , oauthProviderClientSecret = "gh-secret"
                    , oauthProviderDiscoveryUrl = "https://github.com/.well-known/openid-configuration"
                    }
                ]
        mixedCaseSettings = buildSettingsResponse mixedCaseConfig
    assertEqual "settings provider case-fold" (Just True) (Map.lookup "github" (settingsExternal mixedCaseSettings))
    assertEqual "settings provider case-fold absent" Nothing (Map.lookup "GitHub" (settingsExternal mixedCaseSettings))

-- | Build a minimal test 'Config' with the given OAuth providers.
settingsTestConfig :: [OAuthProviderConfig] -> Config
settingsTestConfig providers =
    Config
        { configDatabase =
            DatabaseConfig
                { databaseUrl = "postgresql://hauth:hauth@localhost:5432/hauth"
                , databasePoolSize = 5
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
                { siteUrl = "http://localhost:3000"
                , siteAllowedRedirectUrls = ["http://localhost:3000/auth/callback"]
                }
        , configEmail = EmailConfig "noreply@example.com" "localhost" 1025 Nothing Nothing
        , configOAuth = OAuthConfig{oauthProviders = providers}
        , configServer =
            ServerConfig
                { serverHost = "127.0.0.1"
                , serverPort = 8080
                }
        }
