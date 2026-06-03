module Spec.ConfigSpec (spec) where

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
    ConfigError (..),
    ConfigFieldError (..),
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
    invalidConfigBytes,
    testLogger,
    validConfigBytes,
 )
import Test.Hspec (Spec, describe, expectationFailure, it, shouldBe)

spec :: Spec
spec = do
    describe "decodeConfigBytes (valid)" $
        it "decodes valid config and creates AppEnv" $
            case decodeConfigBytes "valid.json" validConfigBytes of
                Left err ->
                    expectationFailure ("valid config failed: " <> show err)
                Right config -> do
                    databaseUrl (configDatabase config)
                        `shouldBe` "postgresql://hauth:hauth@localhost:5432/hauth"
                    serverPort (configServer config) `shouldBe` 8080
                    env <- createAppEnvWithLogger testLogger config
                    appConfig env `shouldBe` config
                    destroyAppEnv env

    describe "decodeConfigBytes (invalid)" $ do
        it "reports all missing top-level config sections" $
            case decodeConfigBytes "missing.json" "{}" of
                Left (ConfigValidationError _ errs) ->
                    fmap configFieldPath errs
                        `shouldBe` ["database", "jwt", "site", "email", "oauth", "server"]
                _ -> expectationFailure "expected ConfigValidationError"

        it "reports all invalid field paths" $
            case decodeConfigBytes "invalid.json" invalidConfigBytes of
                Left (ConfigValidationError _ errs) ->
                    fmap configFieldPath errs
                        `shouldBe` [ "database.url"
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
                _ -> expectationFailure "expected ConfigValidationError"

    describe "buildSettingsResponse" $ do
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

        it "external email is True" $
            Map.lookup "email" (settingsExternal twoProviderSettings) `shouldBe` Just True
        it "external phone is False" $
            Map.lookup "phone" (settingsExternal twoProviderSettings) `shouldBe` Just False
        it "external github is True" $
            Map.lookup "github" (settingsExternal twoProviderSettings) `shouldBe` Just True
        it "external google is True" $
            Map.lookup "google" (settingsExternal twoProviderSettings) `shouldBe` Just True
        it "external_email_enabled is True" $
            settingsExternalEmailEnabled twoProviderSettings `shouldBe` True
        it "external_phone_enabled is False" $
            settingsExternalPhoneEnabled twoProviderSettings `shouldBe` False
        it "disable_signup is False" $
            settingsDisableSignup twoProviderSettings `shouldBe` False
        it "mailer_autoconfirm is False" $
            settingsMailerAutoconfirm twoProviderSettings `shouldBe` False
        it "phone_autoconfirm is False" $
            settingsPhoneAutoconfirm twoProviderSettings `shouldBe` False
        it "sms_provider is empty" $
            settingsSmsProvider twoProviderSettings `shouldBe` ""

        it "JSON has top-level Supabase contract keys" $ do
            let settingsJson = BSL.toStrict (encode twoProviderSettings)
            case Aeson.decodeStrict' settingsJson of
                Nothing -> expectationFailure "decode failed"
                Just (obj :: Aeson.Object) -> do
                    let requiredKeys =
                            [ "external"
                            , "external_email_enabled"
                            , "external_phone_enabled"
                            , "disable_signup"
                            , "mailer_autoconfirm"
                            , "phone_autoconfirm"
                            , "sms_provider"
                            ]
                    mapM_
                        ( \k ->
                            if KeyMap.member k obj
                                then pure ()
                                else expectationFailure ("missing key: " <> show k)
                        )
                        requiredKeys

        it "case-folds provider name to lowercase in external map" $ do
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
            Map.lookup "github" (settingsExternal mixedCaseSettings) `shouldBe` Just True
            Map.lookup "GitHub" (settingsExternal mixedCaseSettings) `shouldBe` Nothing

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
