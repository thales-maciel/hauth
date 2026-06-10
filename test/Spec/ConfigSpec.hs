{-# LANGUAGE BlockArguments #-}

module Spec.ConfigSpec (spec) where

import Control.Exception (bracket)
import Data.Aeson (encode)
import qualified Data.Aeson as Aeson
import qualified Data.Aeson.KeyMap as KeyMap
import qualified Data.ByteString.Char8 as BSC
import qualified Data.ByteString.Lazy as BSL
import qualified Data.Map.Strict as Map
import qualified Data.Text as T
import Hauth.API.Types (
    SettingsResponse (..),
    buildSettingsResponse,
 )
import Hauth.Config (
    AdminUIConfig (..),
    AdminUICredential (..),
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
    defaultAdminUIConfig,
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
                    bracket (createAppEnvWithLogger testLogger config) destroyAppEnv \env ->
                        appConfig env `shouldBe` config

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

    describe "decodeConfigBytes (malformed URLs)" $ do
        let mkSiteUrl u =
                BSC.pack $
                    unlines
                        [ "{"
                        , "  \"database\": {\"url\": \"postgresql://hauth:hauth@localhost:5432/hauth\", \"pool_size\": 5},"
                        , "  \"jwt\": {\"secret\": \"0123456789abcdef0123456789abcdef\", \"issuer\": \"hauth\", \"audience\": \"authenticated\", \"access_token_ttl_seconds\": 3600, \"refresh_token_ttl_seconds\": 2592000},"
                        , "  \"site\": {\"url\": " <> show u <> ", \"allowed_redirect_urls\": [\"http://localhost:3000\"]},"
                        , "  \"email\": {\"from\": \"noreply@example.com\", \"smtp_host\": \"localhost\", \"smtp_port\": 1025},"
                        , "  \"oauth\": {\"providers\": [{\"name\": \"github\", \"client_id\": \"cid\", \"client_secret\": \"csec\", \"discovery_url\": \"https://github.com/.well-known/openid-configuration\"}]},"
                        , "  \"server\": {\"host\": \"127.0.0.1\", \"port\": 8080}"
                        , "}"
                        ]
            rejectsSiteUrl label u =
                it ("rejects site.url " <> label) $
                    case decodeConfigBytes "test.json" (mkSiteUrl u) of
                        Left (ConfigValidationError _ errs) ->
                            any (\e -> configFieldPath e == "site.url") errs `shouldBe` True
                        other ->
                            expectationFailure ("expected ConfigValidationError, got: " <> show other)

        rejectsSiteUrl "bare scheme (https://)" ("https://" :: String)
        rejectsSiteUrl "scheme with space (http:// bad)" ("http:// bad" :: String)
        rejectsSiteUrl "space in host (https://example .com)" ("https://example .com" :: String)
        rejectsSiteUrl "empty host (https:///missing-host)" ("https:///missing-host" :: String)

    describe "decodeConfigBytes (admin_ui)" $ do
        let argonHash =
                "$argon2id$v=19$m=65536,t=3,p=4$c29tZXNhbHQ$c29tZWhhc2hzb21laGFzaHNvbWVoYXNo" :: String
            mkAdminUI fragment =
                BSC.pack $
                    unlines
                        [ "{"
                        , "  \"database\": {\"url\": \"postgresql://hauth:hauth@localhost:5432/hauth\", \"pool_size\": 5},"
                        , "  \"jwt\": {\"secret\": \"0123456789abcdef0123456789abcdef\", \"issuer\": \"hauth\", \"audience\": \"authenticated\", \"access_token_ttl_seconds\": 3600, \"refresh_token_ttl_seconds\": 2592000},"
                        , "  \"site\": {\"url\": \"http://localhost:3000\", \"allowed_redirect_urls\": [\"http://localhost:3000\"]},"
                        , "  \"email\": {\"from\": \"noreply@example.com\", \"smtp_host\": \"localhost\", \"smtp_port\": 1025},"
                        , "  \"oauth\": {\"providers\": []},"
                        , "  \"server\": {\"host\": \"127.0.0.1\", \"port\": 8080}" <> fragment
                        , "}"
                        ]

        it "defaults to no credentials when the section is absent" $
            case decodeConfigBytes "valid.json" validConfigBytes of
                Left err -> expectationFailure ("valid config failed: " <> show err)
                Right config -> configAdminUI config `shouldBe` defaultAdminUIConfig

        it "parses credentials and session TTL" $
            case decodeConfigBytes
                "admin.json"
                ( mkAdminUI
                    ( ",\n  \"admin_ui\": {\"credentials\": [{\"username\": \"root\", \"password_hash\": \""
                        <> argonHash
                        <> "\"}], \"session_ttl_seconds\": 900}"
                    )
                ) of
                Left err -> expectationFailure ("admin_ui config failed: " <> show err)
                Right config ->
                    configAdminUI config
                        `shouldBe` AdminUIConfig
                            { adminUICredentials =
                                [ AdminUICredential
                                    { adminUIUsername = "root"
                                    , adminUIPasswordHash = T.pack argonHash
                                    }
                                ]
                            , adminUISessionTtlSeconds = 900
                            }

        it "defaults session_ttl_seconds when omitted" $
            case decodeConfigBytes
                "admin.json"
                ( mkAdminUI
                    ( ",\n  \"admin_ui\": {\"credentials\": [{\"username\": \"root\", \"password_hash\": \""
                        <> argonHash
                        <> "\"}]}"
                    )
                ) of
                Left err -> expectationFailure ("admin_ui config failed: " <> show err)
                Right config ->
                    adminUISessionTtlSeconds (configAdminUI config) `shouldBe` 3600

        it "rejects an explicitly empty credentials list" $
            case decodeConfigBytes
                "admin.json"
                (mkAdminUI ",\n  \"admin_ui\": {\"credentials\": []}") of
                Left (ConfigValidationError _ errs) ->
                    fmap configFieldPath errs `shouldBe` ["admin_ui.credentials"]
                other ->
                    expectationFailure ("expected ConfigValidationError, got: " <> show other)

        it "rejects a password_hash that is not argon2id PHC" $
            case decodeConfigBytes
                "admin.json"
                (mkAdminUI ",\n  \"admin_ui\": {\"credentials\": [{\"username\": \"root\", \"password_hash\": \"hunter2\"}]}") of
                Left (ConfigValidationError _ errs) ->
                    fmap configFieldPath errs
                        `shouldBe` ["admin_ui.credentials[0].password_hash"]
                other ->
                    expectationFailure ("expected ConfigValidationError, got: " <> show other)

        it "rejects a section without credentials" $
            case decodeConfigBytes
                "admin.json"
                (mkAdminUI ",\n  \"admin_ui\": {\"session_ttl_seconds\": 900}") of
                Left (ConfigValidationError _ errs) ->
                    fmap configFieldPath errs `shouldBe` ["admin_ui.credentials"]
                other ->
                    expectationFailure ("expected ConfigValidationError, got: " <> show other)

        it "rejects a non-positive session TTL" $
            case decodeConfigBytes
                "admin.json"
                ( mkAdminUI
                    ( ",\n  \"admin_ui\": {\"credentials\": [{\"username\": \"root\", \"password_hash\": \""
                        <> argonHash
                        <> "\"}], \"session_ttl_seconds\": 0}"
                    )
                ) of
                Left (ConfigValidationError _ errs) ->
                    fmap configFieldPath errs `shouldBe` ["admin_ui.session_ttl_seconds"]
                other ->
                    expectationFailure ("expected ConfigValidationError, got: " <> show other)

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
        , configAdminUI = defaultAdminUIConfig
        }
