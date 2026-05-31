module Spec.OAuthSpec (runSpec) where

import Data.Aeson (Object, Value (..))
import qualified Data.Aeson as Aeson
import qualified Data.Aeson.KeyMap as KeyMap
import qualified Data.Text as T
import Data.Time.Clock (addUTCTime, getCurrentTime)
import Hauth.API.Types (OAuthAuthorizeResponse (..))
import Hauth.Config (
    OAuthConfig (..),
    OAuthProviderConfig (..),
    SiteConfig (..),
 )
import Hauth.OAuth (
    OAuthError (..),
    buildStubAuthorizeUrl,
    generateState,
    isFlowStateExpired,
    lookupProvider,
    validateRedirectTo,
 )
import Spec.TestUtils (assertContains, assertEqual)

runSpec :: IO ()
runSpec = do
    let oauthCfg =
            OAuthConfig
                { oauthProviders =
                    [ OAuthProviderConfig
                        { oauthProviderName = "google"
                        , oauthProviderClientId = "google-client-id"
                        , oauthProviderClientSecret = "google-secret"
                        , oauthProviderDiscoveryUrl = "https://accounts.google.com/.well-known/openid-configuration"
                        }
                    , OAuthProviderConfig
                        { oauthProviderName = "github"
                        , oauthProviderClientId = "github-client-id"
                        , oauthProviderClientSecret = "github-secret"
                        , oauthProviderDiscoveryUrl = "https://github.com/.well-known/openid-configuration"
                        }
                    ]
                }
    case lookupProvider oauthCfg "google" of
        Left e -> fail ("lookupProvider exact match: expected Right, got Left: " <> show e)
        Right cfg -> assertEqual "lookupProvider exact match name" "google" (oauthProviderName cfg)
    case lookupProvider oauthCfg "GOOGLE" of
        Left e -> fail ("lookupProvider case-insensitive: expected Right, got Left: " <> show e)
        Right cfg -> assertEqual "lookupProvider GOOGLE match name" "google" (oauthProviderName cfg)
    case lookupProvider oauthCfg "facebook" of
        Left (OAuthUnknownProvider n) ->
            assertEqual "lookupProvider unknown provider name" "facebook" n
        Left other ->
            fail ("lookupProvider unknown: expected OAuthUnknownProvider, got " <> show other)
        Right _ ->
            fail "lookupProvider unknown: expected Left, got Right"
    let oauthSiteCfg =
            SiteConfig
                { siteUrl = "https://app.example.com"
                , siteAllowedRedirectUrls = ["https://app.example.com/auth/callback", "https://app.example.com/login"]
                }
    assertEqual
        "validateRedirectTo allowed"
        (Right "https://app.example.com/auth/callback")
        (validateRedirectTo oauthSiteCfg "https://app.example.com/auth/callback")
    case validateRedirectTo oauthSiteCfg "https://evil.example.com/steal" of
        Left _ -> pure ()
        Right _ -> fail "validateRedirectTo disallowed: expected Left, got Right"
    stateA <- generateState
    assertEqual "generateState non-empty" True (not (T.null stateA))
    assertEqual "generateState length 43" 43 (T.length stateA)
    stateB <- generateState
    assertEqual "generateState two calls differ" True (stateA /= stateB)
    nowForExpiry <- getCurrentTime
    let createdRecently = addUTCTime (negate 300) nowForExpiry
        createdLongAgo = addUTCTime (negate 1200) nowForExpiry
    assertEqual
        "isFlowStateExpired 5 min ago not expired"
        False
        (isFlowStateExpired nowForExpiry createdRecently 600)
    assertEqual
        "isFlowStateExpired 20 min ago expired"
        True
        (isFlowStateExpired nowForExpiry createdLongAgo 600)
    let stubCfg =
            OAuthProviderConfig
                { oauthProviderName = "google"
                , oauthProviderClientId = "my-client-id"
                , oauthProviderClientSecret = "my-secret"
                , oauthProviderDiscoveryUrl = "https://accounts.google.com/.well-known/openid-configuration"
                }
        stubUrl = buildStubAuthorizeUrl stubCfg "test-state-token" "https://app.example.com/callback" "https://app.example.com/login"
    assertContains "buildStubAuthorizeUrl state=" "state=" stubUrl
    assertContains "buildStubAuthorizeUrl client_id=" "client_id=" stubUrl
    assertContains "buildStubAuthorizeUrl redirect_uri=" "redirect_uri=" stubUrl
    assertContains "buildStubAuthorizeUrl state value" "test-state-token" stubUrl
    assertContains "buildStubAuthorizeUrl client_id value" "my-client-id" stubUrl
    let oauthResp =
            OAuthAuthorizeResponse
                { oauthAuthorizeUrl = "https://accounts.google.com/o/oauth2/auth?state=xyz"
                , oauthAuthorizeState = "xyz"
                }
    case Aeson.decode (Aeson.encode oauthResp) of
        Nothing -> fail "OAuthAuthorizeResponse: JSON decode failed"
        Just (obj :: Object) -> do
            if KeyMap.member "url" obj
                then pure ()
                else fail "OAuthAuthorizeResponse JSON: missing 'url' key"
            if KeyMap.member "state" obj
                then pure ()
                else fail "OAuthAuthorizeResponse JSON: missing 'state' key"
            assertEqual
                "OAuthAuthorizeResponse url value"
                (Just (String "https://accounts.google.com/o/oauth2/auth?state=xyz"))
                (KeyMap.lookup "url" obj)
            assertEqual
                "OAuthAuthorizeResponse state value"
                (Just (String "xyz"))
                (KeyMap.lookup "state" obj)
