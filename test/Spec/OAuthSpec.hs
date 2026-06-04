module Spec.OAuthSpec (spec) where

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
import Test.Hspec (Spec, describe, expectationFailure, it, shouldBe, shouldSatisfy)

spec :: Spec
spec = do
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

    describe "lookupProvider" $ do
        it "lookupProvider exact match name" $
            case lookupProvider oauthCfg "google" of
                Left e -> expectationFailure ("expected Right, got Left: " <> show e)
                Right cfg -> oauthProviderName cfg `shouldBe` "google"

        it "lookupProvider GOOGLE match name (case-insensitive)" $
            case lookupProvider oauthCfg "GOOGLE" of
                Left e -> expectationFailure ("expected Right, got Left: " <> show e)
                Right cfg -> oauthProviderName cfg `shouldBe` "google"

        it "lookupProvider unknown provider name" $
            case lookupProvider oauthCfg "facebook" of
                Left (OAuthUnknownProvider n) ->
                    n `shouldBe` "facebook"
                Left other ->
                    expectationFailure ("expected OAuthUnknownProvider, got " <> show other)
                Right _ ->
                    expectationFailure "expected Left, got Right"

    describe "validateRedirectTo" $ do
        let oauthSiteCfg =
                SiteConfig
                    { siteUrl = "https://app.example.com"
                    , siteAllowedRedirectUrls = ["https://app.example.com/auth/callback", "https://app.example.com/login"]
                    }

        it "validateRedirectTo allowed" $
            validateRedirectTo oauthSiteCfg "https://app.example.com/auth/callback"
                `shouldBe` Right "https://app.example.com/auth/callback"

        it "validateRedirectTo disallowed returns Left" $
            case validateRedirectTo oauthSiteCfg "https://evil.example.com/steal" of
                Left _ -> pure ()
                Right _ -> expectationFailure "expected Left, got Right"

    describe "generateState" $ do
        it "generateState non-empty" $ do
            stateA <- generateState
            not (T.null stateA) `shouldBe` True

        it "generateState length 43" $ do
            stateA <- generateState
            T.length stateA `shouldBe` 43

        it "generateState two calls differ" $ do
            stateA <- generateState
            stateB <- generateState
            (stateA /= stateB) `shouldBe` True

    describe "isFlowStateExpired" $ do
        it "isFlowStateExpired 5 min ago not expired" $ do
            nowForExpiry <- getCurrentTime
            let createdRecently = addUTCTime (negate 300) nowForExpiry
            isFlowStateExpired nowForExpiry createdRecently 600 `shouldBe` False

        it "isFlowStateExpired 20 min ago expired" $ do
            nowForExpiry <- getCurrentTime
            let createdLongAgo = addUTCTime (negate 1200) nowForExpiry
            isFlowStateExpired nowForExpiry createdLongAgo 600 `shouldBe` True

    describe "buildStubAuthorizeUrl" $ do
        let providers =
                [
                    ( "google"
                    , OAuthProviderConfig
                        { oauthProviderName = "google"
                        , oauthProviderClientId = "google-client-id"
                        , oauthProviderClientSecret = "google-secret"
                        , oauthProviderDiscoveryUrl = "https://accounts.google.com/o/oauth2/v2/auth"
                        }
                    )
                ,
                    ( "github"
                    , OAuthProviderConfig
                        { oauthProviderName = "github"
                        , oauthProviderClientId = "Ov23liGitHubClientId"
                        , oauthProviderClientSecret = "github-secret"
                        , oauthProviderDiscoveryUrl = "https://github.com/login/oauth/authorize"
                        }
                    )
                ]
            stateToken = "test-state-token"
            callbackUrl = "https://app.example.com/auth/v1/callback"
            redirectTo = "https://app.example.com/post-login"

        mapM_
            ( \(label, cfg) ->
                describe (label <> " authorization URL") $ do
                    let url = buildStubAuthorizeUrl cfg stateToken callbackUrl redirectTo
                        authBase = oauthProviderDiscoveryUrl cfg
                    it "starts with the configured authorization endpoint" $
                        url `shouldSatisfy` T.isPrefixOf (authBase <> "?")
                    it "carries the state token verbatim" $
                        url `shouldSatisfy` T.isInfixOf ("state=" <> stateToken)
                    it "carries the configured client_id verbatim" $
                        url `shouldSatisfy` T.isInfixOf ("client_id=" <> oauthProviderClientId cfg)
                    it "carries the callback as redirect_uri" $
                        url `shouldSatisfy` T.isInfixOf ("redirect_uri=" <> callbackUrl)
                    it "requests the authorization-code response type" $
                        url `shouldSatisfy` T.isInfixOf "response_type=code"
                    it "requests the fixed openid email profile scope" $
                        url `shouldSatisfy` T.isInfixOf "scope=openid%20email%20profile"
            )
            providers

    describe "OAuthAuthorizeResponse JSON" $ do
        let oauthResp =
                OAuthAuthorizeResponse
                    { oauthAuthorizeUrl = "https://accounts.google.com/o/oauth2/auth?state=xyz"
                    , oauthAuthorizeState = "xyz"
                    }

        it "has url key" $
            case Aeson.decode (Aeson.encode oauthResp) of
                Nothing -> expectationFailure "JSON decode failed"
                Just (obj :: Object) ->
                    KeyMap.member "url" obj `shouldBe` True

        it "has state key" $
            case Aeson.decode (Aeson.encode oauthResp) of
                Nothing -> expectationFailure "JSON decode failed"
                Just (obj :: Object) ->
                    KeyMap.member "state" obj `shouldBe` True

        it "url value" $
            case Aeson.decode (Aeson.encode oauthResp) of
                Nothing -> expectationFailure "JSON decode failed"
                Just (obj :: Object) ->
                    KeyMap.lookup "url" obj
                        `shouldBe` Just (String "https://accounts.google.com/o/oauth2/auth?state=xyz")

        it "state value" $
            case Aeson.decode (Aeson.encode oauthResp) of
                Nothing -> expectationFailure "JSON decode failed"
                Just (obj :: Object) ->
                    KeyMap.lookup "state" obj `shouldBe` Just (String "xyz")
