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
        let stubCfg =
                OAuthProviderConfig
                    { oauthProviderName = "google"
                    , oauthProviderClientId = "my-client-id"
                    , oauthProviderClientSecret = "my-secret"
                    , oauthProviderDiscoveryUrl = "https://accounts.google.com/.well-known/openid-configuration"
                    }
            stubUrl = buildStubAuthorizeUrl stubCfg "test-state-token" "https://app.example.com/callback" "https://app.example.com/login"

        it "buildStubAuthorizeUrl state=" $
            stubUrl `shouldSatisfy` T.isInfixOf "state="

        it "buildStubAuthorizeUrl client_id=" $
            stubUrl `shouldSatisfy` T.isInfixOf "client_id="

        it "buildStubAuthorizeUrl redirect_uri=" $
            stubUrl `shouldSatisfy` T.isInfixOf "redirect_uri="

        it "buildStubAuthorizeUrl state value" $
            stubUrl `shouldSatisfy` T.isInfixOf "test-state-token"

        it "buildStubAuthorizeUrl client_id value" $
            stubUrl `shouldSatisfy` T.isInfixOf "my-client-id"

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
