module Spec.OAuth.GoogleSpec (spec) where

import qualified Data.Aeson as Aeson
import qualified Data.Text.Encoding as TE
import Hauth.Config (OAuthProviderConfig (..))
import Hauth.OAuth (IdentityClaims (..))
import Hauth.OAuth.Google (
    GoogleExchangeError (..),
    buildGoogleTokenForm,
    googleProviderName,
    parseGoogleUserinfo,
 )
import Test.Hspec (Spec, describe, expectationFailure, it, shouldBe)

spec :: Spec
spec = do
    describe "googleProviderName" $ do
        it "googleProviderName is google" $
            googleProviderName `shouldBe` "google"

    describe "parseGoogleUserinfo" $ do
        it "parses a valid blob with sub, email, name, picture" $ do
            let validBlob =
                    Aeson.object
                        [ "sub" Aeson..= ("108876543210987654321" :: Aeson.Value)
                        , "email" Aeson..= ("alice@gmail.com" :: Aeson.Value)
                        , "name" Aeson..= ("Alice Example" :: Aeson.Value)
                        , "picture" Aeson..= ("https://lh3.googleusercontent.com/photo.jpg" :: Aeson.Value)
                        ]
            case parseGoogleUserinfo validBlob of
                Left e ->
                    expectationFailure ("parseGoogleUserinfo valid: expected Right, got Left: " <> show e)
                Right claims -> do
                    identityProvider claims `shouldBe` "google"
                    identityProviderId claims `shouldBe` "108876543210987654321"
                    identityEmail claims `shouldBe` Just "alice@gmail.com"
                    identityData claims `shouldBe` validBlob

        it "returns GoogleMissingSub when sub field is missing" $ do
            let noSubBlob =
                    Aeson.object
                        [ "email" Aeson..= ("alice@gmail.com" :: Aeson.Value)
                        ]
            case parseGoogleUserinfo noSubBlob of
                Left GoogleMissingSub -> pure ()
                Left e ->
                    expectationFailure ("parseGoogleUserinfo missing sub: expected GoogleMissingSub, got: " <> show e)
                Right _ ->
                    expectationFailure "parseGoogleUserinfo missing sub: expected Left, got Right"

        it "returns GoogleUserinfoInvalid on non-object input" $
            case parseGoogleUserinfo (Aeson.String "not-an-object") of
                Left (GoogleUserinfoInvalid _) -> pure ()
                Left e ->
                    expectationFailure ("parseGoogleUserinfo non-object: expected GoogleUserinfoInvalid, got: " <> show e)
                Right _ ->
                    expectationFailure "parseGoogleUserinfo non-object: expected Left, got Right"

    describe "buildGoogleTokenForm" $ do
        let providerCfg =
                OAuthProviderConfig
                    { oauthProviderName = "google"
                    , oauthProviderClientId = "test-client-id"
                    , oauthProviderClientSecret = "test-client-secret"
                    , oauthProviderDiscoveryUrl = "https://accounts.google.com/.well-known/openid-configuration"
                    }
            callbackUrl = "https://app.example.com/auth/v1/callback"
            authCode = "test-auth-code"
            form = buildGoogleTokenForm providerCfg callbackUrl authCode

        it "buildGoogleTokenForm has 5 fields" $
            length form `shouldBe` 5

        it "buildGoogleTokenForm code key" $
            lookup "code" form `shouldBe` Just (TE.encodeUtf8 authCode)

        it "buildGoogleTokenForm client_id key" $
            lookup "client_id" form `shouldBe` Just (TE.encodeUtf8 "test-client-id")

        it "buildGoogleTokenForm client_secret key" $
            lookup "client_secret" form `shouldBe` Just (TE.encodeUtf8 "test-client-secret")

        it "buildGoogleTokenForm redirect_uri key" $
            lookup "redirect_uri" form `shouldBe` Just (TE.encodeUtf8 callbackUrl)

        it "buildGoogleTokenForm grant_type is authorization_code" $
            lookup "grant_type" form `shouldBe` Just "authorization_code"
