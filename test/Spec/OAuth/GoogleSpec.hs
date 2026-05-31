module Spec.OAuth.GoogleSpec (runSpec) where

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
import Spec.TestUtils (assertEqual)

runSpec :: IO ()
runSpec = do
    -- googleProviderName is "google"
    assertEqual
        "googleProviderName is google"
        "google"
        googleProviderName

    -- parseGoogleUserinfo: valid blob with sub, email, name, picture
    let validBlob =
            Aeson.object
                [ "sub" Aeson..= ("108876543210987654321" :: Aeson.Value)
                , "email" Aeson..= ("alice@gmail.com" :: Aeson.Value)
                , "name" Aeson..= ("Alice Example" :: Aeson.Value)
                , "picture" Aeson..= ("https://lh3.googleusercontent.com/photo.jpg" :: Aeson.Value)
                ]
    case parseGoogleUserinfo validBlob of
        Left e ->
            fail ("parseGoogleUserinfo valid: expected Right, got Left: " <> show e)
        Right claims -> do
            assertEqual
                "parseGoogleUserinfo provider"
                "google"
                (identityProvider claims)
            assertEqual
                "parseGoogleUserinfo sub"
                "108876543210987654321"
                (identityProviderId claims)
            assertEqual
                "parseGoogleUserinfo email"
                (Just "alice@gmail.com")
                (identityEmail claims)
            assertEqual
                "parseGoogleUserinfo identityData equals input"
                validBlob
                (identityData claims)

    -- parseGoogleUserinfo: missing sub field
    let noSubBlob =
            Aeson.object
                [ "email" Aeson..= ("alice@gmail.com" :: Aeson.Value)
                ]
    case parseGoogleUserinfo noSubBlob of
        Left GoogleMissingSub -> pure ()
        Left e ->
            fail ("parseGoogleUserinfo missing sub: expected GoogleMissingSub, got: " <> show e)
        Right _ ->
            fail "parseGoogleUserinfo missing sub: expected Left, got Right"

    -- parseGoogleUserinfo: non-object input
    case parseGoogleUserinfo (Aeson.String "not-an-object") of
        Left (GoogleUserinfoInvalid _) -> pure ()
        Left e ->
            fail ("parseGoogleUserinfo non-object: expected GoogleUserinfoInvalid, got: " <> show e)
        Right _ ->
            fail "parseGoogleUserinfo non-object: expected Left, got Right"

    -- buildGoogleTokenForm: correct keys and values
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

    assertEqual
        "buildGoogleTokenForm has 5 fields"
        5
        (length form)

    assertEqual
        "buildGoogleTokenForm code key"
        (Just (TE.encodeUtf8 authCode))
        (lookup "code" form)

    assertEqual
        "buildGoogleTokenForm client_id key"
        (Just (TE.encodeUtf8 "test-client-id"))
        (lookup "client_id" form)

    assertEqual
        "buildGoogleTokenForm client_secret key"
        (Just (TE.encodeUtf8 "test-client-secret"))
        (lookup "client_secret" form)

    assertEqual
        "buildGoogleTokenForm redirect_uri key"
        (Just (TE.encodeUtf8 callbackUrl))
        (lookup "redirect_uri" form)

    assertEqual
        "buildGoogleTokenForm grant_type is authorization_code"
        (Just "authorization_code")
        (lookup "grant_type" form)
