{- | Google OAuth provider implementation.

Exchanges an authorization code for an access token, then fetches the
Google OpenID Connect userinfo endpoint to obtain a stable @sub@ and any
available profile data.

Discovery-document fetch is intentionally omitted for v0.1.  The two
endpoints used here are stable and documented by Google:
  - Token endpoint:   https://oauth2.googleapis.com/token
  - Userinfo endpoint: https://openidconnect.googleapis.com/v1/userinfo

TODO (#29): Replace hardcoded endpoint URLs with fetched discovery document
using @oauthProviderDiscoveryUrl@ from 'OAuthProviderConfig'.
-}
module Hauth.OAuth.Google (
    GoogleExchangeError (..),
    buildGoogleTokenForm,
    googleExchangeCode,
    googleProviderName,
    parseGoogleUserinfo,
) where

import Data.Aeson (Value (..))
import qualified Data.Aeson as Aeson
import qualified Data.Aeson.KeyMap as KeyMap
import qualified Data.ByteString as BS
import Data.Text (Text)
import qualified Data.Text as T
import qualified Data.Text.Encoding as TE
import Hauth.Config (OAuthProviderConfig (..))
import Hauth.OAuth (IdentityClaims (..))
import Network.HTTP.Client (
    Manager,
    httpLbs,
    newManager,
    parseRequest,
    requestHeaders,
    responseBody,
    responseStatus,
    setQueryString,
    urlEncodedBody,
 )
import Network.HTTP.Client.TLS (tlsManagerSettings)
import Network.HTTP.Types (status200)

-- | The canonical provider name string for Google OAuth.
googleProviderName :: Text
googleProviderName = "google"

-- | Errors that can occur during the Google OAuth code exchange flow.
data GoogleExchangeError
    = -- | An HTTP-level failure occurred (e.g. connection refused, non-2xx).
      GoogleHttpError Text
    | -- | The token endpoint returned a body that couldn't be parsed.
      GoogleTokenResponseInvalid Text
    | -- | The userinfo endpoint returned a body that couldn't be parsed.
      GoogleUserinfoInvalid Text
    | -- | The userinfo object was valid JSON but missing the required @sub@ field.
      GoogleMissingSub
    deriving stock (Eq, Show)

-- ---------------------------------------------------------------------------
-- Pure helpers
-- ---------------------------------------------------------------------------

{- | Build the @application/x-www-form-urlencoded@ body for the token endpoint.

All fields are required by Google's OAuth 2.0 token endpoint.
-}
buildGoogleTokenForm ::
    OAuthProviderConfig ->
    -- | Redirect URI (must match the one used in the authorization request).
    Text ->
    -- | Authorization code received from the callback.
    Text ->
    [(BS.ByteString, BS.ByteString)]
buildGoogleTokenForm OAuthProviderConfig{oauthProviderClientId, oauthProviderClientSecret} callbackUrl code =
    [ ("code", TE.encodeUtf8 code)
    , ("client_id", TE.encodeUtf8 oauthProviderClientId)
    , ("client_secret", TE.encodeUtf8 oauthProviderClientSecret)
    , ("redirect_uri", TE.encodeUtf8 callbackUrl)
    , ("grant_type", "authorization_code")
    ]

{- | Parse a Google userinfo JSON blob into 'IdentityClaims'.

Required field: @sub@ → 'identityProviderId'.
Optional field: @email@ → 'identityEmail'.
The entire 'Value' is stored as 'identityData'.
'identityProvider' is always set to 'googleProviderName'.
-}
parseGoogleUserinfo :: Aeson.Value -> Either GoogleExchangeError IdentityClaims
parseGoogleUserinfo val = case val of
    Object obj -> do
        sub <- case KeyMap.lookup "sub" obj of
            Just (String s) | not (T.null s) -> Right s
            Just _ -> Left GoogleMissingSub
            Nothing -> Left GoogleMissingSub
        let email = case KeyMap.lookup "email" obj of
                Just (String e) -> Just e
                _ -> Nothing
        Right
            IdentityClaims
                { identityProvider = googleProviderName
                , identityProviderId = sub
                , identityEmail = email
                , identityData = val
                }
    _ -> Left (GoogleUserinfoInvalid "userinfo response is not a JSON object")

-- ---------------------------------------------------------------------------
-- IO: code exchange
-- ---------------------------------------------------------------------------

{- | Exchange a Google authorization code for 'IdentityClaims'.

Steps:
  1. POST to @https://oauth2.googleapis.com/token@ with the authorization
     code and client credentials.
  2. Extract @access_token@ from the JSON response.
  3. GET @https://openidconnect.googleapis.com/v1/userinfo@ with the access
     token as a Bearer credential.
  4. Parse the userinfo JSON into 'IdentityClaims' via 'parseGoogleUserinfo'.

Note: @id_token@ is present in the response but we do not verify its
signature here.  The userinfo endpoint call provides equivalent information
with the benefit of being fetched from Google's servers on each login.

TODO (#29): Use @oauthProviderDiscoveryUrl@ to fetch the discovery document
and resolve the @token_endpoint@ and @userinfo_endpoint@ URLs dynamically
instead of hardcoding them.
-}
googleExchangeCode ::
    OAuthProviderConfig ->
    -- | Callback URL (redirect_uri used during authorization).
    Text ->
    -- | Authorization code from the callback query parameter.
    Text ->
    IO (Either GoogleExchangeError IdentityClaims)
googleExchangeCode providerCfg callbackUrl code = do
    manager <- newManager tlsManagerSettings
    tokenResult <- fetchGoogleToken manager providerCfg callbackUrl code
    case tokenResult of
        Left e -> pure (Left e)
        Right accessToken -> do
            userinfoResult <- fetchGoogleUserinfo manager accessToken
            case userinfoResult of
                Left e -> pure (Left e)
                Right jsonVal -> pure (parseGoogleUserinfo jsonVal)

-- ---------------------------------------------------------------------------
-- Internal IO helpers
-- ---------------------------------------------------------------------------

-- | POST to the Google token endpoint and extract the @access_token@.
fetchGoogleToken ::
    Manager ->
    OAuthProviderConfig ->
    Text ->
    Text ->
    IO (Either GoogleExchangeError Text)
fetchGoogleToken manager providerCfg callbackUrl code = do
    let formPairs = buildGoogleTokenForm providerCfg callbackUrl code
    initReq <- parseRequest "POST https://oauth2.googleapis.com/token"
    let req =
            urlEncodedBody formPairs $
                initReq
                    { requestHeaders =
                        [ ("Accept", "application/json")
                        ]
                    }
    response <- httpLbs req manager
    let status = responseStatus response
    if status /= status200
        then
            pure
                ( Left
                    ( GoogleHttpError
                        ( "token endpoint returned status: "
                            <> T.pack (show status)
                        )
                    )
                )
        else case Aeson.decode (responseBody response) of
            Nothing ->
                pure (Left (GoogleTokenResponseInvalid "could not parse token endpoint JSON"))
            Just (Object obj) ->
                case KeyMap.lookup "access_token" obj of
                    Just (String tok) -> pure (Right tok)
                    _ ->
                        pure
                            ( Left
                                ( GoogleTokenResponseInvalid
                                    "token endpoint response missing access_token"
                                )
                            )
            Just _ ->
                pure (Left (GoogleTokenResponseInvalid "token endpoint response is not a JSON object"))

-- | GET the Google userinfo endpoint using a Bearer access token.
fetchGoogleUserinfo ::
    Manager ->
    Text ->
    IO (Either GoogleExchangeError Aeson.Value)
fetchGoogleUserinfo manager accessToken = do
    initReq <- parseRequest "GET https://openidconnect.googleapis.com/v1/userinfo"
    let req =
            initReq
                { requestHeaders =
                    [ ("Authorization", "Bearer " <> TE.encodeUtf8 accessToken)
                    , ("Accept", "application/json")
                    ]
                }
        -- Suppress any default query-string; setQueryString with empty list is a no-op
        req' = setQueryString [] req
    response <- httpLbs req' manager
    let status = responseStatus response
    if status /= status200
        then
            pure
                ( Left
                    ( GoogleHttpError
                        ( "userinfo endpoint returned status: "
                            <> T.pack (show status)
                        )
                    )
                )
        else case Aeson.decode (responseBody response) of
            Nothing ->
                pure (Left (GoogleUserinfoInvalid "could not parse userinfo endpoint JSON"))
            Just val ->
                pure (Right val)
