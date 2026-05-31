{- | GitHub OAuth App code-exchange and user-info helpers.

Implements the three-step flow:

1. POST to @https://github.com/login/oauth/access_token@ to exchange a code
   for an access token.
2. GET @https://api.github.com/user@ to fetch the user profile.
3. GET @https://api.github.com/user/emails@ to resolve the primary verified
   email (GitHub's @\/user@ endpoint may return a null email for users who
   keep it private).

References:
 - https://docs.github.com/en/apps/oauth-apps/building-oauth-apps/authorizing-oauth-apps
-}
module Hauth.OAuth.Github (
    GithubExchangeError (..),
    buildGithubTokenForm,
    githubExchangeCode,
    githubProviderName,
    parseGithubEmails,
    parseGithubUser,
    pickPrimaryEmail,
) where

import Control.Applicative ((<|>))
import Data.Aeson (Value (..))
import qualified Data.Aeson as Aeson
import qualified Data.Aeson.KeyMap as KeyMap
import qualified Data.ByteString as BS
import Data.Foldable (toList)
import Data.Text (Text)
import qualified Data.Text as T
import qualified Data.Text.Encoding as TE
import Hauth.Config (OAuthProviderConfig (..))
import Hauth.OAuth (IdentityClaims (..))
import Network.HTTP.Client (
    Manager,
    Request (..),
    httpLbs,
    newManager,
    parseRequest,
    responseBody,
    responseStatus,
    urlEncodedBody,
 )
import Network.HTTP.Client.TLS (tlsManagerSettings)
import Network.HTTP.Types.Status (statusCode)

-- ---------------------------------------------------------------------------
-- Public constants
-- ---------------------------------------------------------------------------

-- | The literal provider name used in flow state and identity rows.
githubProviderName :: Text
githubProviderName = "github"

-- ---------------------------------------------------------------------------
-- Error type
-- ---------------------------------------------------------------------------

-- | Errors that can occur during the GitHub OAuth code-exchange flow.
data GithubExchangeError
    = -- | An HTTP request failed (network error or non-2xx response).
      GithubHttpError Text
    | -- | The token endpoint response could not be parsed.
      GithubTokenResponseInvalid Text
    | -- | The @\/user@ response could not be parsed.
      GithubUserInvalid Text
    | -- | The @\/user\/emails@ response could not be parsed.
      GithubEmailsInvalid Text
    | -- | The @\/user@ response was valid JSON but had no @id@ field.
      GithubMissingId
    deriving stock (Eq, Show)

-- ---------------------------------------------------------------------------
-- Pure helpers
-- ---------------------------------------------------------------------------

{- | Build the URL-encoded form body for the access-token request.

Returns pairs suitable for 'urlEncodedBody'.
-}
buildGithubTokenForm ::
    OAuthProviderConfig ->
    -- | Callback URL (@redirect_uri@).
    Text ->
    -- | Authorization code from GitHub.
    Text ->
    [(BS.ByteString, BS.ByteString)]
buildGithubTokenForm OAuthProviderConfig{oauthProviderClientId, oauthProviderClientSecret} callbackUrl code =
    [ ("client_id", TE.encodeUtf8 oauthProviderClientId)
    , ("client_secret", TE.encodeUtf8 oauthProviderClientSecret)
    , ("code", TE.encodeUtf8 code)
    , ("redirect_uri", TE.encodeUtf8 callbackUrl)
    ]

{- | Parse the GitHub @\/user@ response into a @(provider_id, maybe_email)@ pair.

The @id@ field is a JSON number; we convert it to text via @show . round@.
The @email@ field may be missing or null; we return 'Nothing' in both cases.

Returns 'Left' 'GithubMissingId' when the @id@ field is absent, and
'Left' ('GithubUserInvalid' msg) when it is present but not a number or
the top-level value is not an object.
-}
parseGithubUser :: Value -> Either GithubExchangeError (Text, Maybe Text)
parseGithubUser (Object obj) = do
    pid <- case KeyMap.lookup "id" obj of
        Just (Number n) ->
            Right (T.pack (show (round n :: Integer)))
        Just _ ->
            Left (GithubUserInvalid "id field is not a number")
        Nothing ->
            Left GithubMissingId
    let mEmail = case KeyMap.lookup "email" obj of
            Just (String e) | not (T.null e) -> Just e
            _ -> Nothing
    Right (pid, mEmail)
parseGithubUser _ = Left (GithubUserInvalid "expected a JSON object")

{- | Parse the GitHub @\/user\/emails@ response.

Returns @[(email, primary, verified)]@ on success.
-}
parseGithubEmails :: Value -> Either GithubExchangeError [(Text, Bool, Bool)]
parseGithubEmails (Array arr) =
    traverse parseEmailEntry (toList arr)
  where
    parseEmailEntry (Object obj) = do
        email <- case KeyMap.lookup "email" obj of
            Just (String e) -> Right e
            _ -> Left (GithubEmailsInvalid "email field missing or not a string")
        let primary = case KeyMap.lookup "primary" obj of
                Just (Bool b) -> b
                _ -> False
            verified = case KeyMap.lookup "verified" obj of
                Just (Bool b) -> b
                _ -> False
        Right (email, primary, verified)
    parseEmailEntry _ =
        Left (GithubEmailsInvalid "expected email entry to be a JSON object")
parseGithubEmails _ = Left (GithubEmailsInvalid "expected a JSON array")

{- | Pick the best email from a list of @(email, primary, verified)@ tuples.

Selection priority:

1. The entry where @primary == True && verified == True@.
2. The first entry where @verified == True@.
3. 'Nothing' when no verified email exists.
-}
pickPrimaryEmail :: [(Text, Bool, Bool)] -> Maybe Text
pickPrimaryEmail entries =
    case filter (\(_, p, v) -> p && v) entries of
        ((e, _, _) : _) -> Just e
        [] ->
            case filter (\(_, _, v) -> v) entries of
                ((e, _, _) : _) -> Just e
                [] -> Nothing

-- ---------------------------------------------------------------------------
-- IO: code exchange
-- ---------------------------------------------------------------------------

{- | Exchange a GitHub authorization code for an 'IdentityClaims' record.

Steps:

1. POST to @https://github.com/login/oauth/access_token@ (JSON accept header).
2. Parse @access_token@ from the response.
3. GET @https://api.github.com/user@.
4. GET @https://api.github.com/user/emails@.
5. Assemble 'IdentityClaims'.
-}
githubExchangeCode ::
    OAuthProviderConfig ->
    -- | Callback URL (@redirect_uri@).
    Text ->
    -- | Authorization code from the OAuth callback.
    Text ->
    IO (Either GithubExchangeError IdentityClaims)
githubExchangeCode cfg callbackUrl code = do
    manager <- newManager tlsManagerSettings
    tokenResult <- fetchAccessToken manager cfg callbackUrl code
    case tokenResult of
        Left err -> pure (Left err)
        Right accessToken -> do
            userResult <- fetchGithubUser manager accessToken
            case userResult of
                Left err -> pure (Left err)
                Right userVal -> do
                    emailsResult <- fetchGithubEmails manager accessToken
                    case emailsResult of
                        Left err -> pure (Left err)
                        Right emailsVal ->
                            pure (buildClaims userVal emailsVal)

-- ---------------------------------------------------------------------------
-- Internal IO helpers
-- ---------------------------------------------------------------------------

fetchAccessToken ::
    Manager ->
    OAuthProviderConfig ->
    Text ->
    Text ->
    IO (Either GithubExchangeError Text)
fetchAccessToken manager cfg callbackUrl code = do
    initReq <- parseRequest "https://github.com/login/oauth/access_token"
    let formPairs = buildGithubTokenForm cfg callbackUrl code
        req =
            (urlEncodedBody formPairs initReq)
                { requestHeaders =
                    [ ("Accept", "application/json")
                    , ("User-Agent", "hauth")
                    ]
                , method = "POST"
                }
    resp <- httpLbs req manager
    let status = statusCode (responseStatus resp)
        body = responseBody resp
    if status < 200 || status >= 300
        then
            pure $
                Left $
                    GithubHttpError $
                        "token endpoint returned status "
                            <> T.pack (show status)
        else case Aeson.decode body of
            Nothing ->
                pure $
                    Left $
                        GithubTokenResponseInvalid "could not parse token response as JSON"
            Just (Object obj) ->
                case KeyMap.lookup "access_token" obj of
                    Just (String t) -> pure (Right t)
                    _ ->
                        pure $
                            Left $
                                GithubTokenResponseInvalid "access_token field missing or not a string"
            Just _ ->
                pure $
                    Left $
                        GithubTokenResponseInvalid "token response is not a JSON object"

fetchGithubUser ::
    Manager ->
    Text ->
    IO (Either GithubExchangeError Value)
fetchGithubUser manager accessToken = do
    initReq <- parseRequest "https://api.github.com/user"
    let req =
            initReq
                { requestHeaders =
                    [ ("Authorization", "Bearer " <> TE.encodeUtf8 accessToken)
                    , ("User-Agent", "hauth")
                    , ("Accept", "application/json")
                    ]
                }
    resp <- httpLbs req manager
    let status = statusCode (responseStatus resp)
        body = responseBody resp
    if status < 200 || status >= 300
        then
            pure $
                Left $
                    GithubHttpError $
                        "user endpoint returned status "
                            <> T.pack (show status)
        else case Aeson.decode body of
            Nothing ->
                pure $
                    Left $
                        GithubUserInvalid "could not parse user response as JSON"
            Just val ->
                pure (Right val)

fetchGithubEmails ::
    Manager ->
    Text ->
    IO (Either GithubExchangeError Value)
fetchGithubEmails manager accessToken = do
    initReq <- parseRequest "https://api.github.com/user/emails"
    let req =
            initReq
                { requestHeaders =
                    [ ("Authorization", "Bearer " <> TE.encodeUtf8 accessToken)
                    , ("User-Agent", "hauth")
                    , ("Accept", "application/json")
                    ]
                }
    resp <- httpLbs req manager
    let status = statusCode (responseStatus resp)
        body = responseBody resp
    if status < 200 || status >= 300
        then
            pure $
                Left $
                    GithubHttpError $
                        "emails endpoint returned status "
                            <> T.pack (show status)
        else case Aeson.decode body of
            Nothing ->
                pure $
                    Left $
                        GithubEmailsInvalid "could not parse emails response as JSON"
            Just val ->
                pure (Right val)

-- ---------------------------------------------------------------------------
-- Internal pure assembly
-- ---------------------------------------------------------------------------

buildClaims ::
    Value ->
    Value ->
    Either GithubExchangeError IdentityClaims
buildClaims userVal emailsVal = do
    (pid, mEmailFromUser) <- parseGithubUser userVal
    emailEntries <- parseGithubEmails emailsVal
    let mEmail = pickPrimaryEmail emailEntries <|> mEmailFromUser
        identityData = mergeUserAndEmails userVal emailsVal
    Right
        IdentityClaims
            { identityProvider = githubProviderName
            , identityProviderId = pid
            , identityEmail = mEmail
            , identityData = identityData
            }

-- | Merge user and emails JSON into a single object for @identity_data@.
mergeUserAndEmails :: Value -> Value -> Value
mergeUserAndEmails (Object userObj) emailsVal =
    Object $
        KeyMap.insert "emails" emailsVal userObj
mergeUserAndEmails userVal _ = userVal
