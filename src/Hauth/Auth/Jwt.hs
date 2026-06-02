{- | JWT signing and validation for Supabase-compatible access tokens.

Implements HS256 (HMAC-SHA256) compact JWTs with the Supabase Auth claim
shape so existing Postgres RLS policies and PostgREST integrations keep
working without changes.
-}
module Hauth.Auth.Jwt (
    AccessTokenClaims (..),
    AmrEntry (..),
    JwtError (..),
    applyOverlay,
    issueAccessToken,
    signAccessToken,
    validateAccessToken,
) where

import Control.Exception (SomeException, try)
import Crypto.Hash (SHA256)
import Crypto.MAC.HMAC (HMAC, hmac, hmacGetDigest)
import Data.Aeson (
    FromJSON (..),
    Object,
    Result (..),
    ToJSON (..),
    Value (..),
    fromJSON,
    object,
    withObject,
    (.:),
    (.=),
 )
import qualified Data.Aeson as Aeson
import Data.Aeson.Key (fromText)
import qualified Data.Aeson.KeyMap as KeyMap
import Data.ByteArray (constEq, convert)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Base64.URL as B64URL
import qualified Data.ByteString.Lazy as BSL
import Data.Scientific (floatingOrInteger)
import Data.Text (Text)
import qualified Data.Text as T
import qualified Data.Text.Encoding as TE
import Data.Time.Clock (UTCTime, getCurrentTime)
import Data.Time.Clock.POSIX (POSIXTime, posixSecondsToUTCTime, utcTimeToPOSIXSeconds)
import Hauth.Config (Config (..), JwtConfig (..))
import Hauth.Env (AppEnv (..), withDatabaseConnection)
import Hauth.Hooks.Runner (HookDecision (..), runHook)
import Hauth.Hooks.Types (HookConfig, HookPoint (..), loadHookConfig)

-- | A single entry in the Authentication Methods References claim array.
data AmrEntry = AmrEntry
    { amrMethod :: Text
    -- ^ Authentication method, e.g. @"password"@, @"oauth"@, @"totp"@.
    , amrTimestamp :: Integer
    -- ^ Unix epoch seconds when the method was applied.
    }
    deriving stock (Eq, Show)

instance ToJSON AmrEntry where
    toJSON AmrEntry{amrMethod, amrTimestamp} =
        object
            [ "method" .= amrMethod
            , "timestamp" .= amrTimestamp
            ]

instance FromJSON AmrEntry where
    parseJSON = withObject "AmrEntry" \o ->
        AmrEntry
            <$> o .: "method"
            <*> o .: "timestamp"

-- | Claims carried in a Supabase-compatible access token.
data AccessTokenClaims = AccessTokenClaims
    { claimSub :: Text
    -- ^ User UUID (@sub@).
    , claimRole :: Text
    -- ^ Postgres role, e.g. @"authenticated"@.
    , claimEmail :: Maybe Text
    -- ^ User email address; omitted when not present.
    , claimPhone :: Maybe Text
    -- ^ User phone number; omitted when not present.
    , claimAppMetadata :: Value
    -- ^ Server-controlled metadata object.
    , claimUserMetadata :: Value
    -- ^ User-controlled metadata object.
    , claimAal :: Text
    -- ^ Authenticator Assurance Level: @"aal1"@ or @"aal2"@.
    , claimAmr :: [AmrEntry]
    -- ^ Authentication methods used in this session.
    , claimSessionId :: Text
    -- ^ Session UUID (@session_id@).
    , claimIssuedAt :: UTCTime
    -- ^ Token issue time (@iat@).
    , claimExpiresAt :: UTCTime
    -- ^ Token expiry time (@exp@).
    }
    deriving stock (Eq, Show)

-- | Errors that can occur during JWT signing or validation.
data JwtError
    = -- | A claim value prevented signing (e.g. negative timestamp).
      JwtSignError String
    | -- | Signature invalid, token malformed, or token expired.
      JwtVerifyError String
    | -- | A required claim is missing or has the wrong type.
      JwtClaimError String
    deriving stock (Eq, Show)

-- ---------------------------------------------------------------------------
-- Signing
-- ---------------------------------------------------------------------------

{- | Sign an access token using HS256 with the configured secret.

Embeds @iss@ and @aud@ from 'JwtConfig', plus all Supabase-required extra
claims. Returns the compact JWT text.
-}
signAccessToken :: JwtConfig -> AccessTokenClaims -> IO (Either JwtError Text)
signAccessToken JwtConfig{jwtSecret, jwtIssuer, jwtAudience} claims = do
    let iatSeconds = floor (utcTimeToPOSIXSeconds (claimIssuedAt claims)) :: Integer
        expSeconds = floor (utcTimeToPOSIXSeconds (claimExpiresAt claims)) :: Integer
        payload = buildPayload jwtIssuer jwtAudience iatSeconds expSeconds claims
        headerJson = "{\"alg\":\"HS256\",\"typ\":\"JWT\"}"
        headerB64 = base64urlEncode (TE.encodeUtf8 headerJson)
        payloadB64 = base64urlEncode (BSL.toStrict (Aeson.encode payload))
        signingInput = headerB64 <> "." <> payloadB64
        sig = computeHmac256 jwtSecret signingInput
        token = signingInput <> "." <> sig
    pure (Right token)

{- | Issue an access token, applying the custom-access-token hook if configured.

Only @app_metadata@ and @user_metadata@ from the hook overlay are merged into
the claims. Security-sensitive claims (@sub@, @role@, @exp@, @iat@, etc.) are
immutable. A @HookReject@ surfaces as @Left (JwtSignError "token_issuance_blocked: <reason>")@.
-}
issueAccessToken :: AppEnv -> AccessTokenClaims -> IO (Either JwtError Text)
issueAccessToken env claims = do
    let AppEnv{appConfig} = env
        Config{configJwt} = appConfig
    mCfg <- tryLoadHookConfig env
    case mCfg of
        Nothing -> signAccessToken configJwt claims
        Just hookCfg -> do
            let payload = buildHookPayload claims
            decision <- runHook hookCfg payload
            case decision of
                HookAllow ->
                    signAccessToken configJwt claims
                HookAllowWith overlay ->
                    signAccessToken configJwt (applyOverlay claims overlay)
                HookReject reason ->
                    pure (Left (JwtSignError ("token_issuance_blocked: " <> T.unpack reason)))

-- | Load the custom-access-token hook config, returning Nothing on DB error.
tryLoadHookConfig :: AppEnv -> IO (Maybe HookConfig)
tryLoadHookConfig env = do
    result <- try (withDatabaseConnection env (`loadHookConfig` HookCustomAccessToken))
    pure $ case (result :: Either SomeException (Maybe HookConfig)) of
        Left _ -> Nothing
        Right v -> v

-- | Build the hook payload for a custom-access-token invocation.
buildHookPayload :: AccessTokenClaims -> Aeson.Value
buildHookPayload claims =
    Aeson.object
        [ "claims" Aeson..= claimsToValue claims
        , "user_id" Aeson..= claimSub claims
        , "session_id" Aeson..= claimSessionId claims
        , "aal" Aeson..= claimAal claims
        ]

-- | Encode the proposed claims as a JSON object for the hook payload.
claimsToValue :: AccessTokenClaims -> Aeson.Value
claimsToValue AccessTokenClaims{..} =
    Aeson.object
        ( [ "sub" Aeson..= claimSub
          , "role" Aeson..= claimRole
          , "aal" Aeson..= claimAal
          , "session_id" Aeson..= claimSessionId
          , "app_metadata" Aeson..= claimAppMetadata
          , "user_metadata" Aeson..= claimUserMetadata
          ]
            ++ maybe [] (\e -> ["email" Aeson..= e]) claimEmail
            ++ maybe [] (\p -> ["phone" Aeson..= p]) claimPhone
        )

-- | Merge only @app_metadata@ and @user_metadata@ from the overlay into claims.
applyOverlay :: AccessTokenClaims -> Aeson.Value -> AccessTokenClaims
applyOverlay claims (Aeson.Object o) =
    claims
        { claimAppMetadata = mergeObjects (claimAppMetadata claims) (KeyMap.lookup (fromText "app_metadata") o)
        , claimUserMetadata = mergeObjects (claimUserMetadata claims) (KeyMap.lookup (fromText "user_metadata") o)
        }
applyOverlay claims _ = claims

-- | Merge overlay object into base; overlay wins on key conflicts.
mergeObjects :: Value -> Maybe Value -> Value
mergeObjects base Nothing = base
mergeObjects base (Just (Aeson.Object overlayObj)) =
    case base of
        Aeson.Object baseObj -> Aeson.Object (KeyMap.unionWith mergeValues baseObj overlayObj)
        _ -> Aeson.Object overlayObj
mergeObjects _ (Just v) = v

mergeValues :: Value -> Value -> Value
mergeValues (Aeson.Object b) (Aeson.Object o) = Aeson.Object (KeyMap.unionWith mergeValues b o)
mergeValues _ overlay = overlay

-- | Build the full JSON claims object for signing.
buildPayload :: Text -> Text -> Integer -> Integer -> AccessTokenClaims -> Object
buildPayload issuer audience iatSecs expSecs AccessTokenClaims{..} =
    KeyMap.fromList $
        [ (fromText "iss", String issuer)
        , (fromText "sub", String claimSub)
        , (fromText "aud", String audience)
        , (fromText "iat", Number (fromInteger iatSecs))
        , (fromText "exp", Number (fromInteger expSecs))
        , (fromText "role", String claimRole)
        , (fromText "aal", String claimAal)
        , (fromText "amr", toJSON claimAmr)
        , (fromText "session_id", String claimSessionId)
        , (fromText "app_metadata", claimAppMetadata)
        , (fromText "user_metadata", claimUserMetadata)
        ]
            ++ maybe [] (\e -> [(fromText "email", String e)]) claimEmail
            ++ maybe [] (\p -> [(fromText "phone", String p)]) claimPhone

-- ---------------------------------------------------------------------------
-- Validation
-- ---------------------------------------------------------------------------

{- | Verify an access token: signature, @iss@, @aud@, and @exp@.

Returns the parsed 'AccessTokenClaims' on success.
-}
validateAccessToken :: JwtConfig -> Text -> IO (Either JwtError AccessTokenClaims)
validateAccessToken cfg@JwtConfig{jwtSecret} token = do
    now <- fmap utcTimeToPOSIXSeconds getCurrentTime
    pure case T.splitOn "." token of
        [headerB64, payloadB64, sigB64] ->
            let signingInput = headerB64 <> "." <> payloadB64
                expectedSig = computeHmac256 jwtSecret signingInput
                -- Constant-time compare on the encoded bytes. constEq fast-exits
                -- on length mismatch (which is fine — different length means
                -- malformed token, no secret-dependent timing leak).
                sigOk = constEq (TE.encodeUtf8 sigB64) (TE.encodeUtf8 expectedSig)
             in if not sigOk
                    then Left (JwtVerifyError "signature verification failed")
                    else do
                        -- Signature is verified — only NOW do we trust the header
                        -- enough to parse it. Header policy is enforced after the
                        -- sig check to avoid leaking parser timing on un-authenticated
                        -- input.
                        validateHeader headerB64
                        payloadBytes <- decodeBase64url payloadB64
                        obj <- parsePayloadJson payloadBytes
                        extractClaims cfg now obj
        _ -> Left (JwtVerifyError "malformed token: expected 3 dot-separated segments")

{- | Decode the JOSE header and enforce algorithm policy: @alg@ MUST be
@HS256@; if @typ@ is present it MUST be @JWT@. This is defence-in-depth on
top of the HMAC verification: the signature already binds the header bytes,
but rejecting non-HS256 explicitly forecloses any future code path that
might dispatch on @alg@ and accidentally accept @none@ or an asymmetric
algorithm.
-}
validateHeader :: Text -> Either JwtError ()
validateHeader headerB64 = do
    bytes <- decodeBase64url headerB64
    hdr <- case Aeson.decodeStrict' bytes of
        Just (Object o) -> Right o
        Just _ -> Left (JwtVerifyError "malformed header: not a JSON object")
        Nothing -> Left (JwtVerifyError "malformed header: not valid JSON")
    case KeyMap.lookup (fromText "alg") hdr of
        Just (String "HS256") -> pure ()
        Just (String other) ->
            Left (JwtVerifyError ("unsupported alg: " <> T.unpack other))
        Just _ ->
            Left (JwtVerifyError "header alg is not a string")
        Nothing ->
            Left (JwtVerifyError "missing alg in header")
    case KeyMap.lookup (fromText "typ") hdr of
        Nothing -> pure () -- typ is optional per RFC 7519 §5.1
        Just (String "JWT") -> pure ()
        Just (String other) ->
            Left (JwtVerifyError ("unsupported typ: " <> T.unpack other))
        Just _ ->
            Left (JwtVerifyError "header typ is not a string")

-- | Parse the JSON payload from raw bytes.
parsePayloadJson :: BS.ByteString -> Either JwtError Object
parsePayloadJson bytes =
    case Aeson.decodeStrict' bytes of
        Nothing -> Left (JwtVerifyError "malformed payload: not valid JSON")
        Just (Object obj) -> Right obj
        Just _ -> Left (JwtVerifyError "malformed payload: not a JSON object")

-- | Extract and validate all claims from the decoded payload object.
extractClaims :: JwtConfig -> POSIXTime -> Object -> Either JwtError AccessTokenClaims
extractClaims JwtConfig{jwtIssuer, jwtAudience} now obj = do
    -- Registered claims
    issText <- requireText obj "iss"
    if issText /= jwtIssuer
        then Left (JwtClaimError ("iss mismatch: got " <> T.unpack issText))
        else Right ()

    audText <- requireText obj "aud"
    if audText /= jwtAudience
        then Left (JwtClaimError ("aud mismatch: got " <> T.unpack audText))
        else Right ()

    expSecs <- requireInteger obj "exp"
    if fromInteger expSecs <= now
        then Left (JwtVerifyError "token has expired")
        else Right ()

    iatSecs <- requireInteger obj "iat"
    subText <- requireText obj "sub"

    -- Extra claims
    roleText <- requireText obj "role"
    let emailVal = lookupText obj "email"
    let phoneVal = lookupText obj "phone"
    appMeta <- requireValue obj "app_metadata"
    userMeta <- requireValue obj "user_metadata"
    aalText <- requireText obj "aal"
    amrEntries <- requireAmr obj "amr"
    sessionId <- requireText obj "session_id"

    Right
        AccessTokenClaims
            { claimSub = subText
            , claimRole = roleText
            , claimEmail = emailVal
            , claimPhone = phoneVal
            , claimAppMetadata = appMeta
            , claimUserMetadata = userMeta
            , claimAal = aalText
            , claimAmr = amrEntries
            , claimSessionId = sessionId
            , claimIssuedAt = posixSecondsToUTCTime (fromInteger iatSecs)
            , claimExpiresAt = posixSecondsToUTCTime (fromInteger expSecs)
            }

-- ---------------------------------------------------------------------------
-- Claim helpers
-- ---------------------------------------------------------------------------

requireText :: Object -> Text -> Either JwtError Text
requireText obj key =
    case KeyMap.lookup (fromText key) obj of
        Nothing -> Left (JwtClaimError ("missing claim: " <> T.unpack key))
        Just (String t) -> Right t
        Just _ -> Left (JwtClaimError ("claim is not a string: " <> T.unpack key))

lookupText :: Object -> Text -> Maybe Text
lookupText obj key =
    case KeyMap.lookup (fromText key) obj of
        Just (String t) -> Just t
        _ -> Nothing

requireInteger :: Object -> Text -> Either JwtError Integer
requireInteger obj key =
    case KeyMap.lookup (fromText key) obj of
        Nothing -> Left (JwtClaimError ("missing claim: " <> T.unpack key))
        -- RFC 7519 §2 NumericDate is "a JSON numeric value representing the
        -- number of seconds from 1970-01-01T00:00:00Z UTC". Fractional values
        -- are allowed by the RFC but are a foot-gun across verifier languages
        -- (rounding/truncation differences) — reject them here so the wire
        -- contract is unambiguous.
        Just (Number n) -> case floatingOrInteger n :: Either Double Integer of
            Right i -> Right i
            Left _ -> Left (JwtClaimError ("claim is not an integer: " <> T.unpack key))
        Just _ -> Left (JwtClaimError ("claim is not a number: " <> T.unpack key))

requireValue :: Object -> Text -> Either JwtError Value
requireValue obj key =
    case KeyMap.lookup (fromText key) obj of
        Nothing -> Left (JwtClaimError ("missing claim: " <> T.unpack key))
        Just v -> Right v

requireAmr :: Object -> Text -> Either JwtError [AmrEntry]
requireAmr obj key =
    case KeyMap.lookup (fromText key) obj of
        Nothing -> Left (JwtClaimError ("missing claim: " <> T.unpack key))
        Just v ->
            case fromJSON v of
                Error e -> Left (JwtClaimError ("failed to parse amr: " <> e))
                Success entries -> Right entries

-- ---------------------------------------------------------------------------
-- Crypto helpers
-- ---------------------------------------------------------------------------

{- | Compute HMAC-SHA256 over @signingInput@ using @secret@ as the key,
returning a base64url-encoded (unpadded) result.
-}
computeHmac256 :: Text -> Text -> Text
computeHmac256 secret signingInput =
    let key = TE.encodeUtf8 secret
        msg = TE.encodeUtf8 signingInput
        mac = hmac key msg :: HMAC SHA256
        digest = convert (hmacGetDigest mac) :: BS.ByteString
     in base64urlEncode digest

-- | Base64url-encode a strict 'ByteString', stripping padding @=@.
base64urlEncode :: BS.ByteString -> Text
base64urlEncode = TE.decodeUtf8 . stripPadding . B64URL.encode
  where
    stripPadding = BS.filter (/= 61) -- 61 == ord '='

-- | Base64url-decode a text segment (with or without padding).
decodeBase64url :: Text -> Either JwtError BS.ByteString
decodeBase64url t =
    case B64URL.decode padded of
        Left e -> Left (JwtVerifyError ("base64url decode failed: " <> e))
        Right bs -> Right bs
  where
    raw = TE.encodeUtf8 t
    rem4 = BS.length raw `mod` 4
    padding = if rem4 == 0 then 0 else 4 - rem4
    padded = raw <> BS.replicate padding 61
