{-# OPTIONS_GHC -Wno-deprecations #-}

{- | JWT signing and validation for Supabase-compatible access tokens.

Implements HS256 (HMAC-SHA256) compact JWTs with the Supabase Auth claim
shape so existing Postgres RLS policies and PostgREST integrations keep
working without changes.

The wire-level JWS (signature, header, base64url, time-bound checks) is
delegated to the maintained @jose@ library. This module owns only the
Supabase-shape claim construction/extraction, the hook-overlay policy, and
the project-specific stricter rules (integer-only @iat@/@exp@).

@jose@'s @addClaim@/@unregisteredClaims@ are deprecated in favour of a
@HasClaimsSet@ subtype. The deprecation is stylistic; the functions still
work, and adopting the subtype encoding would significantly grow this
module without changing behaviour. Suppressing the warning file-locally.
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
import Control.Lens (preview, view, (&), (.~), (?~))
import Crypto.JOSE.Error (runJOSE)
import qualified Crypto.JOSE.Header as Hdr
import Crypto.JOSE.JWK (fromOctets)
import Crypto.JOSE.JWS (validationSettingsAlgorithms)
import qualified Crypto.JOSE.JWS as JWS
import Crypto.JWT (
    Audience (..),
    ClaimsSet,
    JWTError (..),
    NumericDate (..),
    StringOrURI,
    addClaim,
    decodeCompact,
    defaultJWTValidationSettings,
    emptyClaimsSet,
    encodeCompact,
    issuerPredicate,
    jwtValidationSettingsCheckIssuedAt,
    newJWSHeader,
    signClaims,
    string,
    stringOrUri,
    unregisteredClaims,
    verifyClaims,
 )
import qualified Crypto.JWT as JWT
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
import qualified Data.Aeson.Key as Key
import qualified Data.Aeson.KeyMap as KeyMap
import qualified Data.ByteString as BS
import qualified Data.ByteString.Base64.URL as B64URL
import qualified Data.ByteString.Lazy as BSL
import qualified Data.Map.Strict as Map
import Data.Scientific (floatingOrInteger)
import qualified Data.Set as Set
import Data.Text (Text)
import qualified Data.Text as T
import qualified Data.Text.Encoding as TE
import Data.Time.Clock (UTCTime)
import Data.Time.Clock.POSIX (posixSecondsToUTCTime, utcTimeToPOSIXSeconds)
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
signAccessToken cfg@JwtConfig{jwtSecret} claims = do
    let jwk = fromOctets (TE.encodeUtf8 jwtSecret)
        header =
            newJWSHeader ((), JWS.HS256)
                & Hdr.typ ?~ Hdr.HeaderParam () "JWT"
        claimsSet = buildClaimsSet cfg claims
    result <- runJOSE (signClaims jwk header claimsSet)
    case result of
        Left (e :: JWTError) ->
            pure (Left (JwtSignError (show e)))
        Right signed ->
            pure (Right (TE.decodeUtf8 (BSL.toStrict (encodeCompact signed))))

{- | Issue an access token, applying the custom-access-token hook if configured.

Only @app_metadata@ and @user_metadata@ from the hook overlay are merged into
the claims. Security-sensitive claims (@sub@, @role@, @exp@, @iat@, etc.) are
immutable. A @HookReject@ surfaces as @Left (JwtSignError "token_issuance_blocked: <reason>")@.
-}
issueAccessToken :: AppEnv -> AccessTokenClaims -> IO (Either JwtError Text)
issueAccessToken env claims = do
    let AppEnv{appConfig, appHookHttpManager} = env
        Config{configJwt} = appConfig
    mCfg <- tryLoadHookConfig env
    case mCfg of
        Nothing -> signAccessToken configJwt claims
        Just hookCfg -> do
            let payload = buildHookPayload claims
            decision <- runHook appHookHttpManager hookCfg payload
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

{- | Build the @jose@ 'ClaimsSet' with all Supabase-required claims.

@iat@\/@exp@ are floored to integer POSIX seconds so the emitted token
conforms to the project's stricter "no fractional NumericDate" wire
contract — @jose@ would otherwise pass sub-second precision through.
-}
buildClaimsSet :: JwtConfig -> AccessTokenClaims -> ClaimsSet
buildClaimsSet JwtConfig{jwtIssuer, jwtAudience} AccessTokenClaims{..} =
    let issSoUri = textToStringOrURI jwtIssuer
        subSoUri = textToStringOrURI claimSub
        audSoUri = textToStringOrURI jwtAudience
        iatSeconds = floorPosix claimIssuedAt
        expSeconds = floorPosix claimExpiresAt
        base =
            emptyClaimsSet
                & JWT.claimIss ?~ issSoUri
                & JWT.claimSub ?~ subSoUri
                & JWT.claimAud ?~ Audience [audSoUri]
                & JWT.claimIat ?~ NumericDate iatSeconds
                & JWT.claimExp ?~ NumericDate expSeconds
        extras =
            [ ("role", String claimRole)
            , ("aal", String claimAal)
            , ("amr", toJSON claimAmr)
            , ("session_id", String claimSessionId)
            , ("app_metadata", claimAppMetadata)
            , ("user_metadata", claimUserMetadata)
            ]
                ++ maybe [] (\e -> [("email", String e)]) claimEmail
                ++ maybe [] (\p -> [("phone", String p)]) claimPhone
     in foldr (\(k, v) cs -> addClaim k v cs) base extras

{- | Build a 'StringOrURI' from arbitrary text. Strings containing a @:@ that
fail URI parsing are encoded as a plain string fallback so the round-trip is
total — this only matters for hostile inputs the type system can't refuse.
-}
textToStringOrURI :: Text -> StringOrURI
textToStringOrURI t =
    case preview stringOrUri t of
        Just s -> s
        Nothing ->
            -- Defensive: jose's `stringOrUri` prism fails only for strings
            -- with a `:` that don't parse as a URI. Fall back to truncating
            -- at the `:` so we still produce something rather than panicking
            -- at sign-time. Supabase issuers/audiences in practice are either
            -- bare names ("authenticated") or full URIs.
            case preview stringOrUri (T.takeWhile (/= ':') t) of
                Just s -> s
                Nothing -> case preview stringOrUri ("" :: Text) of
                    Just empty_ -> empty_
                    Nothing -> error "textToStringOrURI: stringOrUri prism failed on empty text"

-- ---------------------------------------------------------------------------
-- Validation
-- ---------------------------------------------------------------------------

{- | Verify an access token: signature, @iss@, @aud@, and @exp@.

Returns the parsed 'AccessTokenClaims' on success.
-}
validateAccessToken :: JwtConfig -> Text -> IO (Either JwtError AccessTokenClaims)
validateAccessToken JwtConfig{jwtSecret, jwtIssuer, jwtAudience} token = do
    let jwk = fromOctets (TE.encodeUtf8 jwtSecret)
        expectedAud = textToStringOrURI jwtAudience
        expectedIss = textToStringOrURI jwtIssuer
        settings =
            defaultJWTValidationSettings (== expectedAud)
                & validationSettingsAlgorithms .~ Set.singleton JWS.HS256
                & issuerPredicate .~ (== expectedIss)
                & jwtValidationSettingsCheckIssuedAt .~ False
        tokenBytes = BSL.fromStrict (TE.encodeUtf8 token)
    decodeResult <- runJOSE (decodeCompact tokenBytes >>= verifyClaims settings jwk)
    case decodeResult of
        Left e -> pure (Left (mapJwtError e))
        Right cs -> pure $ do
            -- Post-signature checks below. jose has already verified the
            -- HMAC over the header+payload, so re-parsing those bytes for
            -- our project-specific stricter rules (typ policy, integer-only
            -- NumericDate) is safe — the bytes are trusted.
            enforceTypHeader token
            checkIntegerNumericDates token
            extractAccessTokenClaims cs

-- | Map a 'JWTError' from @jose@ into our 'JwtError' partition.
mapJwtError :: JWTError -> JwtError
mapJwtError = \case
    JWTExpired -> JwtVerifyError "token has expired"
    JWTNotYetValid -> JwtVerifyError "token not yet valid (nbf)"
    JWTIssuedAtFuture -> JwtVerifyError "token iat is in the future"
    JWTNotInIssuer -> JwtClaimError "iss mismatch"
    JWTNotInAudience -> JwtClaimError "aud mismatch"
    JWTClaimsSetDecodeError msg -> JwtVerifyError ("malformed payload: " <> msg)
    JWSError err -> JwtVerifyError ("jws verification failed: " <> show err)

-- | Extract custom Supabase claims from a verified 'ClaimsSet'.
extractAccessTokenClaims :: ClaimsSet -> Either JwtError AccessTokenClaims
extractAccessTokenClaims cs = do
    subText <- case preview (JWT.claimSub . _justStringOrURI) cs of
        Just t -> Right t
        Nothing -> Left (JwtClaimError "missing or non-string claim: sub")
    iatTime <- case view JWT.claimIat cs of
        Just (NumericDate t) -> Right t
        Nothing -> Left (JwtClaimError "missing claim: iat")
    expTime <- case view JWT.claimExp cs of
        Just (NumericDate t) -> Right t
        Nothing -> Left (JwtClaimError "missing claim: exp")
    let customObj :: Object
        customObj =
            KeyMap.fromMap
                ( Map.mapKeysMonotonic Key.fromText (view unregisteredClaims cs)
                )
    roleText <- requireText customObj "role"
    let emailVal = lookupText customObj "email"
    let phoneVal = lookupText customObj "phone"
    appMeta <- requireValue customObj "app_metadata"
    userMeta <- requireValue customObj "user_metadata"
    aalText <- requireText customObj "aal"
    amrEntries <- requireAmr customObj "amr"
    sessionId <- requireText customObj "session_id"
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
            , claimIssuedAt = iatTime
            , claimExpiresAt = expTime
            }
  where
    -- Compose `_Just` with the `string` prism so `preview` on `claimSub` yields
    -- `Maybe Text` rather than `Maybe (Maybe StringOrURI)`.
    _justStringOrURI = traverse . string

{- | Enforce the project's @typ@ header policy: if the @typ@ JOSE header is
present it must be the string @\"JWT\"@. RFC 7519 §5.1 makes @typ@ optional,
so its absence is accepted.

@jose@'s 'verifyClaims' validates @alg@ but does not check @typ@. We keep the
historical hardening that rejected @typ=JWE@ etc. so non-standard tokens are
refused even when their signature is otherwise valid.
-}
enforceTypHeader :: Text -> Either JwtError ()
enforceTypHeader token =
    case T.splitOn "." token of
        [headerB64, _, _] -> do
            bytes <- decodeBase64url headerB64
            hdr <- case Aeson.decodeStrict' bytes of
                Just (Object o) -> Right o
                Just _ -> Left (JwtVerifyError "malformed header: not a JSON object")
                Nothing -> Left (JwtVerifyError "malformed header: not valid JSON")
            case KeyMap.lookup (fromText "typ") hdr of
                Nothing -> Right () -- typ is optional per RFC 7519 §5.1
                Just (String "JWT") -> Right ()
                Just (String other) ->
                    Left (JwtVerifyError ("unsupported typ: " <> T.unpack other))
                Just _ ->
                    Left (JwtVerifyError "header typ is not a string")
        _ -> Left (JwtVerifyError "malformed token: expected 3 dot-separated segments")

{- | Re-parse the token's payload segment to confirm @iat@ and @exp@ are JSON
integers, not fractional numbers. Called after signature verification, so the
parsed bytes are trusted.
-}
checkIntegerNumericDates :: Text -> Either JwtError ()
checkIntegerNumericDates token =
    case T.splitOn "." token of
        [_, payloadB64, _] -> do
            payloadBytes <- decodeBase64url payloadB64
            obj <- case Aeson.decodeStrict' payloadBytes of
                Just (Object o) -> Right o
                Just _ -> Left (JwtClaimError "malformed payload: not a JSON object")
                Nothing -> Left (JwtClaimError "malformed payload: not valid JSON")
            _ <- requireInteger obj "iat"
            _ <- requireInteger obj "exp"
            Right ()
        _ -> Left (JwtVerifyError "malformed token: expected 3 dot-separated segments")

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
        -- RFC 7519 §2 NumericDate permits fractional values, but they are a
        -- foot-gun across verifier languages (rounding/truncation differences)
        -- — reject them here so the wire contract is unambiguous.
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
-- Base64url helper (used only for the post-verification fractional check)
-- ---------------------------------------------------------------------------

-- | Floor a 'UTCTime' to integer POSIX seconds.
floorPosix :: UTCTime -> UTCTime
floorPosix = posixSecondsToUTCTime . fromInteger . floor . utcTimeToPOSIXSeconds

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
