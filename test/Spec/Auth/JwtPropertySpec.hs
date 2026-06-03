-- | Hedgehog-driven malformed-token / property tests for 'Hauth.Auth.Jwt'.
--
-- Complements the hand-written cases in 'Spec.Auth.JwtSpec' by fuzzing the
-- inputs to 'validateAccessToken' — tampered signatures, garbage segments,
-- bad base64, wrong segment counts, random alg headers, non-object header
-- and payload, boundary exp\/iat, and fractional NumericDate.
module Spec.Auth.JwtPropertySpec (runSpec) where

import Control.Monad (unless, when)
import Crypto.Hash (SHA256)
import Crypto.MAC.HMAC (HMAC, hmac, hmacGetDigest)
import qualified Data.Aeson as Aeson
import Data.Aeson (Value (..), object, (.=))
import qualified Data.Aeson.Key as Key
import qualified Data.Aeson.KeyMap as KeyMap
import Data.ByteArray (convert)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Base64.URL as B64URL
import qualified Data.ByteString.Char8 as BSC
import qualified Data.ByteString.Lazy as BSL
import Data.IORef (atomicModifyIORef', newIORef, readIORef)
import Data.Text (Text)
import qualified Data.Text as T
import qualified Data.Text.Encoding as TE
import Data.Time.Clock (NominalDiffTime, UTCTime, addUTCTime, getCurrentTime)
import qualified Data.Time.Clock.POSIX
import Hauth.Auth.Jwt (
    AccessTokenClaims (..),
    AmrEntry (..),
    JwtError (..),
    signAccessToken,
    validateAccessToken,
 )
import Hauth.Config (JwtConfig (..))
import Hedgehog (Gen, Property, PropertyT, evalIO, failure, footnote, forAll, property, withTests, (===))
import qualified Hedgehog as H
import qualified Hedgehog.Gen as Gen
import qualified Hedgehog.Range as Range
import Spec.TestUtils (makeTestClaims, testCfg)

-- ---------------------------------------------------------------------------
-- Generators
-- ---------------------------------------------------------------------------

genUuidLike :: Gen Text
genUuidLike = do
    let hex = Gen.text (Range.singleton 32) (Gen.frequency [(1, Gen.element ['0' .. '9']), (1, Gen.element ['a' .. 'f'])])
    raw <- hex
    pure $
        T.take 8 raw
            <> "-"
            <> T.take 4 (T.drop 8 raw)
            <> "-"
            <> T.take 4 (T.drop 12 raw)
            <> "-"
            <> T.take 4 (T.drop 16 raw)
            <> "-"
            <> T.take 12 (T.drop 20 raw)

genRole :: Gen Text
genRole =
    Gen.element
        [ "authenticated"
        , "service_role"
        , "anon"
        , "supabase_admin"
        ]

genAal :: Gen Text
genAal = Gen.element ["aal1", "aal2"]

genAmrEntry :: Gen AmrEntry
genAmrEntry = do
    method <- Gen.element ["password", "oauth", "totp", "magic_link", "phone_otp"]
    ts <- Gen.integral (Range.linear 1000000000 2000000000)
    pure AmrEntry{amrMethod = method, amrTimestamp = ts}

genMetadataValue :: Gen Value
genMetadataValue =
    Gen.recursive
        Gen.choice
        [ pure Null
        , Bool <$> Gen.bool
        , (String . T.pack) <$> Gen.list (Range.linear 0 10) Gen.alphaNum
        ]
        [ Object . KeyMap.fromList
            <$> Gen.list
                (Range.linear 0 3)
                ( do
                    k <- Gen.text (Range.linear 1 8) Gen.alphaNum
                    v <- genMetadataValue
                    pure (Key.fromString (T.unpack k), v)
                )
        ]

-- | A wide window around \"now\" so exp boundary cases (one second past, one
-- second future) are also reachable, but stays positive and away from
-- year-2038-style overflow.
genClaims :: UTCTime -> Gen AccessTokenClaims
genClaims now = do
    sub <- genUuidLike
    role <- genRole
    email <- Gen.maybe ((<> "@example.com") <$> Gen.text (Range.linear 1 12) Gen.alphaNum)
    phone <- Gen.maybe (T.pack . show <$> Gen.integral (Range.linear (1000000000 :: Int) 9999999999))
    appMeta <- genMetadataValue
    userMeta <- genMetadataValue
    aal <- genAal
    amr <- Gen.list (Range.linear 1 3) genAmrEntry
    sess <- genUuidLike
    expOffset <- Gen.integral (Range.linear 60 86400)
    let expTime = addUTCTime (fromIntegral (expOffset :: Int)) now
    pure
        AccessTokenClaims
            { claimSub = sub
            , claimRole = role
            , claimEmail = email
            , claimPhone = phone
            , claimAppMetadata = appMeta
            , claimUserMetadata = userMeta
            , claimAal = aal
            , claimAmr = amr
            , claimSessionId = sess
            , claimIssuedAt = now
            , claimExpiresAt = expTime
            }

-- ---------------------------------------------------------------------------
-- Helpers for forging arbitrary tokens
-- ---------------------------------------------------------------------------

b64url :: BS.ByteString -> Text
b64url = TE.decodeUtf8 . BSC.takeWhile (/= '=') . B64URL.encode

forgeToken :: JwtConfig -> Value -> Value -> Text
forgeToken cfg header payload =
    let headerB64 = b64url (BSL.toStrict (Aeson.encode header))
        payloadB64 = b64url (BSL.toStrict (Aeson.encode payload))
        signingInput = headerB64 <> "." <> payloadB64
        key = TE.encodeUtf8 (jwtSecret cfg)
        msg = TE.encodeUtf8 signingInput
        mac = hmac key msg :: HMAC SHA256
        sig = b64url (convert (hmacGetDigest mac) :: BS.ByteString)
     in signingInput <> "." <> sig

defaultPayloadFor :: AccessTokenClaims -> JwtConfig -> IO Value
defaultPayloadFor claims cfg = do
    res <- signAccessToken cfg claims
    case res of
        Left e -> error ("defaultPayloadFor: sign failed: " <> show e)
        Right tok -> case T.splitOn "." tok of
            [_, p, _] -> case B64URL.decode (TE.encodeUtf8 p <> padding p) of
                Left e -> error ("defaultPayloadFor: b64 decode: " <> e)
                Right bytes -> case Aeson.decodeStrict bytes of
                    Just v -> pure v
                    Nothing -> error "defaultPayloadFor: json decode"
            _ -> error "defaultPayloadFor: not 3 segments"
  where
    padding t =
        let n = BS.length (TE.encodeUtf8 t) `mod` 4
         in if n == 0 then "" else BS.replicate (4 - n) 61

-- ---------------------------------------------------------------------------
-- Properties
-- ---------------------------------------------------------------------------

-- | A signed token always round-trips back to the original claim fields.
propRoundTrip :: UTCTime -> Property
propRoundTrip now = withTests 100 . property $ do
    claims <- forAll (genClaims now)
    res <- evalIO (signAccessToken testCfg claims)
    case res of
        Left e -> do
            footnote ("sign failed: " <> show e)
            failure
        Right tok -> do
            verified <- evalIO (validateAccessToken testCfg tok)
            case verified of
                Left e -> do
                    footnote ("verify failed: " <> show e)
                    failure
                Right out -> do
                    claimSub out === claimSub claims
                    claimRole out === claimRole claims
                    claimEmail out === claimEmail claims
                    claimPhone out === claimPhone claims
                    claimAal out === claimAal claims
                    claimSessionId out === claimSessionId claims
                    claimAmr out === claimAmr claims

-- | Flipping any single byte of a freshly signed token rejects it.
--
-- We mutate a byte in the signature segment (always present), which
-- guarantees the token is still 3 dot-segments — so the failure mode is
-- always signature verification rather than malformed shape.
propTamperSignature :: UTCTime -> Property
propTamperSignature now = withTests 100 . property $ do
    claims <- forAll (genClaims now)
    res <- evalIO (signAccessToken testCfg claims)
    case res of
        Left e -> do
            footnote ("sign failed: " <> show e)
            failure
        Right tok -> case T.splitOn "." tok of
            [h, p, s] -> do
                let s' =
                        if T.null s
                            then "A"
                            else
                                let c = T.last s
                                    swap = if c == 'A' then 'B' else 'A'
                                 in T.init s <> T.singleton swap
                    tampered = h <> "." <> p <> "." <> s'
                verified <- evalIO (validateAccessToken testCfg tampered)
                expectVerifyError tampered verified
            _ -> do
                footnote "unexpected: signed token did not have 3 segments"
                failure

-- | Random 3-segment garbage (random base64url-ish blobs) always rejects.
propGarbageThreeSegments :: Property
propGarbageThreeSegments = withTests 100 . property $ do
    h <- forAll (Gen.text (Range.linear 0 32) genBase64UrlChar)
    p <- forAll (Gen.text (Range.linear 0 64) genBase64UrlChar)
    s <- forAll (Gen.text (Range.linear 0 64) genBase64UrlChar)
    let tok = h <> "." <> p <> "." <> s
    res <- evalIO (validateAccessToken testCfg tok)
    expectLeft tok res

genBase64UrlChar :: Gen Char
genBase64UrlChar =
    Gen.element
        ( ['A' .. 'Z']
            <> ['a' .. 'z']
            <> ['0' .. '9']
            <> ['-', '_']
        )

-- | Wrong segment count (0, 1, 2, 4, 5 dots) rejects as a verify error.
propWrongSegmentCount :: Property
propWrongSegmentCount = withTests 50 . property $ do
    nDots <- forAll (Gen.element [0, 1, 3, 4, 5 :: Int])
    segs <- forAll (Gen.list (Range.singleton (nDots + 1)) (Gen.text (Range.linear 0 16) genBase64UrlChar))
    let tok = T.intercalate "." segs
    when (length (T.splitOn "." tok) == 3) H.discard
    res <- evalIO (validateAccessToken testCfg tok)
    expectVerifyError tok res

-- | Arbitrary completely-random byte segments (often not valid base64url) reject without exception.
propBadBase64 :: Property
propBadBase64 = withTests 100 . property $ do
    -- Use printable ASCII including chars that aren't valid base64url (!@# etc).
    h <- forAll (Gen.text (Range.linear 1 16) (Gen.element ("!@#$%^&*()[]{}+=;:'\",.<>/?\\|`~ " :: String)))
    p <- forAll (Gen.text (Range.linear 1 32) (Gen.element ("!@#$%^&*()[]{}+=;:'\",.<>/?\\|`~ " :: String)))
    s <- forAll (Gen.text (Range.linear 1 32) (Gen.element ("!@#$%^&*()[]{}+=;:'\",.<>/?\\|`~ " :: String)))
    let tok = h <> "." <> p <> "." <> s
    res <- evalIO (validateAccessToken testCfg tok)
    expectLeft tok res

-- | Any header @alg@ value other than @HS256@ rejects, even with a valid HMAC
-- over the new header bytes.
propRandomAlgRejected :: UTCTime -> Property
propRandomAlgRejected now = withTests 100 . property $ do
    let claims = makeTestClaims now
    payload <- evalIO (defaultPayloadFor claims testCfg)
    badAlg <-
        forAll
            ( Gen.element
                [ "none"
                , "NONE"
                , "None"
                , "RS256"
                , "RS512"
                , "ES256"
                , "ES512"
                , "PS256"
                , "HS384"
                , "HS512"
                , "EdDSA"
                , ""
                , "HS256\x00" -- embedded null
                , "Hs256" -- case mismatch
                ]
            )
    let header = object ["alg" .= (badAlg :: Text), "typ" .= ("JWT" :: Text)]
    let tok = forgeToken testCfg header payload
    res <- evalIO (validateAccessToken testCfg tok)
    expectVerifyError tok res

-- | Header that's a JSON non-object (number, array, string, null) rejects.
propNonObjectHeaderPayload :: UTCTime -> Property
propNonObjectHeaderPayload now = withTests 100 . property $ do
    let claims = makeTestClaims now
    okPayload <- evalIO (defaultPayloadFor claims testCfg)
    okHeader <- pure (object ["alg" .= ("HS256" :: Text), "typ" .= ("JWT" :: Text)])
    target <- forAll (Gen.element (["header", "payload"] :: [Text]))
    badShape <-
        forAll
            ( Gen.element
                [ Aeson.Number 42
                , Aeson.String "not an object"
                , Aeson.Bool True
                , Aeson.Null
                , Aeson.Array mempty
                , Aeson.Array (pure (Aeson.String "x"))
                ]
            )
    let (hdr, pl) = case (target :: Text) of
            "header" -> (badShape, okPayload)
            _ -> (okHeader, badShape)
        tok = forgeToken testCfg hdr pl
    res <- evalIO (validateAccessToken testCfg tok)
    expectLeft tok res

-- | exp boundary: exactly now (rejected), one second past (rejected), one
-- second future (accepted). The verifier is called with verifyClaims at
-- system @currentTime@ — to make this deterministic against the property's
-- chosen offset, we sign with that offset and check shortly after.
propExpBoundary :: Property
propExpBoundary = withTests 30 . property $ do
    offset <- forAll (Gen.element [-2 :: Int, -1, 0, 2, 5])
    res <- evalIO $ do
        now <- getCurrentTime
        let claims = (makeTestClaims now){claimExpiresAt = addUTCTime (fromIntegral offset :: NominalDiffTime) now}
        signed <- signAccessToken testCfg claims
        case signed of
            Left e -> pure (Left ("sign:" <> show e))
            Right tok -> do
                v <- validateAccessToken testCfg tok
                pure (Right (offset, v))
    case res of
        Left m -> do footnote m; failure
        Right (off, v) ->
            if off <= 0
                then expectVerifyError "exp boundary" v
                else case v of
                    Right _ -> pure ()
                    Left e -> do
                        footnote ("expected accept for offset=" <> show off <> ", got " <> show e)
                        failure

-- | Property-generated fractional iat/exp values are always rejected as
-- 'JwtClaimError', not silently floored.
propFractionalNumericDate :: UTCTime -> Property
propFractionalNumericDate now = withTests 100 . property $ do
    let claims = makeTestClaims now
    payload <- evalIO (defaultPayloadFor claims testCfg)
    targetKey <- forAll (Gen.element ["exp", "iat"])
    -- Generate a fractional NumericDate. Use an offset around the existing
    -- value so the token isn't pathologically far in the past/future.
    frac <- forAll (Gen.double (Range.linearFrac 0.01 0.99))
    let baseObj = case payload of
            Object o -> o
            _ -> error "defaultPayloadFor returned non-object"
        existing = case KeyMap.lookup (Key.fromString targetKey) baseObj of
            Just (Number n) -> realToFrac n
            _ -> utcSeconds (addUTCTime 3600 now)
        newVal = Aeson.Number (realToFrac (existing + frac))
        payload' = Object (KeyMap.insert (Key.fromString targetKey) newVal baseObj)
        hdr = object ["alg" .= ("HS256" :: Text), "typ" .= ("JWT" :: Text)]
        tok = forgeToken testCfg hdr payload'
    res <- evalIO (validateAccessToken testCfg tok)
    case res of
        Left (JwtClaimError _) -> pure ()
        Left other -> do
            footnote ("expected JwtClaimError, got " <> show other)
            failure
        Right _ -> do
            footnote ("expected JwtClaimError, got Right; key=" <> targetKey <> " frac=" <> show frac)
            failure

utcSeconds :: UTCTime -> Double
utcSeconds t = realToFrac (Data.Time.Clock.POSIX.utcTimeToPOSIXSeconds t)

-- ---------------------------------------------------------------------------
-- Assertion helpers
-- ---------------------------------------------------------------------------

expectLeft :: (Show b, Monad m) => Text -> Either a b -> PropertyT m ()
expectLeft ctx = \case
    Left _ -> pure ()
    Right v -> do
        footnote ("expected Left for " <> T.unpack ctx <> ", got Right " <> show v)
        failure

expectVerifyError :: (Show a, Monad m) => Text -> Either JwtError a -> PropertyT m ()
expectVerifyError ctx = \case
    Left (JwtVerifyError _) -> pure ()
    Left (JwtClaimError _) -> pure ()
    Left other -> do
        footnote (T.unpack ctx <> ": expected JwtVerifyError/JwtClaimError, got " <> show other)
        failure
    Right v -> do
        footnote ("expected Left for " <> T.unpack ctx <> ", got Right " <> show v)
        failure

-- ---------------------------------------------------------------------------
-- Spec runner
-- ---------------------------------------------------------------------------

runSpec :: IO ()
runSpec = do
    now <- getCurrentTime
    failedRef <- newIORef False
    let run name p = do
            ok <- H.check p
            unless ok $ do
                putStrLn ("Spec.Auth.JwtPropertySpec: " <> name <> " FAILED")
                atomicModifyIORef' failedRef (\_ -> (True, ()))
    run "roundtrip" (propRoundTrip now)
    run "tamper-signature" (propTamperSignature now)
    run "garbage-three-segments" propGarbageThreeSegments
    run "wrong-segment-count" propWrongSegmentCount
    run "bad-base64" propBadBase64
    run "random-alg-rejected" (propRandomAlgRejected now)
    run "non-object-header-payload" (propNonObjectHeaderPayload now)
    run "exp-boundary" propExpBoundary
    run "fractional-numeric-date" (propFractionalNumericDate now)
    failed <- readIORef failedRef
    when failed $ fail "Spec.Auth.JwtPropertySpec: one or more properties failed"
