module Spec.Auth.JwtSpec (runSpec) where

import Crypto.Hash (SHA256)
import Crypto.MAC.HMAC (HMAC, hmac, hmacGetDigest)
import Data.Aeson (Object, Value, decodeStrict', object, (.=))
import qualified Data.Aeson as Aeson
import qualified Data.Aeson.KeyMap as KeyMap
import Data.ByteArray (convert)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Base64.URL as B64URL
import qualified Data.ByteString.Char8 as BSC
import qualified Data.ByteString.Lazy as BSL
import Data.Text (Text)
import qualified Data.Text as T
import qualified Data.Text.Encoding as TE
import Data.Time.Clock (addUTCTime, getCurrentTime)
import Hauth.Auth.Jwt (
    AccessTokenClaims (..),
    JwtError (..),
    signAccessToken,
    validateAccessToken,
 )
import Hauth.Config (JwtConfig (..))
import Spec.TestUtils (assertEqual, makeTestClaims, testCfg)

{- | Forge a JWT with the given header and payload JSON, signed with the
config's secret. Bypasses 'signAccessToken' so tests can exercise header
policy and malformed-claim handling that the real signer would never emit.
-}
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

b64url :: BS.ByteString -> Text
b64url = TE.decodeUtf8 . BSC.takeWhile (/= '=') . B64URL.encode

{- | Decode a JWT's payload segment to a JSON object so a forge can replace
selected claims without re-deriving the full Supabase claim shape.
-}
payloadObject :: Text -> IO Object
payloadObject token =
    case T.splitOn "." token of
        [_h, p, _s] ->
            case B64URL.decode (TE.encodeUtf8 p) of
                Left e -> fail ("payloadObject: base64 decode: " <> e)
                Right bytes ->
                    case decodeStrict' bytes of
                        Just o -> pure o
                        Nothing -> fail "payloadObject: JSON decode"
        _ -> fail "payloadObject: expected 3 segments"

expectVerifyError :: String -> Either JwtError a -> IO ()
expectVerifyError label = \case
    Left (JwtVerifyError _) -> pure ()
    Left err -> fail (label <> ": expected JwtVerifyError, got " <> show err)
    Right _ -> fail (label <> ": expected Left, got Right")

expectClaimError :: String -> Either JwtError a -> IO ()
expectClaimError label = \case
    Left (JwtClaimError _) -> pure ()
    Left err -> fail (label <> ": expected JwtClaimError, got " <> show err)
    Right _ -> fail (label <> ": expected Left, got Right")

runSpec :: IO ()
runSpec = do
    now <- getCurrentTime
    let testClaims = makeTestClaims now
        pastTime = addUTCTime (-3600) now

    -- Round-trip: sign then validate
    signResult <- signAccessToken testCfg testClaims
    case signResult of
        Left err -> fail ("jwt round-trip sign failed: " <> show err)
        Right token -> do
            validateResult <- validateAccessToken testCfg token
            case validateResult of
                Left err -> fail ("jwt round-trip validate failed: " <> show err)
                Right claims' -> do
                    assertEqual "round-trip sub" (claimSub testClaims) (claimSub claims')
                    assertEqual "round-trip role" (claimRole testClaims) (claimRole claims')
                    assertEqual "round-trip email" (claimEmail testClaims) (claimEmail claims')
                    assertEqual "round-trip phone" (claimPhone testClaims) (claimPhone claims')
                    assertEqual "round-trip aal" (claimAal testClaims) (claimAal claims')
                    assertEqual "round-trip session_id" (claimSessionId testClaims) (claimSessionId claims')
                    assertEqual "round-trip amr length" (length (claimAmr testClaims)) (length (claimAmr claims'))

    -- Wrong audience: validate with different config should fail
    let wrongAudCfg = testCfg{jwtAudience = "wrong-audience"}
    signResult2 <- signAccessToken testCfg testClaims
    case signResult2 of
        Left err -> fail ("jwt wrong-aud sign failed: " <> show err)
        Right token2 -> do
            wrongAudResult <- validateAccessToken wrongAudCfg token2
            case wrongAudResult of
                Left (JwtClaimError _) -> pure ()
                Left (JwtVerifyError _) -> pure ()
                Left err -> fail ("jwt wrong-aud: unexpected error type: " <> show err)
                Right _ -> fail "jwt wrong-aud: expected Left, got Right"

    -- Tampered signature: flip a byte in the last segment
    signResult3 <- signAccessToken testCfg testClaims
    case signResult3 of
        Left err -> fail ("jwt tamper sign failed: " <> show err)
        Right token3 -> do
            let tampered = T.init token3 <> if T.last token3 == 'A' then "B" else "A"
            tamperedResult <- validateAccessToken testCfg tampered
            case tamperedResult of
                Left (JwtVerifyError _) -> pure ()
                Left err -> fail ("jwt tamper: unexpected error type: " <> show err)
                Right _ -> fail "jwt tamper: expected Left, got Right"

    -- Expired token: claimExpiresAt in the past
    let expiredClaims = testClaims{claimExpiresAt = pastTime}
    expiredResult <- signAccessToken testCfg expiredClaims
    case expiredResult of
        Left err -> fail ("jwt expired sign failed: " <> show err)
        Right expiredToken -> do
            expiredValidateResult <- validateAccessToken testCfg expiredToken
            case expiredValidateResult of
                Left (JwtVerifyError _) -> pure ()
                Left (JwtClaimError _) -> pure ()
                Left err -> fail ("jwt expired: unexpected error type: " <> show err)
                Right _ -> fail "jwt expired: expected Left for expired token, got Right"

    -- Claim shape: decode payload segment and check required keys
    signResult4 <- signAccessToken testCfg testClaims
    case signResult4 of
        Left err -> fail ("jwt claim-shape sign failed: " <> show err)
        Right token4 -> do
            let segments = T.splitOn "." token4
            case segments of
                [_hdr, payloadB64, _sig] -> do
                    case B64URL.decode (TE.encodeUtf8 payloadB64) of
                        Left e -> fail ("jwt claim-shape: base64 decode failed: " <> e)
                        Right payloadBytes ->
                            case decodeStrict' payloadBytes of
                                Nothing -> fail "jwt claim-shape: JSON decode failed"
                                Just (obj :: Object) -> do
                                    let requiredKeys = ["sub", "role", "aud", "iss", "iat", "exp", "aal", "amr", "session_id"]
                                    mapM_
                                        ( \k ->
                                            if KeyMap.member k obj
                                                then pure ()
                                                else fail ("jwt claim-shape: missing key: " <> show k)
                                        )
                                        requiredKeys
                _ -> fail ("jwt claim-shape: expected 3 segments, got " <> show (length segments))

    -- Header hardening: forge tokens with a real (HMAC-valid) signature but a
    -- disallowed header. The signature passes; header validation must reject.
    signedForPayload <- signAccessToken testCfg testClaims
    payload <- case signedForPayload of
        Left err -> fail ("jwt header tests: sign failed: " <> show err)
        Right t -> payloadObject t

    let payloadValue = Aeson.Object payload

    -- alg=none must be rejected even though Supabase ecosystem tokens are HS256.
    let algNoneToken = forgeToken testCfg (object ["alg" .= ("none" :: Text), "typ" .= ("JWT" :: Text)]) payloadValue
    algNoneResult <- validateAccessToken testCfg algNoneToken
    expectVerifyError "jwt alg=none" algNoneResult

    -- alg=RS256 must be rejected; we only sign with HS256 secrets.
    let algRsToken = forgeToken testCfg (object ["alg" .= ("RS256" :: Text), "typ" .= ("JWT" :: Text)]) payloadValue
    algRsResult <- validateAccessToken testCfg algRsToken
    expectVerifyError "jwt alg=RS256" algRsResult

    -- Missing alg must be rejected.
    let algMissingToken = forgeToken testCfg (object ["typ" .= ("JWT" :: Text)]) payloadValue
    algMissingResult <- validateAccessToken testCfg algMissingToken
    expectVerifyError "jwt missing alg" algMissingResult

    -- typ absent is allowed (RFC 7519 §5.1).
    let typAbsentToken = forgeToken testCfg (object ["alg" .= ("HS256" :: Text)]) payloadValue
    typAbsentResult <- validateAccessToken testCfg typAbsentToken
    case typAbsentResult of
        Right _ -> pure ()
        Left err -> fail ("jwt typ-absent: expected accept, got " <> show err)

    -- typ=other must be rejected when present.
    let typOtherToken = forgeToken testCfg (object ["alg" .= ("HS256" :: Text), "typ" .= ("JWE" :: Text)]) payloadValue
    typOtherResult <- validateAccessToken testCfg typOtherToken
    expectVerifyError "jwt typ=JWE" typOtherResult

    -- Fractional exp: RFC 7519 NumericDate permits non-integers, but we reject
    -- them so downstream consumers don't have to choose between floor/round/ceil.
    let fractionalExpPayload = Aeson.Object (KeyMap.insert "exp" (Aeson.Number 9999999999.5) payload)
        fractionalExpToken = forgeToken testCfg (object ["alg" .= ("HS256" :: Text), "typ" .= ("JWT" :: Text)]) fractionalExpPayload
    fractionalExpResult <- validateAccessToken testCfg fractionalExpToken
    expectClaimError "jwt fractional exp" fractionalExpResult

    -- Fractional iat: same reasoning.
    let fractionalIatPayload = Aeson.Object (KeyMap.insert "iat" (Aeson.Number 1780000000.25) payload)
        fractionalIatToken = forgeToken testCfg (object ["alg" .= ("HS256" :: Text), "typ" .= ("JWT" :: Text)]) fractionalIatPayload
    fractionalIatResult <- validateAccessToken testCfg fractionalIatToken
    expectClaimError "jwt fractional iat" fractionalIatResult
