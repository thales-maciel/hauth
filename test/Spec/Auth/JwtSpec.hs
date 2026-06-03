module Spec.Auth.JwtSpec (spec) where

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
import Spec.TestUtils (makeTestClaims, testCfg)
import Test.Hspec (
    Spec,
    describe,
    expectationFailure,
    it,
    shouldBe,
    shouldSatisfy,
 )

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

isVerifyError :: Either JwtError a -> Bool
isVerifyError = \case
    Left (JwtVerifyError _) -> True
    _ -> False

isVerifyOrClaimError :: Either JwtError a -> Bool
isVerifyOrClaimError = \case
    Left (JwtVerifyError _) -> True
    Left (JwtClaimError _) -> True
    _ -> False

isClaimError :: Either JwtError a -> Bool
isClaimError = \case
    Left (JwtClaimError _) -> True
    _ -> False

-- | Sign a token and return it, failing the example with a useful message on error.
signOrFail :: JwtConfig -> AccessTokenClaims -> IO Text
signOrFail cfg claims = do
    r <- signAccessToken cfg claims
    case r of
        Left e -> fail ("signAccessToken failed: " <> show e)
        Right t -> pure t

spec :: Spec
spec = do
    describe "round-trip" $
        it "sign then validate preserves the claim fields" $ do
            now <- getCurrentTime
            let claims = makeTestClaims now
            tok <- signOrFail testCfg claims
            result <- validateAccessToken testCfg tok
            case result of
                Left e -> expectationFailure ("validateAccessToken failed: " <> show e)
                Right claims' -> do
                    claimSub claims' `shouldBe` claimSub claims
                    claimRole claims' `shouldBe` claimRole claims
                    claimEmail claims' `shouldBe` claimEmail claims
                    claimPhone claims' `shouldBe` claimPhone claims
                    claimAal claims' `shouldBe` claimAal claims
                    claimSessionId claims' `shouldBe` claimSessionId claims
                    length (claimAmr claims') `shouldBe` length (claimAmr claims)

    describe "claim policy" $ do
        it "rejects when validator audience differs from token aud" $ do
            now <- getCurrentTime
            let wrongAudCfg = testCfg{jwtAudience = "wrong-audience"}
            tok <- signOrFail testCfg (makeTestClaims now)
            result <- validateAccessToken wrongAudCfg tok
            result `shouldSatisfy` isVerifyOrClaimError

        it "rejects a tampered signature byte" $ do
            now <- getCurrentTime
            tok <- signOrFail testCfg (makeTestClaims now)
            let tampered = T.init tok <> if T.last tok == 'A' then "B" else "A"
            result <- validateAccessToken testCfg tampered
            result `shouldSatisfy` isVerifyError

        it "rejects an expired token" $ do
            now <- getCurrentTime
            let pastTime = addUTCTime (-3600) now
                expiredClaims = (makeTestClaims now){claimExpiresAt = pastTime}
            tok <- signOrFail testCfg expiredClaims
            result <- validateAccessToken testCfg tok
            result `shouldSatisfy` isVerifyOrClaimError

    describe "claim shape on the wire" $
        it "payload contains every Supabase-required key" $ do
            now <- getCurrentTime
            tok <- signOrFail testCfg (makeTestClaims now)
            obj <- payloadObject tok
            mapM_
                (\k -> KeyMap.member k obj `shouldBe` True)
                ["sub", "role", "aud", "iss", "iat", "exp", "aal", "amr", "session_id"]

    describe "header hardening" $ do
        let forgeWithHeader header = do
                now <- getCurrentTime
                signed <- signOrFail testCfg (makeTestClaims now)
                payload <- payloadObject signed
                pure (forgeToken testCfg header (Aeson.Object payload))

        it "rejects alg=none even though the HMAC is valid" $ do
            tok <- forgeWithHeader (object ["alg" .= ("none" :: Text), "typ" .= ("JWT" :: Text)])
            result <- validateAccessToken testCfg tok
            result `shouldSatisfy` isVerifyError

        it "rejects alg=RS256 (only HS256 secrets in flight)" $ do
            tok <- forgeWithHeader (object ["alg" .= ("RS256" :: Text), "typ" .= ("JWT" :: Text)])
            result <- validateAccessToken testCfg tok
            result `shouldSatisfy` isVerifyError

        it "rejects missing alg" $ do
            tok <- forgeWithHeader (object ["typ" .= ("JWT" :: Text)])
            result <- validateAccessToken testCfg tok
            result `shouldSatisfy` isVerifyError

        it "accepts typ absent (RFC 7519 §5.1)" $ do
            tok <- forgeWithHeader (object ["alg" .= ("HS256" :: Text)])
            result <- validateAccessToken testCfg tok
            result `shouldSatisfy` \case
                Right _ -> True
                _ -> False

        it "rejects typ=JWE when present" $ do
            tok <- forgeWithHeader (object ["alg" .= ("HS256" :: Text), "typ" .= ("JWE" :: Text)])
            result <- validateAccessToken testCfg tok
            result `shouldSatisfy` isVerifyError

    describe "NumericDate strictness" $ do
        let forgeWithPayloadField k v = do
                now <- getCurrentTime
                signed <- signOrFail testCfg (makeTestClaims now)
                payload <- payloadObject signed
                let payload' = Aeson.Object (KeyMap.insert k v payload)
                    header = object ["alg" .= ("HS256" :: Text), "typ" .= ("JWT" :: Text)]
                pure (forgeToken testCfg header payload')

        it "rejects fractional exp" $ do
            tok <- forgeWithPayloadField "exp" (Aeson.Number 9999999999.5)
            result <- validateAccessToken testCfg tok
            result `shouldSatisfy` isClaimError

        it "rejects fractional iat" $ do
            tok <- forgeWithPayloadField "iat" (Aeson.Number 1780000000.25)
            result <- validateAccessToken testCfg tok
            result `shouldSatisfy` isClaimError
