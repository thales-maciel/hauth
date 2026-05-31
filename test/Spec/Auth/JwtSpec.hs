module Spec.Auth.JwtSpec (runSpec) where

import Data.Aeson (Object, decodeStrict')
import qualified Data.Aeson.KeyMap as KeyMap
import qualified Data.ByteString.Base64.URL as B64URL
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
