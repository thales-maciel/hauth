module Spec.Mfa.TotpSpec (runSpec) where

import Data.Aeson (Object, Value (..))
import qualified Data.Aeson as Aeson
import qualified Data.Aeson.KeyMap as KeyMap
import qualified Data.ByteString as BS
import qualified Data.Text as T
import qualified Data.UUID as UUID
import Hauth.API.Types (
    EnrollError (..),
    EnrollFactorRequest (..),
    buildFactorResponse,
    validateEnrollRequest,
 )
import Hauth.Mfa.Totp (
    TotpSecret (..),
    decodeBase32,
    encodeBase32,
    generateTotpSecret,
    otpAuthUri,
    unTotpSecret,
 )
import Spec.TestUtils (assertEqual)

runSpec :: IO ()
runSpec = do
    assertEqual
        "encodeBase32 empty"
        ""
        (encodeBase32 "")
    assertEqual
        "encodeBase32 foobar"
        "MZXW6YTBOI"
        (encodeBase32 "foobar")
    assertEqual
        "encodeBase32 f"
        "MY"
        (encodeBase32 "f")
    assertEqual
        "encodeBase32 fo"
        "MZXQ"
        (encodeBase32 "fo")
    let knownSecret20 = BS.pack [0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x01, 0x23, 0x45, 0x67]
    case decodeBase32 (encodeBase32 knownSecret20) of
        Nothing -> fail "decodeBase32 round-trip: got Nothing"
        Just decoded -> assertEqual "decodeBase32 round-trip 20-byte" knownSecret20 decoded
    case decodeBase32 "MZXW6YTBOI======" of
        Nothing -> fail "decodeBase32 with padding: got Nothing"
        Just decoded -> assertEqual "decodeBase32 with padding equals foobar" "foobar" decoded
    case decodeBase32 "mzxw6ytboi" of
        Nothing -> fail "decodeBase32 lowercase: got Nothing"
        Just decoded -> assertEqual "decodeBase32 lowercase round-trip" "foobar" decoded
    assertEqual
        "decodeBase32 invalid char returns Nothing"
        Nothing
        (decodeBase32 "invalid!")
    secret1 <- generateTotpSecret
    assertEqual "generateTotpSecret produces 20 bytes" 20 (BS.length (unTotpSecret secret1))
    secret2 <- generateTotpSecret
    assertEqual "generateTotpSecret two calls differ" True (unTotpSecret secret1 /= unTotpSecret secret2)
    let knownSecret = TotpSecret (BS.pack (replicate 20 0))
        uri = otpAuthUri "hauth" "alice@example.com" knownSecret
    assertEqual
        "otpAuthUri starts with otpauth://totp/"
        True
        (T.isPrefixOf "otpauth://totp/" uri)
    assertEqual
        "otpAuthUri encodes @ as %40"
        True
        (T.isInfixOf "alice%40example.com" uri)
    assertEqual
        "otpAuthUri contains issuer=hauth"
        True
        (T.isInfixOf "&issuer=hauth" uri)
    assertEqual
        "otpAuthUri contains algorithm=SHA1"
        True
        (T.isInfixOf "&algorithm=SHA1" uri)
    assertEqual
        "otpAuthUri contains digits=6"
        True
        (T.isInfixOf "&digits=6" uri)
    assertEqual
        "otpAuthUri contains period=30"
        True
        (T.isInfixOf "&period=30" uri)
    assertEqual
        "validateEnrollRequest accepts totp"
        (Right ())
        ( validateEnrollRequest
            EnrollFactorRequest
                { enrollFactorType = "totp"
                , enrollFactorFriendlyName = Nothing
                , enrollFactorIssuer = Nothing
                }
        )
    assertEqual
        "validateEnrollRequest rejects webauthn"
        (Left (EnrollUnsupportedFactorType "webauthn"))
        ( validateEnrollRequest
            EnrollFactorRequest
                { enrollFactorType = "webauthn"
                , enrollFactorFriendlyName = Nothing
                , enrollFactorIssuer = Nothing
                }
        )
    let totpUri' = "otpauth://totp/hauth:user%40example.com?secret=AAAA&issuer=hauth&algorithm=SHA1&digits=6&period=30"
        factorResp =
            buildFactorResponse
                UUID.nil
                "totp"
                (Just "My Authenticator")
                "unverified"
                "AAAA"
                totpUri'
    case Aeson.decode (Aeson.encode factorResp) of
        Nothing ->
            fail "FactorResponse: JSON decode failed"
        Just (obj :: Object) -> do
            let requiredFactorKeys = ["id", "type", "friendly_name", "totp"]
            mapM_
                ( \k ->
                    if KeyMap.member k obj
                        then pure ()
                        else fail ("FactorResponse JSON: missing top-level key: " <> show k)
                )
                requiredFactorKeys
            case KeyMap.lookup "totp" obj of
                Nothing ->
                    fail "FactorResponse JSON: missing totp sub-object"
                Just (Object totpObj) -> do
                    let requiredTotpKeys = ["qr_code", "secret", "uri"]
                    mapM_
                        ( \k ->
                            if KeyMap.member k totpObj
                                then pure ()
                                else fail ("FactorResponse JSON: totp missing key: " <> show k)
                        )
                        requiredTotpKeys
                _ ->
                    fail "FactorResponse JSON: totp is not an object"
