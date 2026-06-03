module Spec.Mfa.TotpSpec (spec) where

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
import Test.Hspec (Spec, describe, expectationFailure, it, shouldBe, shouldSatisfy)

spec :: Spec
spec = do
    describe "encodeBase32" $ do
        it "encodes empty" $
            encodeBase32 "" `shouldBe` ""
        it "encodes foobar" $
            encodeBase32 "foobar" `shouldBe` "MZXW6YTBOI"
        it "encodes f" $
            encodeBase32 "f" `shouldBe` "MY"
        it "encodes fo" $
            encodeBase32 "fo" `shouldBe` "MZXQ"

    describe "decodeBase32" $ do
        it "round-trips a 20-byte secret" $ do
            let knownSecret20 =
                    BS.pack
                        [ 0x00
                        , 0x11
                        , 0x22
                        , 0x33
                        , 0x44
                        , 0x55
                        , 0x66
                        , 0x77
                        , 0x88
                        , 0x99
                        , 0xAA
                        , 0xBB
                        , 0xCC
                        , 0xDD
                        , 0xEE
                        , 0xFF
                        , 0x01
                        , 0x23
                        , 0x45
                        , 0x67
                        ]
            case decodeBase32 (encodeBase32 knownSecret20) of
                Nothing -> expectationFailure "got Nothing"
                Just decoded -> decoded `shouldBe` knownSecret20

        it "decodes padded input" $
            case decodeBase32 "MZXW6YTBOI======" of
                Nothing -> expectationFailure "got Nothing"
                Just decoded -> decoded `shouldBe` "foobar"

        it "decodes lowercase input" $
            case decodeBase32 "mzxw6ytboi" of
                Nothing -> expectationFailure "got Nothing"
                Just decoded -> decoded `shouldBe` "foobar"

        it "returns Nothing for invalid characters" $
            decodeBase32 "invalid!" `shouldBe` Nothing

    describe "generateTotpSecret" $ do
        it "produces 20 bytes" $ do
            secret <- generateTotpSecret
            BS.length (unTotpSecret secret) `shouldBe` 20

        it "two calls differ" $ do
            secret1 <- generateTotpSecret
            secret2 <- generateTotpSecret
            (unTotpSecret secret1 /= unTotpSecret secret2) `shouldBe` True

    describe "otpAuthUri" $ do
        let knownSecret = TotpSecret (BS.pack (replicate 20 0))
            uri = otpAuthUri "hauth" "alice@example.com" knownSecret
        it "starts with otpauth://totp/" $
            uri `shouldSatisfy` T.isPrefixOf "otpauth://totp/"
        it "encodes @ as %40" $
            uri `shouldSatisfy` T.isInfixOf "alice%40example.com"
        it "contains issuer=hauth" $
            uri `shouldSatisfy` T.isInfixOf "&issuer=hauth"
        it "contains algorithm=SHA1" $
            uri `shouldSatisfy` T.isInfixOf "&algorithm=SHA1"
        it "contains digits=6" $
            uri `shouldSatisfy` T.isInfixOf "&digits=6"
        it "contains period=30" $
            uri `shouldSatisfy` T.isInfixOf "&period=30"

    describe "validateEnrollRequest" $ do
        it "accepts totp" $
            validateEnrollRequest
                EnrollFactorRequest
                    { enrollFactorType = "totp"
                    , enrollFactorFriendlyName = Nothing
                    , enrollFactorIssuer = Nothing
                    }
                `shouldBe` Right ()

        it "rejects webauthn as unsupported" $
            validateEnrollRequest
                EnrollFactorRequest
                    { enrollFactorType = "webauthn"
                    , enrollFactorFriendlyName = Nothing
                    , enrollFactorIssuer = Nothing
                    }
                `shouldBe` Left (EnrollUnsupportedFactorType "webauthn")

    describe "buildFactorResponse JSON" $
        it "has the expected top-level and totp sub-object keys" $ do
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
                    expectationFailure "JSON decode failed"
                Just (obj :: Object) -> do
                    let requiredFactorKeys = ["id", "type", "friendly_name", "totp"]
                    mapM_
                        ( \k ->
                            if KeyMap.member k obj
                                then pure ()
                                else expectationFailure ("missing top-level key: " <> show k)
                        )
                        requiredFactorKeys
                    case KeyMap.lookup "totp" obj of
                        Nothing ->
                            expectationFailure "missing totp sub-object"
                        Just (Object totpObj) -> do
                            let requiredTotpKeys = ["qr_code", "secret", "uri"]
                            mapM_
                                ( \k ->
                                    if KeyMap.member k totpObj
                                        then pure ()
                                        else expectationFailure ("totp missing key: " <> show k)
                                )
                                requiredTotpKeys
                        _ ->
                            expectationFailure "totp is not an object"
