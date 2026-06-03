module Spec.Mfa.VerifySpec (spec) where

import qualified Data.Aeson as Aeson
import qualified Data.Aeson.KeyMap as KeyMap
import qualified Data.ByteString as BS
import qualified Data.Text as T
import Data.Time.Clock.POSIX (POSIXTime)
import Hauth.API.Types (
    ChallengeFactorResponse (..),
    SessionResponse (..),
 )
import Hauth.Mfa.Totp (TotpSecret (..))
import Hauth.Mfa.TotpVerify (
    TotpVerificationResult (..),
    currentTimeStep,
    totpCodeAtStep,
    verifyTotpCode,
 )
import Test.Hspec (Spec, describe, expectationFailure, it, shouldBe)

-- | The 20-byte ASCII secret from RFC 6238: "12345678901234567890"
rfcSecret :: TotpSecret
rfcSecret =
    TotpSecret
        ( BS.pack
            [ 0x31
            , 0x32
            , 0x33
            , 0x34
            , 0x35
            , 0x36
            , 0x37
            , 0x38
            , 0x39
            , 0x30
            , 0x31
            , 0x32
            , 0x33
            , 0x34
            , 0x35
            , 0x36
            , 0x37
            , 0x38
            , 0x39
            , 0x30
            ]
        )

spec :: Spec
spec = do
    describe "currentTimeStep" $ do
        it "1234567890 = floor(1234567890/30)" $
            currentTimeStep 1234567890 `shouldBe` 41152263
        it "0 = 0" $
            currentTimeStep 0 `shouldBe` 0
        it "30 = 1" $
            currentTimeStep 30 `shouldBe` 1
        it "59 = 1" $
            currentTimeStep 59 `shouldBe` 1
        it "60 = 2" $
            currentTimeStep 60 `shouldBe` 2

    describe "totpCodeAtStep" $ do
        -- RFC 6238 step=1 (t=30..59) — 8-digit is 94287082 -> 6-digit "287082"
        it "rfcSecret 1 = 287082" $
            totpCodeAtStep rfcSecret 1 `shouldBe` "287082"
        -- Step 2 independently verified
        it "rfcSecret 2 = 359152" $
            totpCodeAtStep rfcSecret 2 `shouldBe` "359152"
        -- Always 6 characters (zero-padded)
        it "always 6 chars" $
            T.length (totpCodeAtStep rfcSecret 1) `shouldBe` 6

    describe "verifyTotpCode core verification" $ do
        it "correct code at exact step" $
            let step1 = 1 :: Int
                step1Time = fromIntegral step1 * 30 :: POSIXTime
                code1 = totpCodeAtStep rfcSecret (fromIntegral step1)
             in verifyTotpCode rfcSecret code1 step1Time `shouldBe` TotpVerified
        it "000000 is invalid for step 1 (unless coincidence)" $
            let step1 = 1 :: Int
                step1Time = fromIntegral step1 * 30 :: POSIXTime
             in verifyTotpCode rfcSecret "000000" step1Time `shouldBe` TotpInvalid

    describe "verifyTotpCode skew window" $ do
        it "code from step N-1 verifies at step N (skew -1)" $
            let step10 = 10 :: Int
                step10Time = fromIntegral step10 * 30 :: POSIXTime
                codeStep9 = totpCodeAtStep rfcSecret 9
             in verifyTotpCode rfcSecret codeStep9 step10Time `shouldBe` TotpVerified
        it "code from step N+1 verifies at step N (skew +1)" $
            let step10 = 10 :: Int
                step10Time = fromIntegral step10 * 30 :: POSIXTime
                codeStep11 = totpCodeAtStep rfcSecret 11
             in verifyTotpCode rfcSecret codeStep11 step10Time `shouldBe` TotpVerified
        it "code from step N-2 does not verify at step N" $
            let step10 = 10 :: Int
                step10Time = fromIntegral step10 * 30 :: POSIXTime
                codeStep8 = totpCodeAtStep rfcSecret 8
             in verifyTotpCode rfcSecret codeStep8 step10Time `shouldBe` TotpInvalid

    describe "verifyTotpCode wrong-length codes" $ do
        it "5-digit code is invalid" $
            let step1Time = fromIntegral (1 :: Int) * 30 :: POSIXTime
             in verifyTotpCode rfcSecret "12345" step1Time `shouldBe` TotpInvalid
        it "7-digit code is invalid" $
            let step1Time = fromIntegral (1 :: Int) * 30 :: POSIXTime
             in verifyTotpCode rfcSecret "1234567" step1Time `shouldBe` TotpInvalid
        it "empty code is invalid" $
            let step1Time = fromIntegral (1 :: Int) * 30 :: POSIXTime
             in verifyTotpCode rfcSecret "" step1Time `shouldBe` TotpInvalid

    describe "ChallengeFactorResponse JSON shape" $
        it "round-trip encodes id and expires_at" $ do
            let now = read "2024-01-01 00:00:00 UTC"
                resp =
                    ChallengeFactorResponse
                        { challengeFactorId = "00000000-0000-0000-0000-000000000001"
                        , challengeExpiresAt = now
                        }
            case Aeson.decode (Aeson.encode resp) of
                Nothing ->
                    expectationFailure "ChallengeFactorResponse: JSON round-trip decode failed"
                Just obj ->
                    mapM_
                        ( \k ->
                            if KeyMap.member k (obj :: KeyMap.KeyMap Aeson.Value)
                                then pure ()
                                else expectationFailure ("ChallengeFactorResponse JSON: missing key: " <> show k)
                        )
                        ["id", "expires_at"]

    describe "VerifyFactorResponse JSON shape" $
        it "round-trips and contains required top-level keys" $ do
            let sessUser =
                    Aeson.object
                        [ "id" Aeson..= ("00000000-0000-0000-0000-000000000000" :: T.Text)
                        , "aud" Aeson..= ("authenticated" :: T.Text)
                        , "role" Aeson..= ("authenticated" :: T.Text)
                        , "email" Aeson..= ("user@example.com" :: T.Text)
                        , "email_confirmed_at" Aeson..= (Nothing :: Maybe T.Text)
                        , "created_at" Aeson..= ("2024-01-01T00:00:00Z" :: T.Text)
                        , "updated_at" Aeson..= ("2024-01-01T00:00:00Z" :: T.Text)
                        , "app_metadata" Aeson..= Aeson.object []
                        , "user_metadata" Aeson..= Aeson.object []
                        ]
                sessionJson =
                    Aeson.object
                        [ "access_token" Aeson..= ("tok" :: T.Text)
                        , "token_type" Aeson..= ("bearer" :: T.Text)
                        , "expires_in" Aeson..= (3600 :: Int)
                        , "refresh_token" Aeson..= ("rtok" :: T.Text)
                        , "user" Aeson..= sessUser
                        ]
                verifyJson =
                    Aeson.object
                        [ "access_token" Aeson..= ("tok" :: T.Text)
                        , "token_type" Aeson..= ("bearer" :: T.Text)
                        , "expires_in" Aeson..= (3600 :: Int)
                        , "refresh_token" Aeson..= ("rtok" :: T.Text)
                        , "user" Aeson..= sessUser
                        ]
            case Aeson.decode (Aeson.encode sessionJson) :: Maybe SessionResponse of
                Nothing ->
                    expectationFailure "SessionResponse JSON: decode failed"
                Just _ -> pure ()
            case Aeson.decode (Aeson.encode verifyJson) :: Maybe Aeson.Value of
                Nothing ->
                    expectationFailure "VerifyFactorResponse JSON: encode failed"
                Just (Aeson.Object obj) ->
                    mapM_
                        ( \k ->
                            if KeyMap.member k obj
                                then pure ()
                                else expectationFailure ("VerifyFactorResponse JSON: missing top-level key: " <> show k)
                        )
                        ["access_token", "token_type", "expires_in", "refresh_token", "user"]
                Just _ ->
                    expectationFailure "VerifyFactorResponse JSON: not an object"
