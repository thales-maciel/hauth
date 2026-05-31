module Spec.Mfa.VerifySpec (runSpec) where

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
import Spec.TestUtils (assertEqual)

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

runSpec :: IO ()
runSpec = do
    -- -----------------------------------------------------------------
    -- currentTimeStep
    -- -----------------------------------------------------------------
    assertEqual
        "currentTimeStep 1234567890 = floor(1234567890/30)"
        41152263
        (currentTimeStep 1234567890)

    assertEqual
        "currentTimeStep 0 = 0"
        0
        (currentTimeStep 0)

    assertEqual
        "currentTimeStep 30 = 1"
        1
        (currentTimeStep 30)

    assertEqual
        "currentTimeStep 59 = 1"
        1
        (currentTimeStep 59)

    assertEqual
        "currentTimeStep 60 = 2"
        2
        (currentTimeStep 60)

    -- -----------------------------------------------------------------
    -- totpCodeAtStep — fixed 6-digit vectors derived from RFC 6238 SHA1
    -- secret (our 6-digit truncation of the RFC's 8-digit vectors)
    -- -----------------------------------------------------------------

    -- RFC 6238 step=1 (t=30..59) — 8-digit is 94287082 → 6-digit "287082"
    assertEqual
        "totpCodeAtStep rfcSecret 1 = 287082"
        "287082"
        (totpCodeAtStep rfcSecret 1)

    -- Step 2 independently verified
    assertEqual
        "totpCodeAtStep rfcSecret 2 = 359152"
        "359152"
        (totpCodeAtStep rfcSecret 2)

    -- Always 6 characters (zero-padded)
    assertEqual
        "totpCodeAtStep always 6 chars"
        6
        (T.length (totpCodeAtStep rfcSecret 1))

    -- -----------------------------------------------------------------
    -- verifyTotpCode — core verification
    -- -----------------------------------------------------------------

    let step1 = 1 :: Int
        step1Time = fromIntegral step1 * 30 :: POSIXTime
        code1 = totpCodeAtStep rfcSecret (fromIntegral step1)

    assertEqual
        "verifyTotpCode: correct code at exact step"
        TotpVerified
        (verifyTotpCode rfcSecret code1 step1Time)

    assertEqual
        "verifyTotpCode: 000000 is invalid for step 1 (unless coincidence)"
        TotpInvalid
        (verifyTotpCode rfcSecret "000000" step1Time)

    -- -----------------------------------------------------------------
    -- ±1 skew window
    -- -----------------------------------------------------------------

    let step10 = 10 :: Int
        step10Time = fromIntegral step10 * 30 :: POSIXTime
        codeStep9 = totpCodeAtStep rfcSecret 9
        codeStep11 = totpCodeAtStep rfcSecret 11
        codeStep8 = totpCodeAtStep rfcSecret 8

    -- Code from step N-1 verifies when "now" is step N
    assertEqual
        "verifyTotpCode: code from step N-1 verifies at step N (skew -1)"
        TotpVerified
        (verifyTotpCode rfcSecret codeStep9 step10Time)

    -- Code from step N+1 verifies when "now" is step N
    assertEqual
        "verifyTotpCode: code from step N+1 verifies at step N (skew +1)"
        TotpVerified
        (verifyTotpCode rfcSecret codeStep11 step10Time)

    -- Code from step N-2 does NOT verify when "now" is step N
    assertEqual
        "verifyTotpCode: code from step N-2 does not verify at step N"
        TotpInvalid
        (verifyTotpCode rfcSecret codeStep8 step10Time)

    -- -----------------------------------------------------------------
    -- Wrong-length codes
    -- -----------------------------------------------------------------

    assertEqual
        "verifyTotpCode: 5-digit code is invalid"
        TotpInvalid
        (verifyTotpCode rfcSecret "12345" step1Time)

    assertEqual
        "verifyTotpCode: 7-digit code is invalid"
        TotpInvalid
        (verifyTotpCode rfcSecret "1234567" step1Time)

    assertEqual
        "verifyTotpCode: empty code is invalid"
        TotpInvalid
        (verifyTotpCode rfcSecret "" step1Time)

    -- -----------------------------------------------------------------
    -- JSON shape — ChallengeFactorResponse
    -- -----------------------------------------------------------------

    do
        let now = read "2024-01-01 00:00:00 UTC"
            resp =
                ChallengeFactorResponse
                    { challengeFactorId = "00000000-0000-0000-0000-000000000001"
                    , challengeExpiresAt = now
                    }
        case Aeson.decode (Aeson.encode resp) of
            Nothing ->
                fail "ChallengeFactorResponse: JSON round-trip decode failed"
            Just obj ->
                mapM_
                    ( \k ->
                        if KeyMap.member k (obj :: KeyMap.KeyMap Aeson.Value)
                            then pure ()
                            else fail ("ChallengeFactorResponse JSON: missing key: " <> show k)
                    )
                    ["id", "expires_at"]

    -- -----------------------------------------------------------------
    -- JSON shape — VerifyFactorResponse
    -- -----------------------------------------------------------------

    do
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
                fail "SessionResponse JSON: decode failed"
            Just _ -> pure ()
        case Aeson.decode (Aeson.encode verifyJson) :: Maybe Aeson.Value of
            Nothing ->
                fail "VerifyFactorResponse JSON: encode failed"
            Just (Aeson.Object obj) ->
                mapM_
                    ( \k ->
                        if KeyMap.member k obj
                            then pure ()
                            else fail ("VerifyFactorResponse JSON: missing top-level key: " <> show k)
                    )
                    ["access_token", "token_type", "expires_in", "refresh_token", "user"]
            Just _ ->
                fail "VerifyFactorResponse JSON: not an object"
