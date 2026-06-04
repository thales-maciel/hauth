-- | Wire-shape coverage for the MFA endpoints.
module Spec.API.Golden.MfaSpec (spec) where

import Hauth.API.Types
import Spec.API.Golden.Helpers (
    canonicalFactorResponse,
    canonicalSessionResponse,
    encodeShape,
    factorResponseJson,
    roundTrip,
    sessionResponseJson,
    t0,
 )
import Test.Hspec (Spec, describe, it)

spec :: Spec
spec = describe "MFA" $ do
    it "ListFactorsResponse" $
        roundTrip
            "ListFactorsResponse"
            ListFactorsResponse
                { listFactorsAll = [canonicalFactorResponse]
                , listFactorsTotp = [canonicalFactorResponse]
                , listFactorsPhone = []
                }
            ("{\"factors\":[" <> factorResponseJson <> "],\"totp\":[" <> factorResponseJson <> "],\"phone\":[]}")

    it "EnrollFactorRequest" $
        roundTrip
            "EnrollFactorRequest"
            EnrollFactorRequest
                { enrollFactorType = "totp"
                , enrollFactorFriendlyName = Just "phone"
                , enrollFactorIssuer = Just "Hauth"
                }
            "{\"factor_type\":\"totp\",\"friendly_name\":\"phone\",\"issuer\":\"Hauth\"}"

    it "FactorResponse" $
        roundTrip
            "FactorResponse"
            canonicalFactorResponse
            factorResponseJson

    it "ChallengeFactorRequest" $
        roundTrip
            "ChallengeFactorRequest"
            ChallengeFactorRequest{challengeFactorChannel = Just "sms"}
            "{\"channel\":\"sms\"}"

    -- ChallengeFactorResponse's ToJSON adds "type":"totp"; FromJSON ignores it.
    -- A strict round-trip would re-add "type" on re-encode, so we just verify
    -- the encoded shape.
    it "ChallengeFactorResponse" $
        encodeShape
            "ChallengeFactorResponse"
            ChallengeFactorResponse
                { challengeFactorId = "00000000-0000-0000-0000-000000000000"
                , challengeExpiresAt = t0
                }
            "{\"id\":\"00000000-0000-0000-0000-000000000000\",\"type\":\"totp\",\"expires_at\":\"2026-01-02T03:04:05Z\"}"

    it "VerifyFactorRequest" $
        roundTrip
            "VerifyFactorRequest"
            VerifyFactorRequest{verifyFactorChallengeId = "00000000-0000-0000-0000-000000000000", verifyFactorCode = "123456"}
            "{\"challenge_id\":\"00000000-0000-0000-0000-000000000000\",\"code\":\"123456\"}"

    it "VerifyFactorResponse" $
        roundTrip
            "VerifyFactorResponse"
            (VerifyFactorResponse canonicalSessionResponse)
            sessionResponseJson
