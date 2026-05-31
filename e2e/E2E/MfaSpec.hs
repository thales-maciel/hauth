{-# LANGUAGE OverloadedStrings #-}

module E2E.MfaSpec (spec) where

import qualified Data.Aeson as Aeson
import qualified Data.Aeson.KeyMap as KeyMap
import qualified Data.Text as T
import qualified Data.Text.Encoding as TE
import Data.Time.Clock.POSIX (getPOSIXTime)
import E2E.Helpers (
    TestEnv (..),
    decodeBody,
    expectStatus,
    jsonPost,
    runApp,
 )
import Hauth.Env (withDatabaseConnection)
import Hauth.Mfa.Totp (TotpSecret (..), decodeBase32)
import Hauth.Mfa.TotpVerify (currentTimeStep, totpCodeAtStep)
import Hauth.User (User (..), getUserByEmail)
import Test.Hspec (SpecWith, describe, it, shouldBe)

spec :: SpecWith TestEnv
spec = do
    describe "enroll → challenge → verify TOTP factor" $
        it "elevates the session to aal2" \env -> do
            access <- bootstrapVerifiedUser env "gina@example.com" "correct horse"

            -- Enroll the factor.
            enrollResp <-
                runApp env $
                    jsonPost
                        "/factors"
                        (Aeson.object ["factor_type" Aeson..= ("totp" :: T.Text), "friendly_name" Aeson..= ("Phone" :: T.Text)])
                        (Just access)
            expectStatus 200 enrollResp
            (enrollObj :: Aeson.Object) <- decodeBody enrollResp
            factorId <- extractString "id" enrollObj
            totp <- case KeyMap.lookup "totp" enrollObj of
                Just (Aeson.Object t) -> pure t
                other -> error ("expected totp object; got " <> show other)
            secretB32 <- extractString "secret" totp
            secretBytes <- case decodeBase32 secretB32 of
                Just bs -> pure bs
                Nothing -> error ("could not decode TOTP secret: " <> T.unpack secretB32)

            -- Challenge (mostly a no-op for TOTP).
            challengeResp <-
                runApp env $
                    jsonPost
                        ("/factors/" <> TE.encodeUtf8 factorId <> "/challenge")
                        (Aeson.object [])
                        (Just access)
            expectStatus 200 challengeResp
            (challengeObj :: Aeson.Object) <- decodeBody challengeResp
            challengeId <- extractString "id" challengeObj

            -- Compute a valid code for the current time and submit it.
            now <- getPOSIXTime
            let code = totpCodeAtStep (TotpSecret secretBytes) (currentTimeStep now)
            verifyResp <-
                runApp env $
                    jsonPost
                        ("/factors/" <> TE.encodeUtf8 factorId <> "/verify")
                        ( Aeson.object
                            [ "challenge_id" Aeson..= challengeId
                            , "code" Aeson..= code
                            ]
                        )
                        (Just access)
            expectStatus 200 verifyResp
            (verifyObj :: Aeson.Object) <- decodeBody verifyResp
            KeyMap.member "access_token" verifyObj `shouldBe` True

    describe "verify with wrong code" $
        it "returns 401 invalid_code" \env -> do
            access <- bootstrapVerifiedUser env "henry@example.com" "correct horse"
            enrollResp <-
                runApp env $
                    jsonPost
                        "/factors"
                        (Aeson.object ["factor_type" Aeson..= ("totp" :: T.Text)])
                        (Just access)
            (enrollObj :: Aeson.Object) <- decodeBody enrollResp
            factorId <- extractString "id" enrollObj
            challengeResp <-
                runApp env $
                    jsonPost
                        ("/factors/" <> TE.encodeUtf8 factorId <> "/challenge")
                        (Aeson.object [])
                        (Just access)
            (challengeObj :: Aeson.Object) <- decodeBody challengeResp
            challengeId <- extractString "id" challengeObj
            verifyResp <-
                runApp env $
                    jsonPost
                        ("/factors/" <> TE.encodeUtf8 factorId <> "/verify")
                        ( Aeson.object
                            [ "challenge_id" Aeson..= challengeId
                            , "code" Aeson..= ("000000" :: T.Text)
                            ]
                        )
                        (Just access)
            expectStatus 401 verifyResp

-- Shared signup+verify bootstrap, returning the user's bearer access token.
bootstrapVerifiedUser :: TestEnv -> T.Text -> T.Text -> IO T.Text
bootstrapVerifiedUser env email password = do
    _ <-
        runApp env $
            jsonPost
                "/signup"
                (Aeson.object ["email" Aeson..= email, "password" Aeson..= password])
                Nothing
    mUser <- withDatabaseConnection (testAppEnv env) (`getUserByEmail` email)
    user <- case mUser of
        Just u -> pure u
        Nothing -> error "bootstrapVerifiedUser: no user"
    token <- case userConfirmationToken user of
        Just t -> pure t
        Nothing -> error "bootstrapVerifiedUser: no confirmation_token"
    verifyResp <-
        runApp env $
            jsonPost
                "/verify"
                (Aeson.object ["type" Aeson..= ("signup" :: T.Text), "token" Aeson..= token])
                Nothing
    (obj :: Aeson.Object) <- decodeBody verifyResp
    extractString "access_token" obj

extractString :: Aeson.Key -> Aeson.Object -> IO T.Text
extractString k obj = case KeyMap.lookup k obj of
    Just (Aeson.String t) -> pure t
    other -> error ("expected string at " <> show k <> "; got " <> show other)
