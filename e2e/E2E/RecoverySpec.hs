{-# LANGUAGE OverloadedStrings #-}

module E2E.RecoverySpec (spec) where

import qualified Data.Aeson as Aeson
import qualified Data.Aeson.KeyMap as KeyMap
import qualified Data.Text as T
import Database.PostgreSQL.Simple (Only (..), query)
import E2E.Helpers (
    TestEnv (..),
    decodeBody,
    expectStatus,
    jsonPost,
    runApp,
 )
import Hauth.Env (withDatabaseConnection)
import Hauth.User (User (..), getUserByEmail)
import Test.Hspec (SpecWith, describe, it, shouldBe)

spec :: SpecWith TestEnv
spec = do
    describe "recover → verify(type=recovery) → login with new password" $
        it "completes the happy path" \env -> do
            _ <-
                runApp env $
                    jsonPost
                        "/signup"
                        (Aeson.object ["email" Aeson..= ("frank@example.com" :: T.Text), "password" Aeson..= ("old password" :: T.Text)])
                        Nothing
            confirmationToken <- readConfirmationToken env "frank@example.com"
            _ <-
                runApp env $
                    jsonPost
                        "/verify"
                        (Aeson.object ["type" Aeson..= ("signup" :: T.Text), "token" Aeson..= confirmationToken])
                        Nothing

            recoverResp <-
                runApp env $
                    jsonPost "/recover" (Aeson.object ["email" Aeson..= ("frank@example.com" :: T.Text)]) Nothing
            expectStatus 200 recoverResp
            (recoverObj :: Aeson.Object) <- decodeBody recoverResp
            KeyMap.member "message" recoverObj `shouldBe` True

            recoveryToken <- readRecoveryToken env "frank@example.com"

            verifyResp <-
                runApp env $
                    jsonPost
                        "/verify"
                        ( Aeson.object
                            [ "type" Aeson..= ("recovery" :: T.Text)
                            , "token" Aeson..= recoveryToken
                            , "password" Aeson..= ("new password" :: T.Text)
                            ]
                        )
                        Nothing
            expectStatus 200 verifyResp

            loginNew <-
                runApp env $
                    jsonPost
                        "/token?grant_type=password"
                        ( Aeson.object
                            [ "email" Aeson..= ("frank@example.com" :: T.Text)
                            , "password" Aeson..= ("new password" :: T.Text)
                            ]
                        )
                        Nothing
            expectStatus 200 loginNew

            loginOld <-
                runApp env $
                    jsonPost
                        "/token?grant_type=password"
                        ( Aeson.object
                            [ "email" Aeson..= ("frank@example.com" :: T.Text)
                            , "password" Aeson..= ("old password" :: T.Text)
                            ]
                        )
                        Nothing
            expectStatus 400 loginOld

    describe "recover with unknown email" $
        it "still returns 200 (anti-enumeration)" \env -> do
            resp <-
                runApp env $
                    jsonPost "/recover" (Aeson.object ["email" Aeson..= ("nobody@example.com" :: T.Text)]) Nothing
            expectStatus 200 resp

readConfirmationToken :: TestEnv -> T.Text -> IO T.Text
readConfirmationToken env email = do
    mUser <- withDatabaseConnection (testAppEnv env) (`getUserByEmail` email)
    case mUser >>= userConfirmationToken of
        Just t -> pure t
        Nothing -> error ("readConfirmationToken missing for " <> T.unpack email)

readRecoveryToken :: TestEnv -> T.Text -> IO T.Text
readRecoveryToken env email = do
    rows <-
        withDatabaseConnection (testAppEnv env) \conn ->
            query
                conn
                "SELECT recovery_token FROM auth.users WHERE email = ?"
                (Only email)
    case rows of
        [Only (Just t)] -> pure t
        [Only Nothing] -> error ("readRecoveryToken null for " <> T.unpack email)
        _ -> error ("readRecoveryToken no row for " <> T.unpack email)
