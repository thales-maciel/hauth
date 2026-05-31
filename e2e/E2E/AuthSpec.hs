{-# LANGUAGE OverloadedStrings #-}

module E2E.AuthSpec (spec) where

import qualified Data.Aeson as Aeson
import qualified Data.Aeson.KeyMap as KeyMap
import qualified Data.Text as T
import E2E.Helpers (
    TestEnv (..),
    decodeBody,
    expectStatus,
    jsonGet,
    jsonPost,
    runApp,
 )
import Hauth.Env (withDatabaseConnection)
import Hauth.User (User (..), getUserByEmail)
import Test.Hspec (SpecWith, describe, it, shouldBe)

spec :: SpecWith TestEnv
spec = do
    describe "signup → verify → login → refresh → logout" $
        it "completes the happy path" \env -> do
            -- 1. Signup
            signupResp <- runApp env $ do
                jsonPost
                    "/signup"
                    (Aeson.object ["email" Aeson..= ("alice@example.com" :: T.Text), "password" Aeson..= ("correct horse" :: T.Text)])
                    Nothing
            expectStatus 200 signupResp
            (signupObj :: Aeson.Object) <- decodeBody signupResp
            KeyMap.member "id" signupObj `shouldBe` True
            KeyMap.member "confirmation_sent_at" signupObj `shouldBe` True

            -- 2. Fetch the confirmation_token directly from DB (no real email delivery in e2e)
            mUser <-
                withDatabaseConnection (testAppEnv env) (`getUserByEmail` "alice@example.com")
            user <- case mUser of
                Nothing -> error "expected user after signup"
                Just u -> pure u
            confirmationToken <- case userConfirmationToken user of
                Nothing -> error "expected confirmation_token after signup"
                Just t -> pure t

            -- 3. Verify the email
            verifyResp <- runApp env $ do
                jsonPost
                    "/verify"
                    ( Aeson.object
                        [ "type" Aeson..= ("signup" :: T.Text)
                        , "token" Aeson..= confirmationToken
                        ]
                    )
                    Nothing
            expectStatus 200 verifyResp
            (verifyObj :: Aeson.Object) <- decodeBody verifyResp
            KeyMap.member "access_token" verifyObj `shouldBe` True
            KeyMap.member "refresh_token" verifyObj `shouldBe` True

            -- 4. Login via password grant
            loginResp <- runApp env $ do
                jsonPost
                    "/token?grant_type=password"
                    ( Aeson.object
                        [ "email" Aeson..= ("alice@example.com" :: T.Text)
                        , "password" Aeson..= ("correct horse" :: T.Text)
                        ]
                    )
                    Nothing
            expectStatus 200 loginResp
            (loginObj :: Aeson.Object) <- decodeBody loginResp
            accessToken <- extractStringKey "access_token" loginObj
            refreshToken <- extractStringKey "refresh_token" loginObj
            KeyMap.member "user" loginObj `shouldBe` True

            -- Sanity: hit /user with the access token
            userResp <- runApp env $ jsonGet "/user" (Just accessToken)
            expectStatus 200 userResp

            -- 5. Refresh-token rotation
            refreshResp <- runApp env $ do
                jsonPost
                    "/token?grant_type=refresh_token"
                    (Aeson.object ["refresh_token" Aeson..= refreshToken])
                    Nothing
            expectStatus 200 refreshResp
            (refreshObj :: Aeson.Object) <- decodeBody refreshResp
            newAccess <- extractStringKey "access_token" refreshObj
            _ <- extractStringKey "refresh_token" refreshObj

            -- 6. Logout (revokes the session)
            logoutResp <- runApp env $ jsonPost "/logout" (Aeson.object []) (Just newAccess)
            expectStatus 204 logoutResp

    describe "login with unconfirmed email" $
        it "returns email_not_confirmed" \env -> do
            -- Signup but skip verify.
            _ <- runApp env $ do
                jsonPost
                    "/signup"
                    (Aeson.object ["email" Aeson..= ("bob@example.com" :: T.Text), "password" Aeson..= ("correct horse" :: T.Text)])
                    Nothing
            loginResp <- runApp env $ do
                jsonPost
                    "/token?grant_type=password"
                    ( Aeson.object
                        [ "email" Aeson..= ("bob@example.com" :: T.Text)
                        , "password" Aeson..= ("correct horse" :: T.Text)
                        ]
                    )
                    Nothing
            expectStatus 400 loginResp
            (errObj :: Aeson.Object) <- decodeBody loginResp
            KeyMap.lookup "error" errObj `shouldBe` Just (Aeson.String "email_not_confirmed")

    describe "login with wrong password" $
        it "returns invalid_grant" \env -> do
            _ <- runApp env $ do
                jsonPost
                    "/signup"
                    (Aeson.object ["email" Aeson..= ("carol@example.com" :: T.Text), "password" Aeson..= ("correct horse" :: T.Text)])
                    Nothing
            loginResp <- runApp env $ do
                jsonPost
                    "/token?grant_type=password"
                    ( Aeson.object
                        [ "email" Aeson..= ("carol@example.com" :: T.Text)
                        , "password" Aeson..= ("wrong" :: T.Text)
                        ]
                    )
                    Nothing
            expectStatus 400 loginResp
            (errObj :: Aeson.Object) <- decodeBody loginResp
            KeyMap.lookup "error" errObj `shouldBe` Just (Aeson.String "invalid_grant")

extractStringKey :: Aeson.Key -> Aeson.Object -> IO T.Text
extractStringKey k obj =
    case KeyMap.lookup k obj of
        Just (Aeson.String t) -> pure t
        Just other -> error ("key " <> show k <> " was not a string: " <> show other)
        Nothing -> error ("missing key " <> show k <> " in " <> show obj)
