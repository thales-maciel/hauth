{-# LANGUAGE OverloadedStrings #-}

module E2E.UserSpec (spec) where

import qualified Data.Aeson as Aeson
import qualified Data.Aeson.KeyMap as KeyMap
import qualified Data.Text as T
import E2E.Helpers (
    TestEnv (..),
    decodeBody,
    expectStatus,
    jsonGet,
    jsonPost,
    jsonPut,
    runApp,
 )
import Hauth.Env (withDatabaseConnection)
import Hauth.User (User (..), getUserByEmail)
import Test.Hspec (SpecWith, describe, it, shouldBe)

spec :: SpecWith TestEnv
spec = do
    describe "GET /user" $
        it "returns the authenticated user" \env -> do
            access <- bootstrapVerifiedUser env "dan@example.com" "correct horse"
            resp <- runApp env $ jsonGet "/user" (Just access)
            expectStatus 200 resp
            (obj :: Aeson.Object) <- decodeBody resp
            KeyMap.lookup "email" obj `shouldBe` Just (Aeson.String "dan@example.com")
            KeyMap.lookup "role" obj `shouldBe` Just (Aeson.String "authenticated")

    describe "GET /user without bearer" $
        it "rejects with 401" \env -> do
            resp <- runApp env $ jsonGet "/user" Nothing
            expectStatus 401 resp

    describe "PUT /user updates user_metadata" $
        it "returns 200 and reflects the change on subsequent GET" \env -> do
            access <- bootstrapVerifiedUser env "eve@example.com" "correct horse"
            let putBody =
                    Aeson.object
                        ["data" Aeson..= Aeson.object ["display_name" Aeson..= ("Eve" :: T.Text)]]
            putResp <- runApp env $ jsonPut "/user" putBody (Just access)
            expectStatus 200 putResp
            getResp <- runApp env $ jsonGet "/user" (Just access)
            expectStatus 200 getResp
            (obj :: Aeson.Object) <- decodeBody getResp
            case KeyMap.lookup "user_metadata" obj of
                Just (Aeson.Object m) ->
                    KeyMap.lookup "display_name" m `shouldBe` Just (Aeson.String "Eve")
                other -> error ("expected user_metadata object, got " <> show other)

-- Signup + read confirmation_token from DB + verify; return the access token.
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
        Nothing -> error "bootstrapVerifiedUser: user not found after signup"
        Just u -> pure u
    token <- case userConfirmationToken user of
        Nothing -> error "bootstrapVerifiedUser: no confirmation_token"
        Just t -> pure t
    verifyResp <-
        runApp env $
            jsonPost
                "/verify"
                (Aeson.object ["type" Aeson..= ("signup" :: T.Text), "token" Aeson..= token])
                Nothing
    (obj :: Aeson.Object) <- decodeBody verifyResp
    case KeyMap.lookup "access_token" obj of
        Just (Aeson.String t) -> pure t
        other -> error ("bootstrapVerifiedUser: no access_token; got " <> show other)
