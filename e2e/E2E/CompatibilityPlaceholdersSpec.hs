{-# LANGUAGE OverloadedStrings #-}

module E2E.CompatibilityPlaceholdersSpec (spec) where

import qualified Data.Aeson as Aeson
import qualified Data.Aeson.KeyMap as KeyMap
import qualified Data.Text as T
import E2E.Helpers (
    TestEnv,
    decodeBody,
    expectStatus,
    jsonDelete,
    jsonGet,
    jsonPost,
    jsonPut,
    mintServiceRoleJwt,
    mintSessionJwt,
    runApp,
 )
import Network.Wai.Test (SResponse)
import Test.Hspec (SpecWith, describe, it, shouldBe)

spec :: SpecWith TestEnv
spec = do
    describe "documented 501 compatibility placeholders" do
        it "DELETE /factors/:factor_id returns JSON 501" \env -> do
            jwt <- mintSessionJwt env "00000000-0000-0000-0000-000000000100" "00000000-0000-0000-0000-000000000101"
            resp <-
                runApp env $
                    jsonDelete
                        "/factors/00000000-0000-0000-0000-000000000102"
                        (Just jwt)
            expectNotImplemented resp

        it "DELETE /admin/users/:user_id/identities/:identity_id returns JSON 501" \env -> do
            jwt <- mintServiceRoleJwt env
            resp <-
                runApp env $
                    jsonDelete
                        "/admin/users/00000000-0000-0000-0000-000000000200/identities/00000000-0000-0000-0000-000000000201"
                        (Just jwt)
            expectNotImplemented resp

        it "POST /admin/generate_link returns JSON 501" \env -> do
            jwt <- mintServiceRoleJwt env
            resp <-
                runApp env $
                    jsonPost
                        "/admin/generate_link"
                        ( Aeson.object
                            [ "email" Aeson..= ("placeholder@example.com" :: T.Text)
                            , "type" Aeson..= ("signup" :: T.Text)
                            ]
                        )
                        (Just jwt)
            expectNotImplemented resp

        it "GET /admin/providers returns JSON 501" \env -> do
            jwt <- mintServiceRoleJwt env
            resp <- runApp env $ jsonGet "/admin/providers" (Just jwt)
            expectNotImplemented resp

        it "PUT /admin/providers returns JSON 501" \env -> do
            jwt <- mintServiceRoleJwt env
            resp <-
                runApp env $
                    jsonPut
                        "/admin/providers"
                        (Aeson.object ["providers" Aeson..= ["google" :: T.Text]])
                        (Just jwt)
            expectNotImplemented resp

        it "GET /admin/email_templates returns JSON 501" \env -> do
            jwt <- mintServiceRoleJwt env
            resp <- runApp env $ jsonGet "/admin/email_templates" (Just jwt)
            expectNotImplemented resp

        it "PUT /admin/email_templates returns JSON 501" \env -> do
            jwt <- mintServiceRoleJwt env
            resp <-
                runApp env $
                    jsonPut
                        "/admin/email_templates"
                        (Aeson.object ["templates" Aeson..= ["recovery" :: T.Text]])
                        (Just jwt)
            expectNotImplemented resp

        it "GET /admin/webhook_deliveries returns JSON 501" \env -> do
            jwt <- mintServiceRoleJwt env
            resp <- runApp env $ jsonGet "/admin/webhook_deliveries" (Just jwt)
            expectNotImplemented resp

        it "GET /admin/webhook_deliveries/:delivery_id returns JSON 501" \env -> do
            jwt <- mintServiceRoleJwt env
            resp <-
                runApp env $
                    jsonGet
                        "/admin/webhook_deliveries/00000000-0000-0000-0000-000000000300"
                        (Just jwt)
            expectNotImplemented resp

        it "POST /admin/webhook_deliveries/:delivery_id/retry returns JSON 501" \env -> do
            jwt <- mintServiceRoleJwt env
            resp <-
                runApp env $
                    jsonPost
                        "/admin/webhook_deliveries/00000000-0000-0000-0000-000000000300/retry"
                        Aeson.Null
                        (Just jwt)
            expectNotImplemented resp

expectNotImplemented :: SResponse -> IO ()
expectNotImplemented resp = do
    expectStatus 501 resp
    (obj :: Aeson.Object) <- decodeBody resp
    KeyMap.lookup "code" obj `shouldBe` Just (Aeson.String "not_implemented")
    KeyMap.lookup "msg" obj `shouldBe` Just (Aeson.String "Not implemented")
