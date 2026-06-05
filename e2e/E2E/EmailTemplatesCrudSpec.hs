{-# LANGUAGE OverloadedStrings #-}

module E2E.EmailTemplatesCrudSpec (spec) where

import Control.Exception (bracket_)
import qualified Data.Aeson as Aeson
import qualified Data.Aeson.KeyMap as KeyMap
import qualified Data.Text as T
import Database.PostgreSQL.Simple (execute_)
import E2E.Helpers (
    TestEnv (..),
    decodeBody,
    expectStatus,
    jsonDelete,
    jsonGet,
    jsonPut,
    mintServiceRoleJwt,
    mintSessionJwt,
    runApp,
 )
import Hauth.Env (withDatabaseConnection)
import Test.Hspec (SpecWith, describe, it, shouldBe)

spec :: SpecWith TestEnv
spec = do
    describe "GET /admin/email-templates" $ do
        it "returns 401 without auth" \env -> do
            resp <- runApp env $ jsonGet "/admin/email-templates" Nothing
            expectStatus 401 resp

        it "returns 401 with session JWT (not service-role)" \env -> do
            sessionJwt <- mintSessionJwt env "00000000-0000-0000-0000-000000000099" "00000000-0000-0000-0000-000000000001"
            resp <- runApp env $ jsonGet "/admin/email-templates" (Just sessionJwt)
            expectStatus 401 resp

        it "returns list of seeded templates with service-role JWT" \env -> do
            svcJwt <- mintServiceRoleJwt env
            resp <- runApp env $ jsonGet "/admin/email-templates" (Just svcJwt)
            expectStatus 200 resp
            (obj :: Aeson.Object) <- decodeBody resp
            KeyMap.member "templates" obj `shouldBe` True

    describe "GET /admin/email-templates/{name}" $ do
        it "returns 401 without auth" \env -> do
            resp <- runApp env $ jsonGet "/admin/email-templates/confirmation" Nothing
            expectStatus 401 resp

        it "returns a seeded template" \env -> do
            svcJwt <- mintServiceRoleJwt env
            resp <- runApp env $ jsonGet "/admin/email-templates/confirmation" (Just svcJwt)
            expectStatus 200 resp
            (obj :: Aeson.Object) <- decodeBody resp
            KeyMap.lookup "name" obj `shouldBe` Just (Aeson.String "confirmation")

        it "returns 404 for an unknown name" \env -> do
            svcJwt <- mintServiceRoleJwt env
            resp <- runApp env $ jsonGet "/admin/email-templates/does-not-exist" (Just svcJwt)
            expectStatus 404 resp

    describe "PUT /admin/email-templates/{name}" $ do
        it "returns 401 without auth" \env -> do
            resp <-
                runApp env $
                    jsonPut
                        "/admin/email-templates/confirmation"
                        ( Aeson.object
                            [ "subject" Aeson..= ("Updated subject" :: T.Text)
                            , "body_text" Aeson..= ("text" :: T.Text)
                            , "body_html" Aeson..= ("<p>html</p>" :: T.Text)
                            ]
                        )
                        Nothing
            expectStatus 401 resp

        it "returns 400 for a name not in the allowlist" \env -> do
            svcJwt <- mintServiceRoleJwt env
            resp <-
                runApp env $
                    jsonPut
                        "/admin/email-templates/not-a-valid-name"
                        ( Aeson.object
                            [ "subject" Aeson..= ("s" :: T.Text)
                            , "body_text" Aeson..= ("t" :: T.Text)
                            , "body_html" Aeson..= ("h" :: T.Text)
                            ]
                        )
                        (Just svcJwt)
            expectStatus 400 resp
            (obj :: Aeson.Object) <- decodeBody resp
            KeyMap.lookup "error" obj `shouldBe` Just (Aeson.String "unknown_template")

        it "upserts a template and subsequent GET returns the updated content" \env -> do
            svcJwt <- mintServiceRoleJwt env
            let resetRow =
                    withDatabaseConnection
                        (testAppEnv env)
                        ( `execute_`
                            "UPDATE auth.email_templates \
                            \SET subject = 'Confirm your email address' \
                            \WHERE name = 'confirmation'"
                        )
            bracket_ (pure ()) resetRow $ do
                putResp <-
                    runApp env $
                        jsonPut
                            "/admin/email-templates/confirmation"
                            ( Aeson.object
                                [ "subject" Aeson..= ("Custom subject" :: T.Text)
                                , "body_text" Aeson..= ("custom text body" :: T.Text)
                                , "body_html" Aeson..= ("<p>custom html</p>" :: T.Text)
                                ]
                            )
                            (Just svcJwt)
                expectStatus 200 putResp
                (putObj :: Aeson.Object) <- decodeBody putResp
                KeyMap.lookup "name" putObj `shouldBe` Just (Aeson.String "confirmation")
                KeyMap.lookup "subject" putObj `shouldBe` Just (Aeson.String "Custom subject")

                getResp <- runApp env $ jsonGet "/admin/email-templates/confirmation" (Just svcJwt)
                expectStatus 200 getResp
                (getObj :: Aeson.Object) <- decodeBody getResp
                KeyMap.lookup "subject" getObj `shouldBe` Just (Aeson.String "Custom subject")

    describe "DELETE /admin/email-templates/{name}" $ do
        it "returns 401 without auth" \env -> do
            resp <- runApp env $ jsonDelete "/admin/email-templates/recovery" Nothing
            expectStatus 401 resp

        it "deletes a row; subsequent GET returns 404" \env -> do
            svcJwt <- mintServiceRoleJwt env
            -- Re-seed the row after the test using bracket_
            let reseedRow =
                    withDatabaseConnection
                        (testAppEnv env)
                        ( `execute_`
                            "INSERT INTO auth.email_templates (name, subject, body_text, body_html) \
                            \VALUES ('recovery', 'Reset your password', 'text', '<p>html</p>') \
                            \ON CONFLICT (name) DO NOTHING"
                        )
            bracket_ (pure ()) reseedRow $ do
                delResp <- runApp env $ jsonDelete "/admin/email-templates/recovery" (Just svcJwt)
                expectStatus 204 delResp

                getResp <- runApp env $ jsonGet "/admin/email-templates/recovery" (Just svcJwt)
                expectStatus 404 getResp
