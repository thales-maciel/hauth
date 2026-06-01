{-# LANGUAGE NumericUnderscores #-}
{-# LANGUAGE OverloadedStrings #-}

module E2E.EmailTemplatesSpec (spec) where

import Control.Concurrent (threadDelay)
import Control.Exception (bracket_)
import qualified Data.Aeson as Aeson
import qualified Data.Text as T
import Database.PostgreSQL.Simple (execute_)
import E2E.Helpers (
    TestEnv (..),
    expectStatus,
    jsonPut,
    mintServiceRoleJwt,
    runApp,
 )
import Hauth.Email (
    EmailMessage (..),
    TemplateData (..),
    TemplateKind (..),
    renderEmailCached,
 )
import Hauth.Email.TemplateCache (lookupTemplate, templateSubject)
import Hauth.Env (AppEnv (..), withDatabaseConnection)
import Test.Hspec (SpecWith, describe, it, shouldBe, shouldContain)

-- | Minimal TemplateData used only to exercise subject rendering.
dummyTemplateData :: TemplateData
dummyTemplateData =
    TemplateData
        { templateRecipientEmail = "test@example.com"
        , templateActionUrl = "https://app.example.com/auth/confirm?token=abc"
        , templateSiteUrl = "https://app.example.com"
        , templateTokenHash = "abc"
        }

spec :: SpecWith TestEnv
spec = do
    describe "email template hot-reload" do
        it "PUT /admin/email-templates updates the rendered subject within ~2s" \env -> do
            let cache = appTemplateCache (testAppEnv env)
                from = "noreply@example.com"
                marker = "PUT-UPDATE-MARKER-99" :: T.Text
                restoreSubject =
                    withDatabaseConnection
                        (testAppEnv env)
                        ( `execute_`
                            "UPDATE auth.email_templates \
                            \SET subject = 'Confirm your email address' \
                            \WHERE name = 'confirmation'"
                        )
            bracket_ (pure ()) restoreSubject $ do
                -- Step 1: render the baseline subject before any override.
                t0 <- lookupTemplate cache "confirmation"
                let baseline = templateSubject t0
                baseline `shouldBe` "Confirm your email address"

                -- Step 2: PUT a new subject via the CRUD API.
                svcJwt <- mintServiceRoleJwt env
                putResp <-
                    runApp env $
                        jsonPut
                            "/admin/email-templates/confirmation"
                            ( Aeson.object
                                [ "subject" Aeson..= (marker <> " Confirm your email" :: T.Text)
                                , "body_text" Aeson..= ("Click {{action_url}}" :: T.Text)
                                , "body_html" Aeson..= ("<p>Click {{action_url}}</p>" :: T.Text)
                                ]
                            )
                            (Just svcJwt)
                expectStatus 200 putResp

                -- Step 3: wait up to 2s for the LISTEN/NOTIFY cycle to reload.
                threadDelay 2_000_000

                -- Step 4: render the same kind again; the cache should now serve the DB row.
                result <- renderEmailCached cache Confirmation from dummyTemplateData
                case result of
                    Left err ->
                        error ("renderEmailCached failed after hot-reload: " <> show err)
                    Right msg -> do
                        let subj = T.unpack (emailSubject msg)
                        subj `shouldContain` T.unpack marker
