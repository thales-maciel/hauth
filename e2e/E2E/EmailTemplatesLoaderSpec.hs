{-# LANGUAGE NumericUnderscores #-}
{-# LANGUAGE OverloadedStrings #-}

module E2E.EmailTemplatesLoaderSpec (spec) where

import Control.Concurrent (threadDelay)
import Control.Exception (SomeException, bracket_, try)
import Database.PostgreSQL.Simple (Only (..), execute)
import E2E.Helpers (TestEnv (..))
import Hauth.Email.TemplateCache (
    Template (..),
    lookupTemplate,
    newTemplateCache,
 )
import Hauth.Env (AppEnv (..), withDatabaseConnection)
import Test.Hspec (SpecWith, describe, it, shouldBe)

spec :: SpecWith TestEnv
spec = do
    describe "TemplateCache" do
        it "loads seeded rows from DB on startup" \env -> do
            let cache = appTemplateCache (testAppEnv env)
            t <- lookupTemplate cache "confirmation"
            templateSubject t `shouldBe` "Confirm your email address"

        it "reflects a DB UPDATE within ~500ms via NOTIFY" \env -> do
            let cache = appTemplateCache (testAppEnv env)
            withDatabaseConnection (testAppEnv env) \conn ->
                bracket_
                    ( execute
                        conn
                        "UPDATE auth.email_templates SET subject = ? WHERE name = 'recovery'"
                        (Only ("Password reset requested" :: String))
                    )
                    ( execute
                        conn
                        "UPDATE auth.email_templates SET subject = 'Reset your password' WHERE name = 'recovery'"
                        ()
                    )
                    do
                        -- Give the LISTEN thread time to receive the NOTIFY and reload.
                        threadDelay 500_000
                        t <- lookupTemplate cache "recovery"
                        templateSubject t `shouldBe` "Password reset requested"

        it "falls back to embedded template when DB row is absent" \env -> do
            withDatabaseConnection (testAppEnv env) \conn ->
                bracket_
                    (execute conn "DELETE FROM auth.email_templates WHERE name = 'invite'" ())
                    ( execute
                        conn
                        "INSERT INTO auth.email_templates \
                        \    (name, subject, body_text, body_html) \
                        \VALUES ('invite', 'You''ve been invited', 'txt', 'html')"
                        ()
                    )
                    do
                        -- Fresh empty cache (no listener) — lookups go straight to
                        -- the embedded fallback regardless of DB state.
                        freshCache <- newTemplateCache
                        t <- lookupTemplate freshCache "invite"
                        -- Subject comes from the embedded templates/invite.subject file.
                        templateSubject t `shouldBe` "You've been invited"

        it "errors for a fully unknown template name" \env -> do
            let cache = appTemplateCache (testAppEnv env)
            result <- try @SomeException (lookupTemplate cache "no_such_template_ever")
            case result of
                Left _ -> pure ()
                Right _ -> error "expected an error for unknown template name, got a result"
