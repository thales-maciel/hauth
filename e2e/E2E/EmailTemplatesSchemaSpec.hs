{-# LANGUAGE OverloadedStrings #-}

{- | Cross-checks that migration 0011 seeds auth.email_templates with rows
whose body_text / body_html / subject exactly match the TH-embedded
template files compiled into the library.

Runs as part of the e2e suite, which provides a fully migrated database via
'withTestEnv'.  If the e2e harness is unavailable the whole suite fails —
there is no silent skip.
-}
module E2E.EmailTemplatesSchemaSpec (spec) where

import Control.Exception (bracket)
import Data.List (sort)
import Data.Text (Text)
import qualified Data.Text as T
import Database.PostgreSQL.Simple (Connection, Only (..), fromOnly, query, query_)
import E2E.Helpers (TestEnv (..))
import Hauth.Email.TemplateCache (
    Template (..),
    lookupTemplate,
    newTemplateCache,
    stopTemplateCache,
 )
import Hauth.Env (withDatabaseConnection)
import Test.Hspec (SpecWith, describe, it, shouldBe)

-- ---------------------------------------------------------------------------
-- Expected set of seeded names
-- ---------------------------------------------------------------------------

expectedNames :: [Text]
expectedNames = sort ["confirmation", "email_change", "invite", "recovery"]

-- ---------------------------------------------------------------------------
-- Spec
-- ---------------------------------------------------------------------------

spec :: SpecWith TestEnv
spec = do
    describe "migration 0011 seed (auth.email_templates)" $ do
        it "seeds exactly the four expected template names" \env ->
            withDatabaseConnection (testAppEnv env) \conn -> do
                rows <- query_ conn "SELECT name FROM auth.email_templates ORDER BY name"
                let names = fmap fromOnly rows :: [Text]
                names `shouldBe` expectedNames

        it "seeds body_text / body_html / subject matching the TH-embedded files" \env ->
            withEmbeddedCache \embed ->
                withDatabaseConnection (testAppEnv env) \conn ->
                    mapM_ (checkRow conn embed) expectedNames

-- ---------------------------------------------------------------------------
-- Per-row check
-- ---------------------------------------------------------------------------

checkRow :: Connection -> (Text -> IO Template) -> Text -> IO ()
checkRow conn embed name = do
    rows <-
        query
            conn
            "SELECT body_text, body_html, subject \
            \FROM auth.email_templates WHERE name = ?"
            (Only name)
    case rows of
        [] ->
            fail
                ( "EmailTemplatesSchemaSpec: no row for template "
                    <> T.unpack name
                )
        ((actualText, actualHtml, actualSubject) : _) -> do
            embedded <- embed name
            actualText `shouldBe` templateBodyText embedded
            actualHtml `shouldBe` templateBodyHtml embedded
            actualSubject `shouldBe` templateSubject embedded

-- ---------------------------------------------------------------------------
-- Embedded defaults via a disconnected cache
-- ---------------------------------------------------------------------------

{- | Start a 'TemplateCache' pointed at a deliberately unreachable URL so it
never connects to the database.  'lookupTemplate' then serves the
TH-embedded fallback for every known name — exactly the content that
migration 0011 should have written into the live schema.
-}
withEmbeddedCache :: ((Text -> IO Template) -> IO a) -> IO a
withEmbeddedCache action =
    bracket
        (newTemplateCache "postgresql://nobody@127.0.0.1:1/nonexistent")
        stopTemplateCache
        (action . lookupTemplate)
