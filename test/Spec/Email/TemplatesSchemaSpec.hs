{-# LANGUAGE TemplateHaskell #-}

{- | Cross-checks that migration 0011 seeds auth.email_templates with rows
whose body_text / body_html / subject exactly match the TH-embedded
template files in templates/.

Runs only when HAUTH_SCHEMA_TEST_DATABASE_URL is set; skips otherwise.
-}
module Spec.Email.TemplatesSchemaSpec (runSpec) where

import Control.Exception (bracket)
import Data.ByteString (ByteString)
import Data.FileEmbed (embedFile)
import Data.List (sort)
import Data.Text (Text)
import qualified Data.Text as T
import qualified Data.Text.Encoding as TE
import Database.PostgreSQL.Simple (
    Connection,
    Only (..),
    close,
    connectPostgreSQL,
    fromOnly,
    query,
    query_,
 )
import Hauth.CLI (MigrateCommand (..))
import Hauth.Config (
    Config (..),
    DatabaseConfig (..),
    EmailConfig (..),
    JwtConfig (..),
    OAuthConfig (..),
    ServerConfig (..),
    SiteConfig (..),
 )
import Hauth.Migrate (runMigrate)
import Spec.TestUtils (assertEqual)
import System.Environment (lookupEnv)

-- ---------------------------------------------------------------------------
-- Embedded template bytes (compiled in via TH at build time)
-- ---------------------------------------------------------------------------

embeddedConfirmationTxt :: ByteString
embeddedConfirmationTxt = $(embedFile "templates/confirmation.txt")

embeddedEmailChangeTxt :: ByteString
embeddedEmailChangeTxt = $(embedFile "templates/email_change.txt")

embeddedInviteTxt :: ByteString
embeddedInviteTxt = $(embedFile "templates/invite.txt")

embeddedRecoveryTxt :: ByteString
embeddedRecoveryTxt = $(embedFile "templates/recovery.txt")

embeddedConfirmationHtml :: ByteString
embeddedConfirmationHtml = $(embedFile "templates/confirmation.html")

embeddedEmailChangeHtml :: ByteString
embeddedEmailChangeHtml = $(embedFile "templates/email_change.html")

embeddedInviteHtml :: ByteString
embeddedInviteHtml = $(embedFile "templates/invite.html")

embeddedRecoveryHtml :: ByteString
embeddedRecoveryHtml = $(embedFile "templates/recovery.html")

embeddedConfirmationSubject :: ByteString
embeddedConfirmationSubject = $(embedFile "templates/confirmation.subject")

embeddedEmailChangeSubject :: ByteString
embeddedEmailChangeSubject = $(embedFile "templates/email_change.subject")

embeddedInviteSubject :: ByteString
embeddedInviteSubject = $(embedFile "templates/invite.subject")

embeddedRecoverySubject :: ByteString
embeddedRecoverySubject = $(embedFile "templates/recovery.subject")

-- ---------------------------------------------------------------------------
-- Lookup tables
-- ---------------------------------------------------------------------------

embeddedTxt :: [(Text, ByteString)]
embeddedTxt =
    [ ("confirmation", embeddedConfirmationTxt)
    , ("email_change", embeddedEmailChangeTxt)
    , ("invite", embeddedInviteTxt)
    , ("recovery", embeddedRecoveryTxt)
    ]

embeddedHtml :: [(Text, ByteString)]
embeddedHtml =
    [ ("confirmation", embeddedConfirmationHtml)
    , ("email_change", embeddedEmailChangeHtml)
    , ("invite", embeddedInviteHtml)
    , ("recovery", embeddedRecoveryHtml)
    ]

embeddedSubject :: [(Text, ByteString)]
embeddedSubject =
    [ ("confirmation", embeddedConfirmationSubject)
    , ("email_change", embeddedEmailChangeSubject)
    , ("invite", embeddedInviteSubject)
    , ("recovery", embeddedRecoverySubject)
    ]

-- ---------------------------------------------------------------------------
-- Expected state
-- ---------------------------------------------------------------------------

expectedNames :: [Text]
expectedNames = sort ["confirmation", "email_change", "invite", "recovery"]

-- ---------------------------------------------------------------------------
-- Spec entry point
-- ---------------------------------------------------------------------------

runSpec :: IO ()
runSpec = do
    mDbUrl <- lookupEnv "HAUTH_SCHEMA_TEST_DATABASE_URL"
    case mDbUrl of
        Nothing ->
            putStrLn
                "TemplatesSchemaSpec: skipping \
                \(HAUTH_SCHEMA_TEST_DATABASE_URL not set)"
        Just dbUrl -> runSchemaSpec dbUrl

runSchemaSpec :: String -> IO ()
runSchemaSpec dbUrl = do
    let cfg = schemaTestConfig (T.pack dbUrl)
    _ <- runMigrate cfg MigrateUp
    bracket
        (connectPostgreSQL (TE.encodeUtf8 (T.pack dbUrl)))
        close
        \conn -> do
            nameRows <-
                query_
                    conn
                    "SELECT name FROM auth.email_templates ORDER BY name"
            let names = fmap fromOnly nameRows :: [Text]
            assertEqual "seeded template names" expectedNames names
            mapM_ (checkRow conn) expectedNames

checkRow :: Connection -> Text -> IO ()
checkRow conn name = do
    rows <-
        query
            conn
            "SELECT body_text, body_html, subject \
            \FROM auth.email_templates WHERE name = ?"
            (Only name)
    case rows of
        [] ->
            fail
                ( "TemplatesSchemaSpec: no row for template "
                    <> T.unpack name
                )
        ((bodyText, bodyHtml, subject) : _) -> do
            checkField ("body_text for " <> name) embeddedTxt name bodyText
            checkField ("body_html for " <> name) embeddedHtml name bodyHtml
            -- Subjects are stored without trailing newline (matching
            -- how renderEmail strips them before building EmailMessage).
            checkSubjectField name subject

checkField :: Text -> [(Text, ByteString)] -> Text -> Text -> IO ()
checkField label table name actual =
    case lookup name table of
        Nothing ->
            fail
                ( "TemplatesSchemaSpec: no embedded bytes for "
                    <> T.unpack name
                )
        Just embeddedBytes ->
            assertEqual
                (T.unpack label)
                (TE.decodeUtf8 embeddedBytes)
                actual

checkSubjectField :: Text -> Text -> IO ()
checkSubjectField name actual =
    case lookup name embeddedSubject of
        Nothing ->
            fail
                ( "TemplatesSchemaSpec: no embedded subject for "
                    <> T.unpack name
                )
        Just embeddedBytes -> do
            -- Subject files have no trailing newline; decode and compare.
            let expected = TE.decodeUtf8 embeddedBytes
            assertEqual ("subject for " <> T.unpack name) expected actual

-- ---------------------------------------------------------------------------
-- Minimal Config for the migration runner
-- ---------------------------------------------------------------------------

schemaTestConfig :: Text -> Config
schemaTestConfig dbUrl =
    Config
        { configDatabase =
            DatabaseConfig
                { databaseUrl = dbUrl
                , databasePoolSize = 1
                }
        , configJwt =
            JwtConfig
                { jwtSecret = "0123456789abcdef0123456789abcdef"
                , jwtIssuer = "hauth-schema-test"
                , jwtAudience = "authenticated"
                , jwtAccessTokenTtlSeconds = 3600
                , jwtRefreshTokenTtlSeconds = 2592000
                }
        , configSite =
            SiteConfig
                { siteUrl = "https://example.com"
                , siteAllowedRedirectUrls = []
                }
        , configEmail =
            EmailConfig
                { emailFrom = "noreply@example.com"
                , emailSmtpHost = "localhost"
                , emailSmtpPort = 1025
                , emailUsername = Nothing
                , emailPassword = Nothing
                }
        , configOAuth = OAuthConfig{oauthProviders = []}
        , configServer =
            ServerConfig
                { serverHost = "127.0.0.1"
                , serverPort = 8080
                }
        }
