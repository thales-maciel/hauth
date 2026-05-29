module Main (main) where

import Control.Monad (when)
import qualified Data.ByteString.Char8 as BSC
import Data.Text (Text)
import qualified Data.Text as T
import Hauth.API (hauthAPI)
import Hauth.CLI (
    CliError (..),
    Command (..),
    HelpTopic (..),
    MigrateCommand (..),
    MigrateOptions (..),
    Port (..),
    ServeOptions (..),
    parseCommand,
    resolveMigrateConfigPath,
    resolveServeConfigPath,
    resolveServePort,
 )
import Hauth.Config (
    Config (..),
    ConfigError (..),
    ConfigFieldError (..),
    DatabaseConfig (..),
    ServerConfig (..),
    decodeConfigBytes,
 )
import Hauth.Crypto.Password (
    Argon2Settings (..),
    PasswordPolicyError (..),
    checkPasswordPolicy,
    defaultArgon2Settings,
    defaultPasswordPolicy,
    hashPassword,
    verifyPassword,
 )
import Hauth.Email (
    EmailError (..),
    EmailMessage (..),
    TemplateData (..),
    TemplateKind (..),
    renderEmail,
    sendEmail,
    stubSender,
    substituteVars,
 )
import Hauth.Env (
    AppEnv (..),
    Logger (..),
    createAppEnvWithLogger,
    destroyAppEnv,
 )
import Hauth.Migrate (
    MigrationFile (..),
    embeddedMigrations,
    pendingMigrations,
 )
import Hauth.Server (server)
import System.Exit (exitSuccess)

main :: IO ()
main = do
    hauthAPI `seq` server `seq` pure ()
    assertEqual "top-level help" (Right (Help TopLevelHelp)) (parseCommand ["--help"])
    assertEqual "serve default" (Right (Serve (ServeOptions Nothing Nothing))) (parseCommand ["serve"])
    assertEqual
        "serve config"
        (Right (Serve (ServeOptions (Just "config.json") Nothing)))
        (parseCommand ["serve", "--config", "config.json"])
    assertEqual
        "serve port"
        (Right (Serve (ServeOptions Nothing (Just (Port 18080)))))
        (parseCommand ["serve", "--port", "18080"])
    assertEqual
        "serve config and port"
        (Right (Serve (ServeOptions (Just "config.json") (Just (Port 18080)))))
        (parseCommand ["serve", "--config=config.json", "--port=18080"])
    assertEqual
        "migrate status"
        (Right (Migrate (MigrateOptions Nothing) MigrateStatus))
        (parseCommand ["migrate", "status"])
    assertEqual
        "migrate up"
        (Right (Migrate (MigrateOptions Nothing) MigrateUp))
        (parseCommand ["migrate", "up"])
    assertEqual
        "migrate status --config"
        (Right (Migrate (MigrateOptions (Just "migrate.json")) MigrateStatus))
        (parseCommand ["migrate", "status", "--config", "migrate.json"])
    assertEqual
        "migrate up --config="
        (Right (Migrate (MigrateOptions (Just "migrate.json")) MigrateUp))
        (parseCommand ["migrate", "up", "--config=migrate.json"])
    assertEqual
        "migrate up -c"
        (Right (Migrate (MigrateOptions (Just "migrate.json")) MigrateUp))
        (parseCommand ["migrate", "up", "-c", "migrate.json"])
    assertEqual
        "migrate config path"
        (Right "migrate.json")
        (resolveMigrateConfigPath Nothing (MigrateOptions (Just "migrate.json")))
    assertEqual
        "migrate env config path"
        (Right "env.json")
        (resolveMigrateConfigPath (Just "env.json") (MigrateOptions Nothing))
    assertEqual
        "migrate option overrides env"
        (Right "override.json")
        (resolveMigrateConfigPath (Just "env.json") (MigrateOptions (Just "override.json")))
    assertEqual "config path" (Right "config.json") (resolveServeConfigPath Nothing (ServeOptions (Just "config.json") Nothing))
    assertEqual "env config path" (Right "env.json") (resolveServeConfigPath (Just "env.json") (ServeOptions Nothing Nothing))
    assertEqual "config port" (Right (Port 8080)) (resolveServePort (Port 8080) Nothing (ServeOptions Nothing Nothing))
    assertEqual "env port" (Right (Port 18081)) (resolveServePort (Port 8080) (Just "18081") (ServeOptions Nothing Nothing))
    assertEqual
        "option overrides env"
        (Right (Port 18082))
        (resolveServePort (Port 8080) (Just "18081") (ServeOptions Nothing (Just (Port 18082))))
    case decodeConfigBytes "valid.json" validConfigBytes of
        Left err ->
            fail ("valid config failed: " <> show err)
        Right config -> do
            assertEqual "config database url" "postgresql://hauth:hauth@localhost:5432/hauth" (databaseUrl (configDatabase config))
            assertEqual "config server port" 8080 (serverPort (configServer config))
            env <- createAppEnvWithLogger testLogger config
            assertEqual "env config" config (appConfig env)
            destroyAppEnv env
    assertConfigFields
        "missing config sections"
        ["database", "jwt", "site", "email", "oauth", "server"]
        (decodeConfigBytes "missing.json" "{}")
    assertConfigFields
        "invalid config fields"
        [ "database.url"
        , "database.pool_size"
        , "jwt.secret"
        , "jwt.issuer"
        , "jwt.audience"
        , "jwt.access_token_ttl_seconds"
        , "jwt.refresh_token_ttl_seconds"
        , "site.url"
        , "site.allowed_redirect_urls[0]"
        , "email.from"
        , "email.smtp_host"
        , "email.smtp_port"
        , "oauth.providers[0].name"
        , "oauth.providers[0].client_id"
        , "oauth.providers[0].client_secret"
        , "oauth.providers[0].discovery_url"
        , "server.host"
        , "server.port"
        ]
        (decodeConfigBytes "invalid.json" invalidConfigBytes)
    assertCliError "missing command" (parseCommand [])
    assertCliError "unknown command" (parseCommand ["wat"])
    assertCliError "missing migrate subcommand" (parseCommand ["migrate"])
    assertCliError "unknown migrate subcommand" (parseCommand ["migrate", "wat"])
    assertCliError "migrate missing --config value" (parseCommand ["migrate", "up", "--config"])
    assertCliError "migrate unknown option" (parseCommand ["migrate", "up", "--bogus"])
    assertCliError "bad port" (parseCommand ["serve", "--port", "nope"])
    let names = fmap migrationName embeddedMigrations
    assertEqual "embedded bootstrap" ["0001_init.sql"] names
    assertEqual
        "pending none when all applied"
        []
        (fmap migrationName (pendingMigrations names embeddedMigrations))
    assertEqual
        "pending all when nothing applied"
        names
        (fmap migrationName (pendingMigrations [] embeddedMigrations))
    -- Password hashing tests use cheap settings to keep CI fast.
    let cheapSettings =
            defaultArgon2Settings
                { argon2Iterations = 1
                , argon2Memory = 8
                , argon2Parallelism = 1
                }
    hash1 <- hashPassword cheapSettings "correct horse"
    assertEqual "verify correct password" True (verifyPassword hash1 "correct horse")
    assertEqual "verify wrong password" False (verifyPassword hash1 "wrong")
    hash2 <- hashPassword cheapSettings "correct horse"
    assertEqual "different salts produce different hashes" True (hash1 /= hash2)
    assertEqual "bad phc string" False (verifyPassword "not a phc string" "anything")
    assertEqual
        "policy rejects empty password"
        (Left (PasswordTooShort 8 0))
        (checkPasswordPolicy defaultPasswordPolicy "")
    assertEqual
        "policy accepts min-length password"
        (Right ())
        (checkPasswordPolicy defaultPasswordPolicy "abcdefgh")
    let fromAddr = "noreply@example.com" :: Text
    mapM_ (assertRenderEmail fromAddr sampleTemplateData) [minBound .. maxBound]
    assertSubstituteVars
    stubResult <- sendEmail stubSender (dummyEmailMessage fromAddr)
    case stubResult of
        Left (EmailSendError _) -> pure ()
        other -> fail ("stubSender: expected EmailSendError, got " <> show other)
    exitSuccess

assertEqual :: (Eq a, Show a) => String -> a -> a -> IO ()
assertEqual label expected actual =
    if actual == expected
        then pure ()
        else fail (label <> ": expected " <> show expected <> ", got " <> show actual)

assertCliError :: String -> Either CliError a -> IO ()
assertCliError _ (Left CliError{}) =
    pure ()
assertCliError label (Right _) =
    fail (label <> ": expected CLI error")

assertConfigFields :: String -> [String] -> Either ConfigError Config -> IO ()
assertConfigFields label expected (Left (ConfigValidationError _ errors)) =
    assertEqual label expected (fmap configFieldPath errors)
assertConfigFields label _ actual =
    fail (label <> ": expected config validation error, got " <> show actual)

testLogger :: Logger
testLogger =
    Logger \_level _message ->
        pure ()

validConfigBytes :: BSC.ByteString
validConfigBytes =
    BSC.pack $
        unlines
            [ "{"
            , "  \"database\": {"
            , "    \"url\": \"postgresql://hauth:hauth@localhost:5432/hauth\","
            , "    \"pool_size\": 5"
            , "  },"
            , "  \"jwt\": {"
            , "    \"secret\": \"0123456789abcdef0123456789abcdef\","
            , "    \"issuer\": \"hauth\","
            , "    \"audience\": \"authenticated\","
            , "    \"access_token_ttl_seconds\": 3600,"
            , "    \"refresh_token_ttl_seconds\": 2592000"
            , "  },"
            , "  \"site\": {"
            , "    \"url\": \"http://localhost:3000\","
            , "    \"allowed_redirect_urls\": [\"http://localhost:3000/auth/callback\"]"
            , "  },"
            , "  \"email\": {"
            , "    \"from\": \"noreply@example.com\","
            , "    \"smtp_host\": \"localhost\","
            , "    \"smtp_port\": 1025"
            , "  },"
            , "  \"oauth\": {"
            , "    \"providers\": ["
            , "      {"
            , "        \"name\": \"github\","
            , "        \"client_id\": \"github-client-id\","
            , "        \"client_secret\": \"github-client-secret\","
            , "        \"discovery_url\": \"https://github.com/.well-known/openid-configuration\""
            , "      }"
            , "    ]"
            , "  },"
            , "  \"server\": {"
            , "    \"host\": \"127.0.0.1\","
            , "    \"port\": 8080"
            , "  }"
            , "}"
            ]

invalidConfigBytes :: BSC.ByteString
invalidConfigBytes =
    BSC.pack $
        unlines
            [ "{"
            , "  \"database\": {"
            , "    \"url\": \"mysql://localhost/hauth\","
            , "    \"pool_size\": 0"
            , "  },"
            , "  \"jwt\": {"
            , "    \"secret\": \"short\","
            , "    \"issuer\": \"\","
            , "    \"audience\": \"\","
            , "    \"access_token_ttl_seconds\": 0,"
            , "    \"refresh_token_ttl_seconds\": -1"
            , "  },"
            , "  \"site\": {"
            , "    \"url\": \"localhost:3000\","
            , "    \"allowed_redirect_urls\": [\"ftp://localhost/callback\"]"
            , "  },"
            , "  \"email\": {"
            , "    \"from\": \"noreply\","
            , "    \"smtp_host\": \"\","
            , "    \"smtp_port\": 70000"
            , "  },"
            , "  \"oauth\": {"
            , "    \"providers\": ["
            , "      {"
            , "        \"name\": \"\","
            , "        \"client_id\": \"\","
            , "        \"client_secret\": \"\","
            , "        \"discovery_url\": \"github.com\""
            , "      }"
            , "    ]"
            , "  },"
            , "  \"server\": {"
            , "    \"host\": \"\","
            , "    \"port\": 0"
            , "  }"
            , "}"
            ]

-- | Sample template data used in email rendering tests.
sampleTemplateData :: TemplateData
sampleTemplateData =
    TemplateData
        { templateRecipientEmail = "user@example.com"
        , templateActionUrl = "https://example.com/auth/confirm?token=abc"
        , templateSiteUrl = "https://example.com"
        , templateTokenHash = "abc123"
        }

-- | Minimal dummy message for stubSender test.
dummyEmailMessage :: Text -> EmailMessage
dummyEmailMessage from =
    EmailMessage
        { emailTo = "user@example.com"
        , emailFrom = from
        , emailSubject = "Test"
        , emailTextBody = "Test body"
        , emailHtmlBody = Nothing
        }

-- | Assert that rendering a given kind returns a well-formed message.
assertRenderEmail :: Text -> TemplateData -> TemplateKind -> IO ()
assertRenderEmail from tdata kind =
    case renderEmail kind from tdata of
        Left err ->
            fail ("renderEmail " <> show kind <> ": unexpected error: " <> show err)
        Right msg -> do
            let label = show kind
            assertEqual (label <> " emailTo") (templateRecipientEmail tdata) (emailTo msg)
            assertEqual (label <> " emailFrom") from (emailFrom msg)
            assertNonEmptyNoNewline label (emailSubject msg)
            assertSubstituted label (emailTextBody msg) tdata
            case emailHtmlBody msg of
                Nothing ->
                    fail (label <> ": expected Just htmlBody, got Nothing")
                Just html ->
                    assertSubstituted (label <> " html") html tdata

-- | Assert that a subject is non-empty and contains no newlines.
assertNonEmptyNoNewline :: String -> Text -> IO ()
assertNonEmptyNoNewline label subj = do
    when (T.null subj) $
        fail (label <> " subject: expected non-empty subject")
    when (T.any (== '\n') subj) $
        fail (label <> " subject: unexpected newline in subject")

-- | Assert that all four placeholder variables were substituted in a body.
assertSubstituted :: String -> Text -> TemplateData -> IO ()
assertSubstituted label body tdata = do
    assertContains (label <> " recipient_email") (templateRecipientEmail tdata) body
    assertContains (label <> " action_url") (templateActionUrl tdata) body
    assertContains (label <> " site_url") (templateSiteUrl tdata) body

assertContains :: String -> Text -> Text -> IO ()
assertContains label needle haystack =
    if T.isInfixOf needle haystack
        then pure ()
        else
            fail
                ( label
                    <> ": expected "
                    <> show needle
                    <> " to appear in body"
                )

{- | Test the substituteVars helper directly, including unknown placeholder
pass-through.
-}
assertSubstituteVars :: IO ()
assertSubstituteVars = do
    let tdata =
            TemplateData
                { templateRecipientEmail = "u@x.com"
                , templateActionUrl = "https://x.com/action"
                , templateSiteUrl = "https://x.com"
                , templateTokenHash = "tok"
                }
        input = "Hello {{recipient_email}} visit {{action_url}} ref {{token_hash}} unknown {{nope}}"
        result = substituteVars tdata input
    assertContains "subst recipient" "u@x.com" result
    assertContains "subst action" "https://x.com/action" result
    assertContains "subst token" "tok" result
    assertContains "subst unknown passthrough" "{{nope}}" result
