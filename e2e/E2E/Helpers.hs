{-# LANGUAGE OverloadedStrings #-}

module E2E.Helpers (
    TestEnv (..),
    withTestEnv,
    truncateAll,
    runApp,
    runAppHardened,
    jsonPost,
    jsonGet,
    jsonPut,
    jsonDelete,
    expectStatus,
    decodeBody,
    mintServiceRoleJwt,
    mintSessionJwt,
) where

import Control.Exception (bracket)
import qualified Data.Aeson as Aeson
import qualified Data.ByteString as BS
import qualified Data.ByteString.Lazy as BSL
import Data.Maybe (fromMaybe)
import qualified Data.Text as T
import qualified Data.Text.Encoding as TE
import Data.Time.Clock (addUTCTime, getCurrentTime)
import Database.PostgreSQL.Simple (Connection, execute, execute_)
import Hauth.Auth.Jwt (
    AccessTokenClaims (..),
    JwtError,
    signAccessToken,
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
import Hauth.Email.TemplateCache (
    Template (..),
    lookupTemplate,
    newTemplateCache,
 )
import Hauth.Env (
    AppEnv (..),
    Logger (..),
    createAppEnvWith,
    destroyAppEnv,
    startRequiredBackgroundServices,
    stopBackgroundServices,
    withDatabaseConnection,
 )
import Hauth.Migrate (runMigrate)
import Hauth.Security.OutboundDestination (checkDestination, defaultResolver)
import Hauth.Server (app)
import Hauth.Validation.URL (parseHttpUrl)
import Network.HTTP.Client (defaultManagerSettings, newManager)
import Network.HTTP.Types (Method, hAccept, hAuthorization, hContentType, statusCode)
import Network.Wai (Request (requestHeaders, requestMethod))
import Network.Wai.Test (
    SRequest (..),
    SResponse (..),
    Session,
    defaultRequest,
    runSession,
    setPath,
    srequest,
 )
import qualified Network.Wai.Test as WaiTest
import System.Environment (lookupEnv)
import Test.Hspec (HasCallStack, expectationFailure)

data TestEnv = TestEnv
    { testAppEnv :: AppEnv
    , testConfig :: Config
    }

-- Builds Config from HAUTH_E2E_DATABASE_URL (defaulting to a local mise URL),
-- constructs AppEnv, runs migrate up (BEFORE starting background services so
-- the worker + template-cache listener don't race the schema), hands control
-- to the action, tears services + AppEnv down. The body is responsible for
-- truncating between tests.
--
-- We use 'startRequiredBackgroundServices' (the same entry point as
-- production @hauth serve@) so the e2e harness mirrors operator semantics:
-- if the required webhook worker cannot start, the suite fails loudly
-- instead of producing mysterious test failures hundreds of lines later.
-- Optional services that fail to start still degrade gracefully — the
-- hot-reload spec exists to exercise the listener, so a missing template
-- listener will be caught there.
--
-- Two nested brackets guarantee cleanup if the action throws:
--   * outer bracket pairs createAppEnvWithLogger with destroyAppEnv
--   * inner bracket pairs startRequiredBackgroundServices with
--     stopBackgroundServices
-- migrate-up runs between the brackets (after AppEnv exists, before services
-- start) to preserve the schema-before-worker ordering.
withTestEnv :: (TestEnv -> IO a) -> IO a
withTestEnv action = do
    dbUrl <-
        T.pack . fromMaybe "postgresql://hauth:hauth@localhost:5432/hauth_e2e"
            <$> lookupEnv "HAUTH_E2E_DATABASE_URL"
    let cfg = testingConfig dbUrl
    -- Use a plain (non-hardened) Manager AND a parse-only validation-time
    -- check: e2e tests spin up loopback servers for hook and webhook
    -- receivers, which the hardened defaults would reject. The parse-only
    -- check preserves URL syntax validation (so tests asserting 400 on
    -- malformed URLs still pass) while bypassing IP-class rejection.
    -- The full SSRF policy is exercised by Spec.Security.OutboundDestinationSpec
    -- and E2E.OutboundDestinationSpec (which uses 'runAppHardened').
    plainMgr <- newManager defaultManagerSettings
    let parseOnlyDestCheck url =
            pure $ case parseHttpUrl url of
                Left msg -> Left msg
                Right _ -> Right ()
    bracket (createAppEnvWith silentLogger cfg plainMgr parseOnlyDestCheck) destroyAppEnv \appEnv -> do
        _ <- runMigrate cfg MigrateUp
        bracket (startRequiredBackgroundServices appEnv) stopBackgroundServices \_ -> do
            let env = TestEnv appEnv cfg
            truncateAll env
            action env

silentLogger :: Logger
silentLogger = Logger \_lvl _msg -> pure ()

-- Truncate every auth.* table EXCEPT auth.schema_migrations. Drives per-test
-- isolation when wired via hspec's before_. When adding a new auth.* table,
-- add it here too — otherwise tests pile up rows across runs and assertions
-- like "expected 0 deliveries" start counting hundreds.
--
-- auth.email_templates is also wiped, then re-seeded from the TH-embedded
-- defaults so specs that mutate template rows (CRUD, hot-reload) don't
-- leave migration-0011 content overwritten for the schema-seed spec.
truncateAll :: TestEnv -> IO ()
truncateAll TestEnv{testAppEnv} =
    withDatabaseConnection testAppEnv \conn -> do
        _ <-
            execute_
                conn
                "TRUNCATE TABLE \
                \  auth.flow_state, \
                \  auth.hooks, \
                \  auth.mfa_factors, \
                \  auth.refresh_tokens, \
                \  auth.sessions, \
                \  auth.webhook_deliveries, \
                \  auth.webhook_subscriptions, \
                \  auth.identities, \
                \  auth.users, \
                \  auth.email_templates \
                \RESTART IDENTITY CASCADE"
        reseedEmailTemplates conn

{- | Restore @auth.email_templates@ to the four TH-embedded defaults, matching
what migration 0011 originally seeds. A fresh 'TemplateCache' has no DB
rows loaded, so 'lookupTemplate' falls through to the embedded bundle —
exactly the content the migration writes.
-}
reseedEmailTemplates :: Connection -> IO ()
reseedEmailTemplates conn = do
    cache <- newTemplateCache
    mapM_ (insertOne cache) ["confirmation", "email_change", "invite", "recovery"]
  where
    insertOne cache name = do
        Template{templateSubject, templateBodyText, templateBodyHtml} <-
            lookupTemplate cache name
        _ <-
            execute
                conn
                "INSERT INTO auth.email_templates (name, subject, body_text, body_html) \
                \VALUES (?, ?, ?, ?)"
                (name, templateSubject, templateBodyText, templateBodyHtml)
        pure ()

-- Drive a Wai Session against the in-process Application built from this env.
runApp :: TestEnv -> Session a -> IO a
runApp TestEnv{testAppEnv} sess = runSession sess (app testAppEnv)

-- Like 'runApp' but with the production SSRF validation-time check enabled,
-- regardless of how the shared 'TestEnv' was built. The shared env uses a
-- permissive check so the bulk of the suite can target loopback servers; this
-- variant is for tests that assert /admin/hooks and /admin/webhooks reject
-- blocked destinations at the API layer.
runAppHardened :: TestEnv -> Session a -> IO a
runAppHardened TestEnv{testAppEnv} sess =
    let hardenedEnv =
            testAppEnv
                { appOutboundDestinationCheck = checkDestination defaultResolver
                }
     in runSession sess (app hardenedEnv)

-- Build a JSON POST request, optionally with a Bearer token.
jsonPost ::
    (Aeson.ToJSON a) =>
    BS.ByteString {- path -} ->
    a {- body -} ->
    Maybe T.Text {- bearer -} ->
    Session SResponse
jsonPost = jsonBodyRequest "POST"

jsonPut ::
    (Aeson.ToJSON a) =>
    BS.ByteString ->
    a ->
    Maybe T.Text ->
    Session SResponse
jsonPut = jsonBodyRequest "PUT"

jsonBodyRequest ::
    (Aeson.ToJSON a) =>
    Method ->
    BS.ByteString ->
    a ->
    Maybe T.Text ->
    Session SResponse
jsonBodyRequest method path body mBearer = do
    let baseHeaders =
            [ (hContentType, "application/json")
            , (hAccept, "application/json")
            ]
        headers = case mBearer of
            Nothing -> baseHeaders
            Just tok -> (hAuthorization, "Bearer " <> TE.encodeUtf8 tok) : baseHeaders
        req =
            setPath
                ( defaultRequest
                    { requestMethod = method
                    , requestHeaders = headers
                    }
                )
                path
    srequest (SRequest req (Aeson.encode body))

jsonGet :: BS.ByteString -> Maybe T.Text -> Session SResponse
jsonGet path mBearer = do
    let baseHeaders = [(hAccept, "application/json")]
        headers = case mBearer of
            Nothing -> baseHeaders
            Just tok -> (hAuthorization, "Bearer " <> TE.encodeUtf8 tok) : baseHeaders
        req =
            setPath
                (defaultRequest{requestHeaders = headers})
                path
    srequest (SRequest req BSL.empty)

jsonDelete :: BS.ByteString -> Maybe T.Text -> Session SResponse
jsonDelete path mBearer = do
    let baseHeaders = [(hAccept, "application/json")]
        headers = case mBearer of
            Nothing -> baseHeaders
            Just tok -> (hAuthorization, "Bearer " <> TE.encodeUtf8 tok) : baseHeaders
        req =
            setPath
                ( defaultRequest
                    { requestMethod = "DELETE"
                    , requestHeaders = headers
                    }
                )
                path
    srequest (SRequest req BSL.empty)

expectStatus :: (HasCallStack) => Int -> SResponse -> IO ()
expectStatus expected resp = do
    let actual = statusCode (WaiTest.simpleStatus resp)
    if actual == expected
        then pure ()
        else
            expectationFailure $
                "expected status "
                    <> show expected
                    <> ", got "
                    <> show actual
                    <> "; body: "
                    <> show (WaiTest.simpleBody resp)

decodeBody :: (Aeson.FromJSON a, HasCallStack) => SResponse -> IO a
decodeBody resp =
    case Aeson.eitherDecode (WaiTest.simpleBody resp) of
        Left err -> do
            expectationFailure
                ( "JSON decode failed: "
                    <> err
                    <> "; body: "
                    <> show (WaiTest.simpleBody resp)
                )
            error "unreachable"
        Right v -> pure v

mintServiceRoleJwt :: TestEnv -> IO T.Text
mintServiceRoleJwt env =
    mintJwt' env "service_role" "00000000-0000-0000-0000-000000000000" "00000000-0000-0000-0000-000000000001"

mintSessionJwt :: TestEnv -> T.Text {- userId -} -> T.Text {- sessionId -} -> IO T.Text
mintSessionJwt env = mintJwt' env "authenticated"

mintJwt' :: TestEnv -> T.Text -> T.Text -> T.Text -> IO T.Text
mintJwt' TestEnv{testConfig = Config{configJwt}} role sub sid = do
    now <- getCurrentTime
    let expiry = addUTCTime (fromIntegral (jwtAccessTokenTtlSeconds configJwt)) now
        claims =
            AccessTokenClaims
                { claimSub = sub
                , claimRole = role
                , claimEmail = Nothing
                , claimPhone = Nothing
                , claimAppMetadata = Aeson.object []
                , claimUserMetadata = Aeson.object []
                , claimAal = "aal1"
                , claimAmr = []
                , claimSessionId = sid
                , claimIssuedAt = now
                , claimExpiresAt = expiry
                }
    result <- signAccessToken configJwt claims
    case result of
        Left err -> error ("mintJwt: signAccessToken failed: " <> show (err :: JwtError))
        Right t -> pure t

testingConfig :: T.Text -> Config
testingConfig dbUrl =
    Config
        { configDatabase =
            DatabaseConfig
                { databaseUrl = dbUrl
                , databasePoolSize = 4
                }
        , configJwt =
            JwtConfig
                { jwtSecret = "deadbeefcafefoodfaceb00ddeadbeef"
                , jwtIssuer = "hauth-e2e"
                , jwtAudience = "authenticated"
                , jwtAccessTokenTtlSeconds = 3600
                , jwtRefreshTokenTtlSeconds = 2592000
                }
        , configSite =
            SiteConfig
                { siteUrl = "https://app.example.com"
                , siteAllowedRedirectUrls = ["https://app.example.com/auth/callback"]
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
