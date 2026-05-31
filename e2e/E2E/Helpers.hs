{-# LANGUAGE OverloadedStrings #-}

module E2E.Helpers (
    TestEnv (..),
    withTestEnv,
    truncateAll,
    runApp,
    jsonPost,
    jsonGet,
    jsonPut,
    jsonDelete,
    expectStatus,
    decodeBody,
    mintServiceRoleJwt,
    mintSessionJwt,
) where

import qualified Data.Aeson as Aeson
import qualified Data.ByteString as BS
import qualified Data.ByteString.Lazy as BSL
import Data.Maybe (fromMaybe)
import qualified Data.Text as T
import qualified Data.Text.Encoding as TE
import Data.Time.Clock (addUTCTime, getCurrentTime)
import Database.PostgreSQL.Simple (execute_)
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
import Hauth.Env (
    AppEnv (..),
    Logger (..),
    createAppEnvWithLogger,
    destroyAppEnv,
    withDatabaseConnection,
 )
import Hauth.Migrate (runMigrate)
import Hauth.Server (app)
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
-- constructs AppEnv, runs migrate up, hands control to the action, then tears
-- AppEnv down. The body is responsible for truncating between tests.
withTestEnv :: (TestEnv -> IO a) -> IO a
withTestEnv action = do
    dbUrl <-
        T.pack . fromMaybe "postgresql://hauth:hauth@localhost:5432/hauth_e2e"
            <$> lookupEnv "HAUTH_E2E_DATABASE_URL"
    let cfg = testingConfig dbUrl
    appEnv <- createAppEnvWithLogger silentLogger cfg
    _ <- runMigrate cfg MigrateUp
    let env = TestEnv appEnv cfg
    truncateAll env
    result <- action env
    destroyAppEnv appEnv
    pure result

silentLogger :: Logger
silentLogger = Logger \_lvl _msg -> pure ()

-- Truncate every auth.* table EXCEPT auth.schema_migrations. Drives per-test
-- isolation when wired via hspec's before_.
truncateAll :: TestEnv -> IO ()
truncateAll TestEnv{testAppEnv} =
    withDatabaseConnection testAppEnv \conn -> do
        _ <-
            execute_
                conn
                "TRUNCATE TABLE \
                \  auth.flow_state, \
                \  auth.mfa_factors, \
                \  auth.refresh_tokens, \
                \  auth.sessions, \
                \  auth.identities, \
                \  auth.users \
                \RESTART IDENTITY CASCADE"
        pure ()

-- Drive a Wai Session against the in-process Application built from this env.
runApp :: TestEnv -> Session a -> IO a
runApp TestEnv{testAppEnv} sess = runSession sess (app testAppEnv)

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
                { jwtSecret = "0123456789abcdef0123456789abcdef"
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
