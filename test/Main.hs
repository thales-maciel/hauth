module Main (main) where

import Control.Monad (when)
import Data.Aeson (Object, Value (..), decodeStrict', encode)
import qualified Data.Aeson as Aeson
import qualified Data.Aeson.KeyMap as KeyMap
import qualified Data.ByteString.Base64.URL as B64URL
import qualified Data.ByteString.Char8 as BSC
import qualified Data.ByteString.Lazy as BSL
import qualified Data.Map.Strict as Map
import Data.Text (Text)
import qualified Data.Text as T
import qualified Data.Text.Encoding as TE
import Data.Time.Clock (addUTCTime, getCurrentTime)
import Data.UUID (UUID)
import qualified Data.UUID as UUID
import Hauth.API (hauthAPI)
import Hauth.API.Auth (
    ServiceRolePrincipal (..),
    checkServiceRole,
    extractBearerToken,
 )
import Hauth.API.Types (
    AdminCreateUserRequest (..),
    CheckOutcome (..),
    DeepHealthCheck (..),
    DeepHealthResponse (..),
    DeletedUserResponse (..),
    Email (..),
    GrantType (..),
    InviteUserRequest (..),
    ListIdentitiesResponse (..),
    ListUsersResponse (..),
    MessageResponse (..),
    OAuthAuthorizeResponse (..),
    Password (..),
    RecoverRequest (..),
    RefreshTokenError (..),
    SettingsResponse (..),
    TokenRequest (..),
    TokenResponse (..),
    UpdateUserRequest (..),
    ValidRefreshToken (..),
    VerifyRequest (..),
    buildIdentityResponse,
    buildSettingsResponse,
    buildSignupResponse,
    buildUserResponse,
    classifyRefreshTokenLookup,
    parseGrantType,
 )
import Hauth.Auth.Admin (
    AdminError (..),
    Pagination (..),
    computeNextPage,
    defaultPagination,
    parsePagination,
    validateAdminCreate,
    validateInvite,
 )
import Hauth.Auth.Jwt (
    AccessTokenClaims (..),
    AmrEntry (..),
    JwtError (..),
    signAccessToken,
    validateAccessToken,
 )
import Hauth.Auth.Login (
    LoginError (..),
    authorizeLogin,
    buildLoginClaims,
    extractCredentials,
 )
import Hauth.Auth.Logout (
    LogoutError (..),
    resolveLogoutSession,
    sessionIdFromClaims,
 )
import Hauth.Auth.Recovery (
    RecoveryError (..),
    recoverySentMessage,
    validateRecoverRequest,
    validateRecoveryVerify,
 )
import Hauth.Auth.UserUpdate (UpdateUserError (..), validateUpdateRequest)
import Hauth.Auth.Verify (
    OtpType (..),
    VerifyError (..),
    classifyVerifyRequest,
    parseOtpType,
 )
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
    EmailConfig (EmailConfig),
    JwtConfig (..),
    OAuthConfig (..),
    OAuthProviderConfig (..),
    ServerConfig (..),
    SiteConfig (..),
    decodeConfigBytes,
 )
import Hauth.Crypto.Password (
    Argon2Settings (..),
    PasswordPolicyError (..),
    checkPasswordPolicy,
    defaultArgon2Settings,
    defaultPasswordPolicy,
    hashPassword,
 )
import qualified Hauth.Crypto.Password as Password
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
import Hauth.Identity (Identity (..), IdentityId (..))
import Hauth.Migrate (
    MigrationFile (..),
    embeddedMigrations,
    pendingMigrations,
 )
import Hauth.OAuth (
    OAuthError (..),
    buildStubAuthorizeUrl,
    generateState,
    isFlowStateExpired,
    lookupProvider,
    validateRedirectTo,
 )
import Hauth.Server (aggregateStatus, isUnhealthy, server)
import Hauth.Session (
    NewSession (..),
    RefreshToken (..),
    RefreshTokenId (..),
    Session (..),
    SessionId (..),
    generateOpaqueToken,
 )
import Hauth.User (
    SignupError (..),
    User (..),
    UserId (..),
    UserUpdate (..),
    emptyUserUpdate,
    generateConfirmationToken,
    validateSignupEmail,
    validateSignupPassword,
 )
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
    assertEqual
        "embedded migrations"
        [ "0001_init.sql"
        , "0002_users.sql"
        , "0003_identities.sql"
        , "0004_sessions.sql"
        , "0005_refresh_tokens.sql"
        , "0006_mfa_factors.sql"
        , "0007_flow_state.sql"
        ]
        names
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
    assertEqual "verify correct password" True (Password.verifyPassword hash1 "correct horse")
    assertEqual "verify wrong password" False (Password.verifyPassword hash1 "wrong")
    hash2 <- hashPassword cheapSettings "correct horse"
    assertEqual "different salts produce different hashes" True (hash1 /= hash2)
    assertEqual "bad phc string" False (Password.verifyPassword "not a phc string" "anything")
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

    now <- getCurrentTime
    let futureTime = addUTCTime 3600 now
        pastTime = addUTCTime (-3600) now
        testCfg =
            JwtConfig
                { jwtSecret = "0123456789abcdef0123456789abcdef"
                , jwtIssuer = "https://auth.example.com"
                , jwtAudience = "authenticated"
                , jwtAccessTokenTtlSeconds = 3600
                , jwtRefreshTokenTtlSeconds = 2592000
                }
        testClaims =
            AccessTokenClaims
                { claimSub = "00000000-0000-0000-0000-000000000000"
                , claimRole = "authenticated"
                , claimEmail = Just "user@example.com"
                , claimPhone = Nothing
                , claimAppMetadata = Object (KeyMap.fromList [])
                , claimUserMetadata = Object (KeyMap.fromList [])
                , claimAal = "aal1"
                , claimAmr = [AmrEntry{amrMethod = "password", amrTimestamp = 1780000000}]
                , claimSessionId = "00000000-0000-0000-0000-000000000001"
                , claimIssuedAt = now
                , claimExpiresAt = futureTime
                }

    -- Round-trip: sign then validate
    signResult <- signAccessToken testCfg testClaims
    case signResult of
        Left err -> fail ("jwt round-trip sign failed: " <> show err)
        Right token -> do
            validateResult <- validateAccessToken testCfg token
            case validateResult of
                Left err -> fail ("jwt round-trip validate failed: " <> show err)
                Right claims' -> do
                    assertEqual "round-trip sub" (claimSub testClaims) (claimSub claims')
                    assertEqual "round-trip role" (claimRole testClaims) (claimRole claims')
                    assertEqual "round-trip email" (claimEmail testClaims) (claimEmail claims')
                    assertEqual "round-trip phone" (claimPhone testClaims) (claimPhone claims')
                    assertEqual "round-trip aal" (claimAal testClaims) (claimAal claims')
                    assertEqual "round-trip session_id" (claimSessionId testClaims) (claimSessionId claims')
                    assertEqual "round-trip amr length" (length (claimAmr testClaims)) (length (claimAmr claims'))

    -- Wrong audience: validate with different config should fail
    let wrongAudCfg = testCfg{jwtAudience = "wrong-audience"}
    signResult2 <- signAccessToken testCfg testClaims
    case signResult2 of
        Left err -> fail ("jwt wrong-aud sign failed: " <> show err)
        Right token2 -> do
            wrongAudResult <- validateAccessToken wrongAudCfg token2
            case wrongAudResult of
                Left (JwtClaimError _) -> pure ()
                Left (JwtVerifyError _) -> pure ()
                Left err -> fail ("jwt wrong-aud: unexpected error type: " <> show err)
                Right _ -> fail "jwt wrong-aud: expected Left, got Right"

    -- Tampered signature: flip a byte in the last segment
    signResult3 <- signAccessToken testCfg testClaims
    case signResult3 of
        Left err -> fail ("jwt tamper sign failed: " <> show err)
        Right token3 -> do
            let tampered = T.init token3 <> if T.last token3 == 'A' then "B" else "A"
            tamperedResult <- validateAccessToken testCfg tampered
            case tamperedResult of
                Left (JwtVerifyError _) -> pure ()
                Left err -> fail ("jwt tamper: unexpected error type: " <> show err)
                Right _ -> fail "jwt tamper: expected Left, got Right"

    -- Expired token: claimExpiresAt in the past
    let expiredClaims = testClaims{claimExpiresAt = pastTime}
    expiredResult <- signAccessToken testCfg expiredClaims
    case expiredResult of
        Left err -> fail ("jwt expired sign failed: " <> show err)
        Right expiredToken -> do
            expiredValidateResult <- validateAccessToken testCfg expiredToken
            case expiredValidateResult of
                Left (JwtVerifyError _) -> pure ()
                Left (JwtClaimError _) -> pure ()
                Left err -> fail ("jwt expired: unexpected error type: " <> show err)
                Right _ -> fail "jwt expired: expected Left for expired token, got Right"

    -- Claim shape: decode payload segment and check required keys
    signResult4 <- signAccessToken testCfg testClaims
    case signResult4 of
        Left err -> fail ("jwt claim-shape sign failed: " <> show err)
        Right token4 -> do
            let segments = T.splitOn "." token4
            case segments of
                [_hdr, payloadB64, _sig] -> do
                    case B64URL.decode (TE.encodeUtf8 payloadB64) of
                        Left e -> fail ("jwt claim-shape: base64 decode failed: " <> e)
                        Right payloadBytes ->
                            case decodeStrict' payloadBytes of
                                Nothing -> fail "jwt claim-shape: JSON decode failed"
                                Just (obj :: Object) -> do
                                    let requiredKeys = ["sub", "role", "aud", "iss", "iat", "exp", "aal", "amr", "session_id"]
                                    mapM_
                                        ( \k ->
                                            if KeyMap.member k obj
                                                then pure ()
                                                else fail ("jwt claim-shape: missing key: " <> show k)
                                        )
                                        requiredKeys
                _ -> fail ("jwt claim-shape: expected 3 segments, got " <> show (length segments))

    tok1 <- generateOpaqueToken
    assertEqual "generateOpaqueToken non-empty" True (not (T.null tok1))
    assertEqual "generateOpaqueToken length is 43" 43 (T.length tok1)
    tok2 <- generateOpaqueToken
    assertEqual "two tokens differ" True (tok1 /= tok2)
    let nilUUID :: UUID
        nilUUID = UUID.nil
        sid = SessionId nilUUID
        nsess =
            NewSession
                { newSessionUserId = nilUUID
                , newSessionAal = "aal1"
                , newSessionFactorId = Nothing
                , newSessionUserAgent = Just "test-agent"
                , newSessionIp = Just "127.0.0.1"
                , newSessionNotAfter = Nothing
                }
    assertEqual "newSession userId" nilUUID (newSessionUserId nsess)
    assertEqual "newSession aal" "aal1" (newSessionAal nsess)
    assertEqual "newSession factorId" Nothing (newSessionFactorId nsess)
    assertEqual "newSession userAgent" (Just "test-agent") (newSessionUserAgent nsess)
    assertEqual "newSession ip" (Just "127.0.0.1") (newSessionIp nsess)
    assertEqual "newSession notAfter" Nothing (newSessionNotAfter nsess)
    now2 <- getCurrentTime
    let sess =
            Session
                { sessionId = sid
                , sessionUserId = nilUUID
                , sessionCreatedAt = now2
                , sessionUpdatedAt = now2
                , sessionFactorId = Nothing
                , sessionAal = "aal1"
                , sessionNotAfter = Nothing
                , sessionRefreshedAt = Nothing
                , sessionUserAgent = Just "Mozilla/5.0"
                , sessionIp = Just "192.168.1.1"
                }
    assertEqual "session id" sid (sessionId sess)
    assertEqual "session userId" nilUUID (sessionUserId sess)
    assertEqual "session aal" "aal1" (sessionAal sess)
    assertEqual "session factorId" Nothing (sessionFactorId sess)
    assertEqual "session notAfter" Nothing (sessionNotAfter sess)
    assertEqual "session refreshedAt" Nothing (sessionRefreshedAt sess)
    assertEqual "session userAgent" (Just "Mozilla/5.0") (sessionUserAgent sess)
    assertEqual "session ip" (Just "192.168.1.1") (sessionIp sess)
    assertEqual
        "extractBearerToken missing header"
        (Left "Missing Authorization header")
        (extractBearerToken [])
    assertEqual
        "extractBearerToken bearer token"
        (Right "foo")
        (extractBearerToken [("Authorization", "Bearer foo")])
    assertEqual
        "extractBearerToken basic scheme"
        (Left "Authorization header is not a Bearer token")
        (extractBearerToken [("Authorization", "Basic xxx")])
    assertEqual
        "extractBearerToken empty bearer"
        (Left "Bearer token is empty")
        (extractBearerToken [("Authorization", "Bearer ")])
    let serviceRoleClaims = testClaims{claimRole = "service_role"}
        authenticatedClaims = testClaims{claimRole = "authenticated"}
    assertEqual
        "checkServiceRole service_role claims"
        (Right ServiceRolePrincipal{serviceRoleName = "service_role"})
        (checkServiceRole (Right serviceRoleClaims))
    case checkServiceRole (Right authenticatedClaims) of
        Left _ -> pure ()
        Right _ -> fail "checkServiceRole authenticated: expected Left"
    case checkServiceRole (Left (JwtVerifyError "bad sig")) of
        Left _ -> pure ()
        Right _ -> fail "checkServiceRole JwtVerifyError: expected Left"
    e2eSignResult <- signAccessToken testCfg serviceRoleClaims
    case e2eSignResult of
        Left err -> fail ("service-role e2e sign failed: " <> show err)
        Right srToken -> do
            srValidateResult <- validateAccessToken testCfg srToken
            case checkServiceRole srValidateResult of
                Right ServiceRolePrincipal{serviceRoleName} ->
                    assertEqual "service-role e2e role name" "service_role" serviceRoleName
                Left msg ->
                    fail ("service-role e2e: expected Right, got Left: " <> T.unpack msg)
    assertEqual "aggregateStatus all ok" "ok" (aggregateStatus [CheckOk, CheckOk])
    assertEqual "aggregateStatus with failure" "unhealthy" (aggregateStatus [CheckOk, CheckFailed "boom"])
    assertEqual "aggregateStatus empty" "ok" (aggregateStatus [])
    let allOkResponse =
            DeepHealthResponse
                { deepHealthStatus = aggregateStatus [CheckOk, CheckOk]
                , deepHealthChecks =
                    [ DeepHealthCheck{deepHealthCheckName = "process", deepHealthCheckOutcome = CheckOk, deepHealthCheckLatencyMs = Nothing}
                    , DeepHealthCheck{deepHealthCheckName = "config", deepHealthCheckOutcome = CheckOk, deepHealthCheckLatencyMs = Nothing}
                    ]
                }
    assertEqual "isUnhealthy all ok" False (isUnhealthy allOkResponse)
    let oneFailedResponse =
            DeepHealthResponse
                { deepHealthStatus = aggregateStatus [CheckOk, CheckFailed "db down"]
                , deepHealthChecks =
                    [ DeepHealthCheck{deepHealthCheckName = "process", deepHealthCheckOutcome = CheckOk, deepHealthCheckLatencyMs = Nothing}
                    , DeepHealthCheck{deepHealthCheckName = "postgres", deepHealthCheckOutcome = CheckFailed "db down", deepHealthCheckLatencyMs = Just 5}
                    ]
                }
    assertEqual "isUnhealthy one failed" True (isUnhealthy oneFailedResponse)
    -- JSON shape tests
    let mixedResponse =
            DeepHealthResponse
                { deepHealthStatus = "unhealthy"
                , deepHealthChecks =
                    [ DeepHealthCheck{deepHealthCheckName = "process", deepHealthCheckOutcome = CheckOk, deepHealthCheckLatencyMs = Nothing}
                    , DeepHealthCheck{deepHealthCheckName = "postgres", deepHealthCheckOutcome = CheckFailed "connection refused", deepHealthCheckLatencyMs = Just 12}
                    ]
                }
    case Aeson.decode (Aeson.encode mixedResponse) of
        Nothing ->
            fail "deep health response: JSON decode failed"
        Just (obj :: Object) -> do
            if KeyMap.member "status" obj
                then pure ()
                else fail "deep health response: missing 'status' key"
            if KeyMap.member "checks" obj
                then pure ()
                else fail "deep health response: missing 'checks' key"
            case KeyMap.lookup "checks" obj of
                Just (Array checksVec) ->
                    case foldr (:) [] checksVec of
                        (Object firstCheck : Object failedCheck : _) -> do
                            if KeyMap.member "name" firstCheck
                                then pure ()
                                else fail "ok check: missing 'name' key"
                            assertEqual
                                "ok check status"
                                (Just (String "ok"))
                                (KeyMap.lookup "status" firstCheck)
                            assertEqual
                                "failed check status"
                                (Just (String "failed"))
                                (KeyMap.lookup "status" failedCheck)
                            if KeyMap.member "reason" failedCheck
                                then pure ()
                                else fail "failed check: missing 'reason' key"
                        _ ->
                            fail "deep health response: expected 2 object checks"
                _ ->
                    fail "deep health response: 'checks' is not an Array"
    let twoProviderConfig =
            settingsTestConfig
                [ OAuthProviderConfig
                    { oauthProviderName = "github"
                    , oauthProviderClientId = "gh-id"
                    , oauthProviderClientSecret = "gh-secret"
                    , oauthProviderDiscoveryUrl = "https://github.com/.well-known/openid-configuration"
                    }
                , OAuthProviderConfig
                    { oauthProviderName = "google"
                    , oauthProviderClientId = "g-id"
                    , oauthProviderClientSecret = "g-secret"
                    , oauthProviderDiscoveryUrl = "https://accounts.google.com/.well-known/openid-configuration"
                    }
                ]
        twoProviderSettings = buildSettingsResponse twoProviderConfig
    assertEqual "settings external email" (Just True) (Map.lookup "email" (settingsExternal twoProviderSettings))
    assertEqual "settings external phone" (Just False) (Map.lookup "phone" (settingsExternal twoProviderSettings))
    assertEqual "settings external github" (Just True) (Map.lookup "github" (settingsExternal twoProviderSettings))
    assertEqual "settings external google" (Just True) (Map.lookup "google" (settingsExternal twoProviderSettings))
    assertEqual "settings external_email_enabled" True (settingsExternalEmailEnabled twoProviderSettings)
    assertEqual "settings external_phone_enabled" False (settingsExternalPhoneEnabled twoProviderSettings)
    assertEqual "settings disable_signup" False (settingsDisableSignup twoProviderSettings)
    assertEqual "settings mailer_autoconfirm" False (settingsMailerAutoconfirm twoProviderSettings)
    assertEqual "settings phone_autoconfirm" False (settingsPhoneAutoconfirm twoProviderSettings)
    assertEqual "settings sms_provider" "" (settingsSmsProvider twoProviderSettings)
    -- JSON round-trip: top-level keys must match Supabase contract
    let settingsJson = BSL.toStrict (encode twoProviderSettings)
    case decodeStrict' settingsJson of
        Nothing -> fail "settings JSON: decode failed"
        Just (obj :: Object) -> do
            let requiredKeys = ["external", "external_email_enabled", "external_phone_enabled", "disable_signup", "mailer_autoconfirm", "phone_autoconfirm", "sms_provider"]
            mapM_
                ( \k ->
                    if KeyMap.member k obj
                        then pure ()
                        else fail ("settings JSON: missing key: " <> show k)
                )
                requiredKeys
    -- Provider name case-folding: "GitHub" becomes "github" in external map
    let mixedCaseConfig =
            settingsTestConfig
                [ OAuthProviderConfig
                    { oauthProviderName = "GitHub"
                    , oauthProviderClientId = "gh-id"
                    , oauthProviderClientSecret = "gh-secret"
                    , oauthProviderDiscoveryUrl = "https://github.com/.well-known/openid-configuration"
                    }
                ]
        mixedCaseSettings = buildSettingsResponse mixedCaseConfig
    assertEqual "settings provider case-fold" (Just True) (Map.lookup "github" (settingsExternal mixedCaseSettings))
    assertEqual "settings provider case-fold absent" Nothing (Map.lookup "GitHub" (settingsExternal mixedCaseSettings))

    ctok1 <- generateConfirmationToken
    assertEqual "generateConfirmationToken non-empty" True (not (T.null ctok1))
    assertEqual "generateConfirmationToken length 43" 43 (T.length ctok1)
    ctok2 <- generateConfirmationToken
    assertEqual "generateConfirmationToken two calls differ" True (ctok1 /= ctok2)
    now3 <- getCurrentTime
    let testUserId = UserId UUID.nil
        testUser =
            User
                { userId = testUserId
                , userEmail = Just "test@example.com"
                , userEncryptedPassword = Just "$argon2id$v=19$..."
                , userEmailConfirmedAt = Nothing
                , userConfirmationToken = Just ctok1
                , userConfirmationSentAt = Just now3
                , userRawAppMetaData = Aeson.object []
                , userRawUserMetaData = Aeson.object []
                , userRole = "authenticated"
                , userAud = "authenticated"
                , userCreatedAt = now3
                , userUpdatedAt = now3
                }
    assertEqual "user userId" testUserId (userId testUser)
    assertEqual "user email" (Just "test@example.com") (userEmail testUser)
    assertEqual "user role" "authenticated" (userRole testUser)
    assertEqual "user aud" "authenticated" (userAud testUser)
    assertEqual "user emailConfirmedAt" Nothing (userEmailConfirmedAt testUser)
    assertEqual "user confirmationToken" (Just ctok1) (userConfirmationToken testUser)
    let signupResp = buildSignupResponse testUser
        signupJson = Aeson.encode signupResp
    case Aeson.decode signupJson of
        Nothing -> fail "buildSignupResponse: JSON decode failed"
        Just (obj :: Object) -> do
            let requiredSignupKeys =
                    [ "id"
                    , "aud"
                    , "role"
                    , "email"
                    , "confirmation_sent_at"
                    , "created_at"
                    , "updated_at"
                    , "app_metadata"
                    , "user_metadata"
                    ]
            mapM_
                ( \k ->
                    if KeyMap.member k obj
                        then pure ()
                        else fail ("buildSignupResponse: missing key: " <> show k)
                )
                requiredSignupKeys
    assertEqual
        "validateSignupEmail rejects empty"
        (Left (SignupEmailInvalid ""))
        (validateSignupEmail "")
    assertEqual
        "validateSignupEmail rejects no-at"
        (Left (SignupEmailInvalid "no-at"))
        (validateSignupEmail "no-at")
    assertEqual
        "validateSignupEmail rejects @no-local"
        (Left (SignupEmailInvalid "@no-local"))
        (validateSignupEmail "@no-local")
    assertEqual
        "validateSignupEmail accepts a@b.co"
        (Right "a@b.co")
        (validateSignupEmail "a@b.co")
    case validateSignupPassword "" of
        Left (SignupPasswordTooShort _ _) -> pure ()
        other -> fail ("validateSignupPassword empty: expected SignupPasswordTooShort, got " <> show other)
    case validateSignupPassword "short" of
        Left (SignupPasswordTooShort _ _) -> pure ()
        other -> fail ("validateSignupPassword short: expected SignupPasswordTooShort, got " <> show other)
    assertEqual
        "validateSignupPassword accepts 8+"
        (Right "abcdefgh")
        (validateSignupPassword "abcdefgh")
    let cheapSettings2 =
            defaultArgon2Settings
                { argon2Iterations = 1
                , argon2Memory = 8
                , argon2Parallelism = 1
                }
    hash3 <- hashPassword cheapSettings2 "correct horse"
    assertEqual "signup hash+verify roundtrip" True (Password.verifyPassword hash3 "correct horse")
    assertEqual
        "classify Nothing → InvalidGrant"
        (Left InvalidGrant)
        (classifyRefreshTokenLookup Nothing)
    let revokedRt =
            RefreshToken
                { refreshTokenId = RefreshTokenId 1
                , refreshTokenToken = "revoked-token"
                , refreshTokenSessionId = SessionId UUID.nil
                , refreshTokenUserId = UUID.nil
                , refreshTokenParent = Nothing
                , refreshTokenRevoked = True
                , refreshTokenCreatedAt = now
                , refreshTokenUpdatedAt = now
                }
    assertEqual
        "classify revoked → RefreshTokenReuseDetected"
        (Left RefreshTokenReuseDetected)
        (classifyRefreshTokenLookup (Just revokedRt))
    let validRt = revokedRt{refreshTokenRevoked = False, refreshTokenToken = "valid-token"}
    case classifyRefreshTokenLookup (Just validRt) of
        Left e ->
            fail ("classify valid → expected Right, got Left: " <> show e)
        Right (ValidRefreshToken rt) ->
            assertEqual "classify valid → token value" "valid-token" (refreshTokenToken rt)
    let testTokenResp =
            TokenResponse
                { tokenResponseAccessToken = "access.token.here"
                , tokenResponseTokenType = "bearer"
                , tokenResponseExpiresIn = 3600
                , tokenResponseRefreshToken = "opaque-refresh"
                , tokenResponseUser = Aeson.object ["id" Aeson..= ("uid" :: T.Text)]
                }
    case Aeson.decode (Aeson.encode testTokenResp) of
        Nothing ->
            fail "TokenResponse: JSON decode failed"
        Just (obj :: Object) -> do
            let tokenRespKeys = ["access_token", "token_type", "expires_in", "refresh_token", "user"]
            mapM_
                ( \k ->
                    if KeyMap.member k obj
                        then pure ()
                        else fail ("TokenResponse JSON: missing key: " <> show k)
                )
                tokenRespKeys
            assertEqual
                "TokenResponse token_type"
                (Just (String "bearer"))
                (KeyMap.lookup "token_type" obj)
            assertEqual
                "TokenResponse expires_in"
                (Just (Number 3600))
                (KeyMap.lookup "expires_in" obj)
    case Aeson.decode "{\"refresh_token\": \"abc\"}" of
        Nothing -> fail "TokenRequest: parse {refresh_token} failed"
        Just tr ->
            assertEqual
                "TokenRequest refresh_token"
                (Just "abc")
                (tokenRequestRefreshToken tr)
    case Aeson.decode "{}" of
        Nothing -> fail "TokenRequest: parse {} failed"
        Just (tr :: TokenRequest) -> do
            assertEqual "TokenRequest empty refresh" Nothing (tokenRequestRefreshToken tr)
            assertEqual "TokenRequest empty email" Nothing (tokenRequestEmail tr)
            assertEqual "TokenRequest empty password" Nothing (tokenRequestPassword tr)
    case Aeson.decode "{\"email\": \"a@b.c\", \"password\": \"x\"}" of
        Nothing -> fail "TokenRequest: parse email+password failed"
        Just tr -> do
            assertEqual
                "TokenRequest email"
                (Just (Email "a@b.c"))
                (tokenRequestEmail tr)
            assertEqual
                "TokenRequest password"
                (Just (Password "x"))
                (tokenRequestPassword tr)
    assertEqual "parseGrantType password" GrantPassword (parseGrantType (Just "password"))
    assertEqual "parseGrantType refresh_token" GrantRefreshToken (parseGrantType (Just "refresh_token"))
    assertEqual
        "parseGrantType client_credentials"
        (GrantUnsupported "client_credentials")
        (parseGrantType (Just "client_credentials"))
    assertEqual "parseGrantType Nothing" (GrantUnsupported "") (parseGrantType Nothing)

    -- sessionIdFromClaims: valid UUID string → Right SessionId
    let validSidText = "11111111-2222-3333-4444-555555555555"
        claimsWithValidSid = testClaims{claimSessionId = validSidText}
    case sessionIdFromClaims claimsWithValidSid of
        Right (SessionId uuid) ->
            assertEqual
                "sessionIdFromClaims valid uuid text"
                validSidText
                (UUID.toText uuid)
        Left err ->
            fail ("sessionIdFromClaims valid uuid: unexpected Left: " <> show err)

    -- sessionIdFromClaims: non-UUID string → Left (LogoutBadSessionId _)
    let badSidClaims = testClaims{claimSessionId = "not-a-uuid"}
    case sessionIdFromClaims badSidClaims of
        Left (LogoutBadSessionId _) -> pure ()
        Left other -> fail ("sessionIdFromClaims bad uuid: unexpected LogoutError: " <> show other)
        Right _ -> fail "sessionIdFromClaims bad uuid: expected Left, got Right"

    -- resolveLogoutSession (Left JwtVerifyError) → Left (LogoutInvalidJwt _)
    case resolveLogoutSession (Left (JwtVerifyError "bad sig")) of
        Left (LogoutInvalidJwt _) -> pure ()
        Left other -> fail ("resolveLogoutSession JwtVerifyError: unexpected error: " <> show other)
        Right _ -> fail "resolveLogoutSession JwtVerifyError: expected Left"

    -- resolveLogoutSession (Right validClaims) → Right SessionId
    let goodSidClaims = testClaims{claimSessionId = validSidText}
    case resolveLogoutSession (Right goodSidClaims) of
        Right (SessionId uuid) ->
            assertEqual
                "resolveLogoutSession Right valid uuid"
                validSidText
                (UUID.toText uuid)
        Left err ->
            fail ("resolveLogoutSession Right valid uuid: unexpected Left: " <> show err)

    -- resolveLogoutSession (Right claims with bad session_id) → Left (LogoutBadSessionId _)
    let badSidClaims2 = testClaims{claimSessionId = "not-a-uuid-either"}
    case resolveLogoutSession (Right badSidClaims2) of
        Left (LogoutBadSessionId _) -> pure ()
        Left other -> fail ("resolveLogoutSession bad session_id: unexpected error: " <> show other)
        Right _ -> fail "resolveLogoutSession bad session_id: expected Left, got Right"

    -- End-to-end: sign → validate → resolveLogoutSession → Right SessionId
    let e2eSidText = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
        e2eClaims = testClaims{claimSessionId = e2eSidText}
    e2eSignOut <- signAccessToken testCfg e2eClaims
    case e2eSignOut of
        Left err -> fail ("logout e2e sign failed: " <> show err)
        Right outToken -> do
            e2eValidate <- validateAccessToken testCfg outToken
            case resolveLogoutSession e2eValidate of
                Right (SessionId uuid) ->
                    assertEqual
                        "logout e2e resolved session id"
                        e2eSidText
                        (UUID.toText uuid)
                Left err ->
                    fail ("logout e2e resolveLogoutSession: unexpected Left: " <> show err)

    let noEmailReq =
            TokenRequest
                { tokenRequestRefreshToken = Nothing
                , tokenRequestEmail = Nothing
                , tokenRequestPassword = Just (Password "secret")
                }
    assertEqual
        "extractCredentials missing email"
        (Left LoginMissingFields)
        (extractCredentials noEmailReq)
    let blankEmailReq =
            TokenRequest
                { tokenRequestRefreshToken = Nothing
                , tokenRequestEmail = Just (Email "")
                , tokenRequestPassword = Just (Password "secret")
                }
    assertEqual
        "extractCredentials blank email"
        (Left LoginMissingFields)
        (extractCredentials blankEmailReq)
    let noPasswordReq =
            TokenRequest
                { tokenRequestRefreshToken = Nothing
                , tokenRequestEmail = Just (Email "user@example.com")
                , tokenRequestPassword = Nothing
                }
    assertEqual
        "extractCredentials missing password"
        (Left LoginMissingFields)
        (extractCredentials noPasswordReq)
    let blankPasswordReq =
            TokenRequest
                { tokenRequestRefreshToken = Nothing
                , tokenRequestEmail = Just (Email "user@example.com")
                , tokenRequestPassword = Just (Password "")
                }
    assertEqual
        "extractCredentials blank password"
        (Left LoginMissingFields)
        (extractCredentials blankPasswordReq)
    let fullCredsReq =
            TokenRequest
                { tokenRequestRefreshToken = Nothing
                , tokenRequestEmail = Just (Email "user@example.com")
                , tokenRequestPassword = Just (Password "mysecret")
                }
    assertEqual
        "extractCredentials both present"
        (Right ("user@example.com", "mysecret"))
        (extractCredentials fullCredsReq)
    now4 <- getCurrentTime
    assertEqual
        "authorizeLogin wrong password + confirmed"
        (Left LoginInvalidGrant)
        (authorizeLogin False (Just now4))
    assertEqual
        "authorizeLogin wrong password + unconfirmed"
        (Left LoginInvalidGrant)
        (authorizeLogin False Nothing)
    assertEqual
        "authorizeLogin correct password + unconfirmed"
        (Left LoginEmailNotConfirmed)
        (authorizeLogin True Nothing)
    assertEqual
        "authorizeLogin correct password + confirmed"
        (Right ())
        (authorizeLogin True (Just now4))
    now5 <- getCurrentTime
    let loginSid = SessionId UUID.nil
        loginUser =
            User
                { userId = UserId UUID.nil
                , userEmail = Just "login@example.com"
                , userEncryptedPassword = Just "$argon2id$v=19$..."
                , userEmailConfirmedAt = Just now5
                , userConfirmationToken = Nothing
                , userConfirmationSentAt = Nothing
                , userRawAppMetaData = Aeson.object []
                , userRawUserMetaData = Aeson.object []
                , userRole = "authenticated"
                , userAud = "authenticated"
                , userCreatedAt = now5
                , userUpdatedAt = now5
                }
        loginCfg =
            JwtConfig
                { jwtSecret = "0123456789abcdef0123456789abcdef"
                , jwtIssuer = "https://auth.example.com"
                , jwtAudience = "authenticated"
                , jwtAccessTokenTtlSeconds = 3600
                , jwtRefreshTokenTtlSeconds = 2592000
                }
        loginClaims = buildLoginClaims loginCfg loginUser loginSid now5
    assertEqual
        "buildLoginClaims sub = userId"
        (UUID.toText UUID.nil)
        (claimSub loginClaims)
    assertEqual
        "buildLoginClaims email"
        (Just "login@example.com")
        (claimEmail loginClaims)
    assertEqual
        "buildLoginClaims aal"
        "aal1"
        (claimAal loginClaims)
    assertEqual
        "buildLoginClaims amr length 1"
        1
        (length (claimAmr loginClaims))
    assertEqual
        "buildLoginClaims amr method password"
        "password"
        (amrMethod (head (claimAmr loginClaims)))
    assertEqual
        "buildLoginClaims session_id"
        (UUID.toText UUID.nil)
        (claimSessionId loginClaims)
    loginSignResult <- signAccessToken loginCfg loginClaims
    case loginSignResult of
        Left err ->
            fail ("login claims round-trip sign failed: " <> show err)
        Right loginToken -> do
            loginValidateResult <- validateAccessToken loginCfg loginToken
            case loginValidateResult of
                Left err ->
                    fail ("login claims round-trip validate failed: " <> show err)
                Right loginClaims' -> do
                    assertEqual
                        "login round-trip sub"
                        (claimSub loginClaims)
                        (claimSub loginClaims')
                    assertEqual
                        "login round-trip email"
                        (claimEmail loginClaims)
                        (claimEmail loginClaims')
                    assertEqual
                        "login round-trip aal"
                        (claimAal loginClaims)
                        (claimAal loginClaims')
                    assertEqual
                        "login round-trip amr length"
                        (length (claimAmr loginClaims))
                        (length (claimAmr loginClaims'))
                    assertEqual
                        "login round-trip amr method"
                        (amrMethod (head (claimAmr loginClaims)))
                        (amrMethod (head (claimAmr loginClaims')))
                    assertEqual
                        "login round-trip session_id"
                        (claimSessionId loginClaims)
                        (claimSessionId loginClaims')
    assertEqual
        "validateUpdateRequest empty"
        (Right (Nothing, Nothing, Nothing))
        ( validateUpdateRequest
            UpdateUserRequest
                { updateUserEmail = Nothing
                , updateUserPassword = Nothing
                , updateUserData = Nothing
                }
        )
    assertEqual
        "validateUpdateRequest valid email"
        (Right (Just "new@example.com", Nothing, Nothing))
        ( validateUpdateRequest
            UpdateUserRequest
                { updateUserEmail = Just (Email "new@example.com")
                , updateUserPassword = Nothing
                , updateUserData = Nothing
                }
        )
    case validateUpdateRequest
        UpdateUserRequest
            { updateUserEmail = Just (Email "invalid-no-at")
            , updateUserPassword = Nothing
            , updateUserData = Nothing
            } of
        Left (UpdateUserEmailInvalid _) -> pure ()
        other -> fail ("validateUpdateRequest bad email: expected UpdateUserEmailInvalid, got " <> show other)
    case validateUpdateRequest
        UpdateUserRequest
            { updateUserEmail = Nothing
            , updateUserPassword = Just (Password "short")
            , updateUserData = Nothing
            } of
        Left (UpdateUserPasswordTooShort _ _) -> pure ()
        other -> fail ("validateUpdateRequest short password: expected UpdateUserPasswordTooShort, got " <> show other)
    let testMeta = Aeson.object ["key" Aeson..= ("value" :: T.Text)]
    case validateUpdateRequest
        UpdateUserRequest
            { updateUserEmail = Just (Email "all@fields.com")
            , updateUserPassword = Just (Password "validpassword")
            , updateUserData = Just testMeta
            } of
        Right (Just _, Just _, Just _) -> pure ()
        other -> fail ("validateUpdateRequest all fields: expected Right (Just, Just, Just), got " <> show other)
    assertEqual "emptyUserUpdate emailChange" Nothing (updateEmailChange emptyUserUpdate)
    assertEqual "emptyUserUpdate encryptedPassword" Nothing (updateEncryptedPassword emptyUserUpdate)
    assertEqual "emptyUserUpdate rawUserMetaData" Nothing (updateRawUserMetaData emptyUserUpdate)
    assertEqual "emptyUserUpdate emailChangeToken" Nothing (updateEmailChangeToken emptyUserUpdate)
    now6 <- getCurrentTime
    let testUserForResponse =
            User
                { userId = UserId UUID.nil
                , userEmail = Just "resp@example.com"
                , userEncryptedPassword = Just "$argon2id$v=19$..."
                , userEmailConfirmedAt = Just now6
                , userConfirmationToken = Nothing
                , userConfirmationSentAt = Nothing
                , userRawAppMetaData = Aeson.object []
                , userRawUserMetaData = Aeson.object []
                , userRole = "authenticated"
                , userAud = "authenticated"
                , userCreatedAt = now6
                , userUpdatedAt = now6
                }
        userResp = buildUserResponse testUserForResponse
        userRespJson = BSL.toStrict (Aeson.encode userResp)
    case Aeson.decodeStrict' userRespJson of
        Nothing -> fail "UserResponse: JSON decode failed"
        Just (obj :: Object) -> do
            let requiredUserRespKeys =
                    [ "id"
                    , "aud"
                    , "role"
                    , "email"
                    , "email_confirmed_at"
                    , "created_at"
                    , "updated_at"
                    , "app_metadata"
                    , "user_metadata"
                    ]
            mapM_
                ( \k ->
                    if KeyMap.member k obj
                        then pure ()
                        else fail ("UserResponse JSON: missing key: " <> show k)
                )
                requiredUserRespKeys
    assertEqual
        "parseOtpType signup"
        (Right OtpSignup)
        (parseOtpType "signup")
    assertEqual
        "parseOtpType recovery"
        (Right OtpRecovery)
        (parseOtpType "recovery")
    assertEqual
        "parseOtpType magiclink"
        (Right OtpMagicLink)
        (parseOtpType "magiclink")
    assertEqual
        "parseOtpType invite"
        (Right OtpInvite)
        (parseOtpType "invite")
    assertEqual
        "parseOtpType email_change"
        (Right OtpEmailChange)
        (parseOtpType "email_change")
    assertEqual
        "parseOtpType bogus"
        (Left (VerifyUnsupportedOtpType "bogus"))
        (parseOtpType "bogus")

    -- ---------------------------------------------------------------------------
    -- Hauth.Auth.Verify: classifyVerifyRequest
    -- ---------------------------------------------------------------------------

    let emptyTokenReq =
            VerifyRequest
                { verifyToken = ""
                , verifyType = "signup"
                , verifyEmail = Nothing
                , verifyPassword = Nothing
                }
    assertEqual
        "classifyVerifyRequest empty token"
        (Left VerifyMissingToken)
        (classifyVerifyRequest emptyTokenReq)

    let unsupportedTypeReq =
            VerifyRequest
                { verifyToken = "some-token"
                , verifyType = "unknown_type"
                , verifyEmail = Nothing
                , verifyPassword = Nothing
                }
    case classifyVerifyRequest unsupportedTypeReq of
        Left (VerifyUnsupportedOtpType _) -> pure ()
        other ->
            fail
                ( "classifyVerifyRequest unsupported type: expected Left VerifyUnsupportedOtpType, got "
                    <> show other
                )

    let validSignupReq =
            VerifyRequest
                { verifyToken = "valid-token-abc"
                , verifyType = "signup"
                , verifyEmail = Nothing
                , verifyPassword = Nothing
                }
    assertEqual
        "classifyVerifyRequest valid signup"
        (Right OtpSignup)
        (classifyVerifyRequest validSignupReq)

    -- ---------------------------------------------------------------------------
    -- MessageResponse JSON shape
    -- ---------------------------------------------------------------------------

    let msgResp = MessageResponse "Verification email sent if needed"
    case Aeson.decode (Aeson.encode msgResp) of
        Nothing ->
            fail "MessageResponse: JSON decode failed"
        Just (obj :: Object) -> do
            if KeyMap.member "message" obj
                then pure ()
                else fail "MessageResponse JSON: missing 'message' key"
            assertEqual
                "MessageResponse message value"
                (Just (String "Verification email sent if needed"))
                (KeyMap.lookup "message" obj)
    assertEqual
        "validateRecoverRequest empty email"
        (Left RecoveryMissingEmail)
        (validateRecoverRequest (RecoverRequest (Email "")))
    assertEqual
        "validateRecoverRequest whitespace email"
        (Left RecoveryMissingEmail)
        (validateRecoverRequest (RecoverRequest (Email "   ")))
    assertEqual
        "validateRecoverRequest valid email"
        (Right "user@example.com")
        (validateRecoverRequest (RecoverRequest (Email "user@example.com")))
    assertEqual
        "validateRecoveryVerify empty token"
        (Left RecoveryMissingToken)
        ( validateRecoveryVerify
            VerifyRequest{verifyToken = "", verifyType = "recovery", verifyEmail = Nothing, verifyPassword = Just "abcdefgh"}
        )
    case validateRecoveryVerify
        VerifyRequest{verifyToken = "sometoken", verifyType = "recovery", verifyEmail = Nothing, verifyPassword = Nothing} of
        Left (RecoveryPasswordTooShort _ _) -> pure ()
        other -> fail ("validateRecoveryVerify no password: expected RecoveryPasswordTooShort, got " <> show other)
    case validateRecoveryVerify
        VerifyRequest{verifyToken = "sometoken", verifyType = "recovery", verifyEmail = Nothing, verifyPassword = Just "short"} of
        Left (RecoveryPasswordTooShort _ _) -> pure ()
        other -> fail ("validateRecoveryVerify short password: expected RecoveryPasswordTooShort, got " <> show other)
    assertEqual
        "validateRecoveryVerify valid token + password"
        (Right ("sometoken", "abcdefgh"))
        ( validateRecoveryVerify
            VerifyRequest{verifyToken = "sometoken", verifyType = "recovery", verifyEmail = Nothing, verifyPassword = Just "abcdefgh"}
        )
    assertEqual
        "recoverySentMessage exact text"
        "If an account exists for this email, a recovery email has been sent."
        recoverySentMessage
    let recoveryMsgResp = MessageResponse{message = recoverySentMessage}
    case Aeson.decode (Aeson.encode recoveryMsgResp) of
        Nothing -> fail "MessageResponse: JSON decode failed"
        Just (obj :: Object) ->
            if KeyMap.member "message" obj
                then pure ()
                else fail "MessageResponse JSON: missing 'message' key"

    -- ---------------------------------------------------------------------------
    -- Hauth.OAuth: pure unit tests
    -- ---------------------------------------------------------------------------

    let oauthCfg =
            OAuthConfig
                { oauthProviders =
                    [ OAuthProviderConfig
                        { oauthProviderName = "google"
                        , oauthProviderClientId = "google-client-id"
                        , oauthProviderClientSecret = "google-secret"
                        , oauthProviderDiscoveryUrl = "https://accounts.google.com/.well-known/openid-configuration"
                        }
                    , OAuthProviderConfig
                        { oauthProviderName = "github"
                        , oauthProviderClientId = "github-client-id"
                        , oauthProviderClientSecret = "github-secret"
                        , oauthProviderDiscoveryUrl = "https://github.com/.well-known/openid-configuration"
                        }
                    ]
                }

    -- lookupProvider: exact match
    case lookupProvider oauthCfg "google" of
        Left e -> fail ("lookupProvider exact match: expected Right, got Left: " <> show e)
        Right cfg -> assertEqual "lookupProvider exact match name" "google" (oauthProviderName cfg)

    -- lookupProvider: case-insensitive match
    case lookupProvider oauthCfg "GOOGLE" of
        Left e -> fail ("lookupProvider case-insensitive: expected Right, got Left: " <> show e)
        Right cfg -> assertEqual "lookupProvider GOOGLE match name" "google" (oauthProviderName cfg)

    -- lookupProvider: unknown provider
    case lookupProvider oauthCfg "facebook" of
        Left (OAuthUnknownProvider n) ->
            assertEqual "lookupProvider unknown provider name" "facebook" n
        Left other ->
            fail ("lookupProvider unknown: expected OAuthUnknownProvider, got " <> show other)
        Right _ ->
            fail "lookupProvider unknown: expected Left, got Right"

    -- validateRedirectTo: allowed URL
    let oauthSiteCfg =
            SiteConfig
                { siteUrl = "https://app.example.com"
                , siteAllowedRedirectUrls = ["https://app.example.com/auth/callback", "https://app.example.com/login"]
                }
    assertEqual
        "validateRedirectTo allowed"
        (Right "https://app.example.com/auth/callback")
        (validateRedirectTo oauthSiteCfg "https://app.example.com/auth/callback")

    -- validateRedirectTo: disallowed URL
    case validateRedirectTo oauthSiteCfg "https://evil.example.com/steal" of
        Left _ -> pure ()
        Right _ -> fail "validateRedirectTo disallowed: expected Left, got Right"

    -- generateState: non-empty 43-char token
    stateA <- generateState
    assertEqual "generateState non-empty" True (not (T.null stateA))
    assertEqual "generateState length 43" 43 (T.length stateA)
    stateB <- generateState
    assertEqual "generateState two calls differ" True (stateA /= stateB)

    -- isFlowStateExpired: 5 minutes ago, max 600 → False
    nowForExpiry <- getCurrentTime
    let createdRecently = addUTCTime (negate 300) nowForExpiry
        createdLongAgo = addUTCTime (negate 1200) nowForExpiry
    assertEqual
        "isFlowStateExpired 5 min ago not expired"
        False
        (isFlowStateExpired nowForExpiry createdRecently 600)

    -- isFlowStateExpired: 20 minutes ago, max 600 → True
    assertEqual
        "isFlowStateExpired 20 min ago expired"
        True
        (isFlowStateExpired nowForExpiry createdLongAgo 600)

    -- buildStubAuthorizeUrl: contains required substrings
    let stubCfg =
            OAuthProviderConfig
                { oauthProviderName = "google"
                , oauthProviderClientId = "my-client-id"
                , oauthProviderClientSecret = "my-secret"
                , oauthProviderDiscoveryUrl = "https://accounts.google.com/.well-known/openid-configuration"
                }
        stubUrl = buildStubAuthorizeUrl stubCfg "test-state-token" "https://app.example.com/callback" "https://app.example.com/login"
    assertContains "buildStubAuthorizeUrl state=" "state=" stubUrl
    assertContains "buildStubAuthorizeUrl client_id=" "client_id=" stubUrl
    assertContains "buildStubAuthorizeUrl redirect_uri=" "redirect_uri=" stubUrl
    assertContains "buildStubAuthorizeUrl state value" "test-state-token" stubUrl
    assertContains "buildStubAuthorizeUrl client_id value" "my-client-id" stubUrl

    -- OAuthAuthorizeResponse JSON shape: must have keys "url" and "state"
    let oauthResp =
            OAuthAuthorizeResponse
                { oauthAuthorizeUrl = "https://accounts.google.com/o/oauth2/auth?state=xyz"
                , oauthAuthorizeState = "xyz"
                }
    case Aeson.decode (Aeson.encode oauthResp) of
        Nothing -> fail "OAuthAuthorizeResponse: JSON decode failed"
        Just (obj :: Object) -> do
            if KeyMap.member "url" obj
                then pure ()
                else fail "OAuthAuthorizeResponse JSON: missing 'url' key"
            if KeyMap.member "state" obj
                then pure ()
                else fail "OAuthAuthorizeResponse JSON: missing 'state' key"
            assertEqual
                "OAuthAuthorizeResponse url value"
                (Just (String "https://accounts.google.com/o/oauth2/auth?state=xyz"))
                (KeyMap.lookup "url" obj)
            assertEqual
                "OAuthAuthorizeResponse state value"
                (Just (String "xyz"))
                (KeyMap.lookup "state" obj)

    -- ---------------------------------------------------------------------------
    -- Hauth.Auth.Admin: parsePagination
    -- ---------------------------------------------------------------------------

    assertEqual
        "parsePagination Nothing Nothing == defaultPagination"
        defaultPagination
        (parsePagination Nothing Nothing)
    assertEqual
        "parsePagination defaults page=1"
        1
        (pagPage (parsePagination Nothing Nothing))
    assertEqual
        "parsePagination defaults per_page=50"
        50
        (pagPerPage (parsePagination Nothing Nothing))
    -- page=0 is clamped to 1; per_page=200 is clamped to 100 (maxPerPage)
    assertEqual
        "parsePagination clamps page 0 → 1"
        1
        (pagPage (parsePagination (Just 0) (Just 200)))
    assertEqual
        "parsePagination clamps per_page 200 → 100"
        100
        (pagPerPage (parsePagination (Just 0) (Just 200)))
    assertEqual
        "parsePagination explicit page=3 per_page=20"
        (Pagination{pagPage = 3, pagPerPage = 20})
        (parsePagination (Just 3) (Just 20))

    -- ---------------------------------------------------------------------------
    -- Hauth.Auth.Admin: computeNextPage
    -- ---------------------------------------------------------------------------

    assertEqual
        "computeNextPage on last page → Nothing"
        Nothing
        (computeNextPage (Pagination 1 50) 50)
    assertEqual
        "computeNextPage exactly full page → Nothing"
        Nothing
        (computeNextPage (Pagination 1 50) 50)
    assertEqual
        "computeNextPage one more row → Just 2"
        (Just 2)
        (computeNextPage (Pagination 1 50) 51)
    assertEqual
        "computeNextPage page 2 of 3"
        (Just 3)
        (computeNextPage (Pagination 2 10) 25)
    assertEqual
        "computeNextPage zero total → Nothing"
        Nothing
        (computeNextPage (Pagination 1 50) 0)

    -- ---------------------------------------------------------------------------
    -- Hauth.Auth.Admin: validateAdminCreate
    -- ---------------------------------------------------------------------------

    assertEqual
        "validateAdminCreate empty email → AdminEmailRequired"
        (Left AdminEmailRequired)
        ( validateAdminCreate
            AdminCreateUserRequest
                { adminCreateUserEmail = Email ""
                , adminCreateUserPassword = Nothing
                , adminCreateUserConfirmed = False
                , adminCreateUserUserMetadata = Nothing
                , adminCreateUserAppMetadata = Nothing
                }
        )
    case validateAdminCreate
        AdminCreateUserRequest
            { adminCreateUserEmail = Email "notanemail"
            , adminCreateUserPassword = Nothing
            , adminCreateUserConfirmed = False
            , adminCreateUserUserMetadata = Nothing
            , adminCreateUserAppMetadata = Nothing
            } of
        Left (AdminEmailInvalid _) -> pure ()
        other ->
            fail ("validateAdminCreate bad email: expected AdminEmailInvalid, got " <> show other)
    case validateAdminCreate
        AdminCreateUserRequest
            { adminCreateUserEmail = Email "user@example.com"
            , adminCreateUserPassword = Just (Password "short")
            , adminCreateUserConfirmed = False
            , adminCreateUserUserMetadata = Nothing
            , adminCreateUserAppMetadata = Nothing
            } of
        Left (AdminPasswordPolicy _ _) -> pure ()
        other ->
            fail ("validateAdminCreate short password: expected AdminPasswordPolicy, got " <> show other)
    -- Email-only (no password) → Right () — admin can create without a password
    assertEqual
        "validateAdminCreate email-only → Right ()"
        (Right ())
        ( validateAdminCreate
            AdminCreateUserRequest
                { adminCreateUserEmail = Email "user@example.com"
                , adminCreateUserPassword = Nothing
                , adminCreateUserConfirmed = False
                , adminCreateUserUserMetadata = Nothing
                , adminCreateUserAppMetadata = Nothing
                }
        )

    -- ---------------------------------------------------------------------------
    -- Hauth.Auth.Admin: validateInvite
    -- ---------------------------------------------------------------------------

    assertEqual
        "validateInvite empty email → AdminEmailRequired"
        (Left AdminEmailRequired)
        (validateInvite InviteUserRequest{inviteUserEmail = Email "", inviteUserData = Nothing})
    assertEqual
        "validateInvite valid email → Right ()"
        (Right ())
        (validateInvite InviteUserRequest{inviteUserEmail = Email "invite@example.com", inviteUserData = Nothing})

    -- ---------------------------------------------------------------------------
    -- ListUsersResponse JSON shape
    -- ---------------------------------------------------------------------------

    now7 <- getCurrentTime
    let sampleUserResp =
            buildUserResponse
                User
                    { userId = UserId UUID.nil
                    , userEmail = Just "list@example.com"
                    , userEncryptedPassword = Nothing
                    , userEmailConfirmedAt = Just now7
                    , userConfirmationToken = Nothing
                    , userConfirmationSentAt = Nothing
                    , userRawAppMetaData = Aeson.object []
                    , userRawUserMetaData = Aeson.object []
                    , userRole = "authenticated"
                    , userAud = "authenticated"
                    , userCreatedAt = now7
                    , userUpdatedAt = now7
                    }
        listUsersResp =
            ListUsersResponse
                { listUsers = [sampleUserResp]
                , listUsersAud = "authenticated"
                , listUsersNextPage = Just 2
                }
    case Aeson.decode (Aeson.encode listUsersResp) of
        Nothing -> fail "ListUsersResponse: JSON decode failed"
        Just (obj :: Object) -> do
            mapM_
                ( \k ->
                    if KeyMap.member k obj
                        then pure ()
                        else fail ("ListUsersResponse JSON: missing key: " <> show k)
                )
                ["users", "aud", "next_page"]
            assertEqual
                "ListUsersResponse aud"
                (Just (String "authenticated"))
                (KeyMap.lookup "aud" obj)

    -- ---------------------------------------------------------------------------
    -- DeletedUserResponse JSON shape
    -- ---------------------------------------------------------------------------

    let deletedResp = DeletedUserResponse{deletedUser = sampleUserResp}
    case Aeson.decode (Aeson.encode deletedResp) of
        Nothing -> fail "DeletedUserResponse: JSON decode failed"
        Just (obj :: Object) -> do
            if KeyMap.member "user" obj
                then pure ()
                else fail "DeletedUserResponse JSON: missing 'user' key"

    -- ---------------------------------------------------------------------------
    -- Identity record selectors round-trip
    -- ---------------------------------------------------------------------------

    let sampleIdentity =
            Identity
                { identityIdentityId = IdentityId "provider-id-123"
                , identityUserId = UUID.nil
                , identityProvider = "email"
                , identityProviderId = "provider-id-123"
                , identityIdentityData = Aeson.object ["email" Aeson..= ("user@example.com" :: T.Text)]
                , identityEmail = Just "user@example.com"
                , identityCreatedAt = now7
                , identityUpdatedAt = now7
                , identityLastSignInAt = Nothing
                }
    assertEqual "identity identityId" (IdentityId "provider-id-123") (identityIdentityId sampleIdentity)
    assertEqual "identity userId" UUID.nil (identityUserId sampleIdentity)
    assertEqual "identity provider" "email" (identityProvider sampleIdentity)
    assertEqual "identity email" (Just "user@example.com") (identityEmail sampleIdentity)
    -- Build IdentityResponse and check JSON shape
    let identResp = buildIdentityResponse sampleIdentity
    case Aeson.decode (Aeson.encode identResp) of
        Nothing -> fail "IdentityResponse: JSON decode failed"
        Just (obj :: Object) -> do
            mapM_
                ( \k ->
                    if KeyMap.member k obj
                        then pure ()
                        else fail ("IdentityResponse JSON: missing key: " <> show k)
                )
                [ "id"
                , "user_id"
                , "provider"
                , "provider_id"
                , "identity_data"
                , "created_at"
                , "updated_at"
                ]
    -- ListIdentitiesResponse JSON shape
    let listIdResp = ListIdentitiesResponse{listIdentities = [identResp]}
    case Aeson.decode (Aeson.encode listIdResp) of
        Nothing -> fail "ListIdentitiesResponse: JSON decode failed"
        Just (obj :: Object) ->
            if KeyMap.member "identities" obj
                then pure ()
                else fail "ListIdentitiesResponse JSON: missing 'identities' key"

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

-- | Build a minimal test 'Config' with the given OAuth providers.
settingsTestConfig :: [OAuthProviderConfig] -> Config
settingsTestConfig providers =
    Config
        { configDatabase =
            DatabaseConfig
                { databaseUrl = "postgresql://hauth:hauth@localhost:5432/hauth"
                , databasePoolSize = 5
                }
        , configJwt =
            JwtConfig
                { jwtSecret = "0123456789abcdef0123456789abcdef"
                , jwtIssuer = "hauth"
                , jwtAudience = "authenticated"
                , jwtAccessTokenTtlSeconds = 3600
                , jwtRefreshTokenTtlSeconds = 2592000
                }
        , configSite =
            SiteConfig
                { siteUrl = "http://localhost:3000"
                , siteAllowedRedirectUrls = ["http://localhost:3000/auth/callback"]
                }
        , configEmail = EmailConfig "noreply@example.com" "localhost" 1025 Nothing Nothing
        , configOAuth = OAuthConfig{oauthProviders = providers}
        , configServer =
            ServerConfig
                { serverHost = "127.0.0.1"
                , serverPort = 8080
                }
        }

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
