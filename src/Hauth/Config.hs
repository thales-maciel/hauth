module Hauth.Config (
    Config (..),
    ConfigError (..),
    ConfigFieldError (..),
    DatabaseConfig (..),
    EmailConfig (..),
    JwtConfig (..),
    OAuthConfig (..),
    OAuthProviderConfig (..),
    ServerConfig (..),
    SiteConfig (..),
    decodeConfigBytes,
    formatConfigError,
    loadConfig,
) where

import Control.Exception (IOException, try)
import Data.Aeson (FromJSON (parseJSON), eitherDecodeStrict', withObject, (.:?))
import qualified Data.ByteString as BS
import Data.List (intercalate)
import Data.Text (Text)
import qualified Data.Text as T

data Config = Config
    { configDatabase :: DatabaseConfig
    , configJwt :: JwtConfig
    , configSite :: SiteConfig
    , configEmail :: EmailConfig
    , configOAuth :: OAuthConfig
    , configServer :: ServerConfig
    }
    deriving stock (Eq, Show)

data DatabaseConfig = DatabaseConfig
    { databaseUrl :: Text
    , databasePoolSize :: Int
    }
    deriving stock (Eq, Show)

data JwtConfig = JwtConfig
    { jwtSecret :: Text
    , jwtIssuer :: Text
    , jwtAudience :: Text
    , jwtAccessTokenTtlSeconds :: Int
    , jwtRefreshTokenTtlSeconds :: Int
    }
    deriving stock (Eq, Show)

data SiteConfig = SiteConfig
    { siteUrl :: Text
    , siteAllowedRedirectUrls :: [Text]
    }
    deriving stock (Eq, Show)

data EmailConfig = EmailConfig
    { emailFrom :: Text
    , emailSmtpHost :: Text
    , emailSmtpPort :: Int
    , emailUsername :: Maybe Text
    , emailPassword :: Maybe Text
    }
    deriving stock (Eq, Show)

newtype OAuthConfig = OAuthConfig
    { oauthProviders :: [OAuthProviderConfig]
    }
    deriving stock (Eq, Show)

data OAuthProviderConfig = OAuthProviderConfig
    { oauthProviderName :: Text
    , oauthProviderClientId :: Text
    , oauthProviderClientSecret :: Text
    , oauthProviderDiscoveryUrl :: Text
    }
    deriving stock (Eq, Show)

data ServerConfig = ServerConfig
    { serverHost :: Text
    , serverPort :: Int
    }
    deriving stock (Eq, Show)

data ConfigFieldError = ConfigFieldError
    { configFieldPath :: String
    , configFieldMessage :: String
    }
    deriving stock (Eq, Show)

data ConfigError
    = ConfigReadError FilePath String
    | ConfigParseError FilePath String
    | ConfigValidationError FilePath [ConfigFieldError]
    deriving stock (Eq, Show)

data RawConfig = RawConfig
    { rawConfigDatabase :: Maybe RawDatabaseConfig
    , rawConfigJwt :: Maybe RawJwtConfig
    , rawConfigSite :: Maybe RawSiteConfig
    , rawConfigEmail :: Maybe RawEmailConfig
    , rawConfigOAuth :: Maybe RawOAuthConfig
    , rawConfigServer :: Maybe RawServerConfig
    }
    deriving stock (Eq, Show)

instance FromJSON RawConfig where
    parseJSON =
        withObject "Config" \object ->
            RawConfig
                <$> object .:? "database"
                <*> object .:? "jwt"
                <*> object .:? "site"
                <*> object .:? "email"
                <*> object .:? "oauth"
                <*> object .:? "server"

data RawDatabaseConfig = RawDatabaseConfig
    { rawDatabaseUrl :: Maybe Text
    , rawDatabasePoolSize :: Maybe Int
    }
    deriving stock (Eq, Show)

instance FromJSON RawDatabaseConfig where
    parseJSON =
        withObject "DatabaseConfig" \object ->
            RawDatabaseConfig
                <$> object .:? "url"
                <*> object .:? "pool_size"

data RawJwtConfig = RawJwtConfig
    { rawJwtSecret :: Maybe Text
    , rawJwtIssuer :: Maybe Text
    , rawJwtAudience :: Maybe Text
    , rawJwtAccessTokenTtlSeconds :: Maybe Int
    , rawJwtRefreshTokenTtlSeconds :: Maybe Int
    }
    deriving stock (Eq, Show)

instance FromJSON RawJwtConfig where
    parseJSON =
        withObject "JwtConfig" \object ->
            RawJwtConfig
                <$> object .:? "secret"
                <*> object .:? "issuer"
                <*> object .:? "audience"
                <*> object .:? "access_token_ttl_seconds"
                <*> object .:? "refresh_token_ttl_seconds"

data RawSiteConfig = RawSiteConfig
    { rawSiteUrl :: Maybe Text
    , rawSiteAllowedRedirectUrls :: Maybe [Text]
    }
    deriving stock (Eq, Show)

instance FromJSON RawSiteConfig where
    parseJSON =
        withObject "SiteConfig" \object ->
            RawSiteConfig
                <$> object .:? "url"
                <*> object .:? "allowed_redirect_urls"

data RawEmailConfig = RawEmailConfig
    { rawEmailFrom :: Maybe Text
    , rawEmailSmtpHost :: Maybe Text
    , rawEmailSmtpPort :: Maybe Int
    , rawEmailUsername :: Maybe Text
    , rawEmailPassword :: Maybe Text
    }
    deriving stock (Eq, Show)

instance FromJSON RawEmailConfig where
    parseJSON =
        withObject "EmailConfig" \object ->
            RawEmailConfig
                <$> object .:? "from"
                <*> object .:? "smtp_host"
                <*> object .:? "smtp_port"
                <*> object .:? "username"
                <*> object .:? "password"

newtype RawOAuthConfig = RawOAuthConfig
    { rawOAuthProviders :: Maybe [RawOAuthProviderConfig]
    }
    deriving stock (Eq, Show)

instance FromJSON RawOAuthConfig where
    parseJSON =
        withObject "OAuthConfig" \object ->
            RawOAuthConfig
                <$> object .:? "providers"

data RawOAuthProviderConfig = RawOAuthProviderConfig
    { rawOAuthProviderName :: Maybe Text
    , rawOAuthProviderClientId :: Maybe Text
    , rawOAuthProviderClientSecret :: Maybe Text
    , rawOAuthProviderDiscoveryUrl :: Maybe Text
    }
    deriving stock (Eq, Show)

instance FromJSON RawOAuthProviderConfig where
    parseJSON =
        withObject "OAuthProviderConfig" \object ->
            RawOAuthProviderConfig
                <$> object .:? "name"
                <*> object .:? "client_id"
                <*> object .:? "client_secret"
                <*> object .:? "discovery_url"

data RawServerConfig = RawServerConfig
    { rawServerHost :: Maybe Text
    , rawServerPort :: Maybe Int
    }
    deriving stock (Eq, Show)

instance FromJSON RawServerConfig where
    parseJSON =
        withObject "ServerConfig" \object ->
            RawServerConfig
                <$> object .:? "host"
                <*> object .:? "port"

data Checked a = Checked
    { checkedErrors :: [ConfigFieldError]
    , checkedValue :: Maybe a
    }
    deriving stock (Eq, Show)

loadConfig :: FilePath -> IO (Either ConfigError Config)
loadConfig path = do
    result <- try (BS.readFile path)
    pure case result of
        Left (err :: IOException) ->
            Left (ConfigReadError path (show err))
        Right bytes ->
            decodeConfigBytes path bytes

decodeConfigBytes :: FilePath -> BS.ByteString -> Either ConfigError Config
decodeConfigBytes path bytes =
    case eitherDecodeStrict' bytes of
        Left message ->
            Left (ConfigParseError path message)
        Right rawConfig ->
            case validateRawConfig rawConfig of
                Left errors ->
                    Left (ConfigValidationError path errors)
                Right config ->
                    Right config

formatConfigError :: ConfigError -> String
formatConfigError = \case
    ConfigReadError path message ->
        "Could not read config " <> path <> ": " <> message
    ConfigParseError path message ->
        "Could not parse config " <> path <> ": " <> message
    ConfigValidationError path errors ->
        intercalate
            "\n"
            ( ("Invalid config " <> path <> ":")
                : fmap formatConfigFieldError errors
            )

formatConfigFieldError :: ConfigFieldError -> String
formatConfigFieldError ConfigFieldError{configFieldPath, configFieldMessage} =
    "  - " <> configFieldPath <> ": " <> configFieldMessage

validateRawConfig :: RawConfig -> Either [ConfigFieldError] Config
validateRawConfig RawConfig{..} =
    let database = validateSection "database" rawConfigDatabase validateDatabase
        jwt = validateSection "jwt" rawConfigJwt validateJwt
        site = validateSection "site" rawConfigSite validateSite
        email = validateSection "email" rawConfigEmail validateEmail
        oauth = validateSection "oauth" rawConfigOAuth validateOAuth
        server = validateSection "server" rawConfigServer validateServer
        errors =
            concatMap
                checkedErrors
                [ hideValue database
                , hideValue jwt
                , hideValue site
                , hideValue email
                , hideValue oauth
                , hideValue server
                ]
     in case ( checkedValue database
             , checkedValue jwt
             , checkedValue site
             , checkedValue email
             , checkedValue oauth
             , checkedValue server
             ) of
            (Just databaseConfig, Just jwtConfig, Just siteConfig, Just emailConfig, Just oauthConfig, Just serverConfig) ->
                Right
                    Config
                        { configDatabase = databaseConfig
                        , configJwt = jwtConfig
                        , configSite = siteConfig
                        , configEmail = emailConfig
                        , configOAuth = oauthConfig
                        , configServer = serverConfig
                        }
            _ ->
                Left errors

hideValue :: Checked a -> Checked ()
hideValue Checked{checkedErrors} =
    Checked checkedErrors (Just ())

validateSection :: String -> Maybe raw -> (raw -> Checked value) -> Checked value
validateSection path rawConfig validator =
    case rawConfig of
        Nothing ->
            invalid path "is required"
        Just value ->
            validator value

validateDatabase :: RawDatabaseConfig -> Checked DatabaseConfig
validateDatabase RawDatabaseConfig{..} =
    let url = requiredPostgresUrl "database.url" rawDatabaseUrl
        poolSize = requiredPositiveInt "database.pool_size" rawDatabasePoolSize
     in Checked
            (checkedErrors url <> checkedErrors poolSize)
            (DatabaseConfig <$> checkedValue url <*> checkedValue poolSize)

validateJwt :: RawJwtConfig -> Checked JwtConfig
validateJwt RawJwtConfig{..} =
    let secret = requiredMinText 32 "jwt.secret" rawJwtSecret
        issuer = requiredText "jwt.issuer" rawJwtIssuer
        audience = requiredText "jwt.audience" rawJwtAudience
        accessTokenTtl = requiredPositiveInt "jwt.access_token_ttl_seconds" rawJwtAccessTokenTtlSeconds
        refreshTokenTtl = requiredPositiveInt "jwt.refresh_token_ttl_seconds" rawJwtRefreshTokenTtlSeconds
     in Checked
            ( concatMap
                checkedErrors
                [ hideValue secret
                , hideValue issuer
                , hideValue audience
                , hideValue accessTokenTtl
                , hideValue refreshTokenTtl
                ]
            )
            ( JwtConfig
                <$> checkedValue secret
                <*> checkedValue issuer
                <*> checkedValue audience
                <*> checkedValue accessTokenTtl
                <*> checkedValue refreshTokenTtl
            )

validateSite :: RawSiteConfig -> Checked SiteConfig
validateSite RawSiteConfig{..} =
    let url = requiredHttpUrl "site.url" rawSiteUrl
        redirects = requiredHttpUrlList "site.allowed_redirect_urls" rawSiteAllowedRedirectUrls
     in Checked
            (checkedErrors url <> checkedErrors redirects)
            (SiteConfig <$> checkedValue url <*> checkedValue redirects)

validateEmail :: RawEmailConfig -> Checked EmailConfig
validateEmail RawEmailConfig{..} =
    let fromAddress = requiredEmail "email.from" rawEmailFrom
        smtpHost = requiredText "email.smtp_host" rawEmailSmtpHost
        smtpPort = requiredPort "email.smtp_port" rawEmailSmtpPort
        username = optionalText "email.username" rawEmailUsername
        password = optionalText "email.password" rawEmailPassword
     in Checked
            ( concatMap
                checkedErrors
                [ hideValue fromAddress
                , hideValue smtpHost
                , hideValue smtpPort
                , hideValue username
                , hideValue password
                ]
            )
            ( EmailConfig
                <$> checkedValue fromAddress
                <*> checkedValue smtpHost
                <*> checkedValue smtpPort
                <*> checkedValue username
                <*> checkedValue password
            )

validateOAuth :: RawOAuthConfig -> Checked OAuthConfig
validateOAuth RawOAuthConfig{rawOAuthProviders} =
    case rawOAuthProviders of
        Nothing ->
            invalid "oauth.providers" "is required"
        Just providers ->
            let checkedProviders =
                    zipWith validateOAuthProvider [0 :: Int ..] providers
                errors = concatMap checkedErrors checkedProviders
                values = traverse checkedValue checkedProviders
             in Checked errors (OAuthConfig <$> values)

validateOAuthProvider :: Int -> RawOAuthProviderConfig -> Checked OAuthProviderConfig
validateOAuthProvider index RawOAuthProviderConfig{..} =
    let fieldPath field = "oauth.providers[" <> show index <> "]." <> field
        name = requiredText (fieldPath "name") rawOAuthProviderName
        clientId = requiredText (fieldPath "client_id") rawOAuthProviderClientId
        clientSecret = requiredText (fieldPath "client_secret") rawOAuthProviderClientSecret
        discoveryUrl = requiredHttpUrl (fieldPath "discovery_url") rawOAuthProviderDiscoveryUrl
     in Checked
            ( concatMap
                checkedErrors
                [ hideValue name
                , hideValue clientId
                , hideValue clientSecret
                , hideValue discoveryUrl
                ]
            )
            ( OAuthProviderConfig
                <$> checkedValue name
                <*> checkedValue clientId
                <*> checkedValue clientSecret
                <*> checkedValue discoveryUrl
            )

validateServer :: RawServerConfig -> Checked ServerConfig
validateServer RawServerConfig{..} =
    let host = requiredText "server.host" rawServerHost
        port = requiredPort "server.port" rawServerPort
     in Checked
            (checkedErrors host <> checkedErrors port)
            (ServerConfig <$> checkedValue host <*> checkedValue port)

requiredText :: String -> Maybe Text -> Checked Text
requiredText path value =
    case fmap T.strip value of
        Nothing ->
            invalid path "is required"
        Just text
            | T.null text ->
                invalid path "must not be empty"
            | otherwise ->
                valid text

requiredMinText :: Int -> String -> Maybe Text -> Checked Text
requiredMinText minimumLength path value =
    case requiredText path value of
        Checked errors Nothing ->
            Checked errors Nothing
        Checked _ (Just text)
            | T.length text < minimumLength ->
                invalid path ("must be at least " <> show minimumLength <> " characters")
            | otherwise ->
                valid text

optionalText :: String -> Maybe Text -> Checked (Maybe Text)
optionalText path value =
    case fmap T.strip value of
        Nothing ->
            valid Nothing
        Just text
            | T.null text ->
                invalid path "must not be empty when set"
            | otherwise ->
                valid (Just text)

requiredPositiveInt :: String -> Maybe Int -> Checked Int
requiredPositiveInt path value =
    case value of
        Nothing ->
            invalid path "is required"
        Just number
            | number <= 0 ->
                invalid path "must be greater than 0"
            | otherwise ->
                valid number

requiredPort :: String -> Maybe Int -> Checked Int
requiredPort path value =
    case value of
        Nothing ->
            invalid path "is required"
        Just port
            | port < 1 || port > 65535 ->
                invalid path "must be between 1 and 65535"
            | otherwise ->
                valid port

requiredPostgresUrl :: String -> Maybe Text -> Checked Text
requiredPostgresUrl path =
    requireScheme path ["postgres://", "postgresql://"]

requiredHttpUrl :: String -> Maybe Text -> Checked Text
requiredHttpUrl path =
    requireScheme path ["http://", "https://"]

requiredHttpUrlList :: String -> Maybe [Text] -> Checked [Text]
requiredHttpUrlList path value =
    case value of
        Nothing ->
            invalid path "is required"
        Just urls ->
            let checkedUrls =
                    zipWith
                        ( \index url ->
                            requiredHttpUrl (path <> "[" <> show index <> "]") (Just url)
                        )
                        [0 :: Int ..]
                        urls
             in Checked (concatMap checkedErrors checkedUrls) (traverse checkedValue checkedUrls)

requiredEmail :: String -> Maybe Text -> Checked Text
requiredEmail path value =
    case requiredText path value of
        Checked errors Nothing ->
            Checked errors Nothing
        Checked _ (Just text)
            | isEmailLike text ->
                valid text
            | otherwise ->
                invalid path "must be an email address"

requireScheme :: String -> [Text] -> Maybe Text -> Checked Text
requireScheme path schemes value =
    case requiredText path value of
        Checked errors Nothing ->
            Checked errors Nothing
        Checked _ (Just text)
            | any (`T.isPrefixOf` text) schemes ->
                valid text
            | otherwise ->
                invalid path ("must start with " <> intercalate " or " (fmap T.unpack schemes))

isEmailLike :: Text -> Bool
isEmailLike value =
    case T.splitOn "@" value of
        [localPart, domain]
            | not (T.null localPart) && not (T.null domain) ->
                True
        _ ->
            False

valid :: a -> Checked a
valid value =
    Checked [] (Just value)

invalid :: String -> String -> Checked a
invalid path message =
    Checked [ConfigFieldError path message] Nothing
