module Spec.Verify.SmtpSpec (runSpec) where

import Control.Exception (bracket)
import Data.Text (Text)
import qualified Data.Text as T
import Hauth.Config (
    Config (..),
    DatabaseConfig (..),
    EmailConfig (..),
    JwtConfig (..),
    OAuthConfig (..),
    ServerConfig (..),
    SiteConfig (..),
 )
import Hauth.Env (AppEnv (..), Logger (..))
import Hauth.Verify (Check (..), CheckOutcome (..))
import Hauth.Verify.Smtp (checks)
import Network.Socket (
    AddrInfo (..),
    SockAddr (..),
    Socket,
    SocketOption (..),
    SocketType (..),
    bind,
    close,
    defaultHints,
    getAddrInfo,
    getSocketName,
    listen,
    setSocketOption,
    socket,
 )
import Spec.TestUtils (assertEqual)

runSpec :: IO ()
runSpec = do
    testTcpRefused
    testTcpConnects
    testHandshakeConnects

-- | TCP check against a port that is not listening should return CheckFail.
testTcpRefused :: IO ()
testTcpRefused = do
    let env = mkEnv "127.0.0.1" 1
    outcome <- runCheck "smtp.tcp" env
    case outcome of
        CheckFail msg ->
            assertContainsText "refused msg" "connection refused" msg
        other ->
            fail ("testTcpRefused: expected CheckFail, got " <> show other)

-- | TCP check against a listening socket should return CheckOk.
testTcpConnects :: IO ()
testTcpConnects = do
    withListeningSocket \port -> do
        let env = mkEnv "127.0.0.1" port
        outcome <- runCheck "smtp.tcp" env
        assertEqual "tcp connects" CheckOk outcome

-- | Handshake check against a port that is not listening should return CheckFail.
testHandshakeConnects :: IO ()
testHandshakeConnects = do
    let env = mkEnv "127.0.0.1" 1
    outcome <- runCheck "smtp.handshake" env
    case outcome of
        CheckFail _ -> pure ()
        other -> fail ("testHandshakeConnects: expected CheckFail for closed port, got " <> show other)

-- | Bind a listening socket on an ephemeral port, run an action with the port number.
withListeningSocket :: (Int -> IO a) -> IO a
withListeningSocket action = do
    addrs <- getAddrInfo (Just listenHints) (Just "127.0.0.1") (Just "0")
    case addrs of
        [] -> fail "could not resolve 127.0.0.1"
        (addr : _) ->
            bracket (socket (addrFamily addr) Stream (addrProtocol addr)) close \sock -> do
                setSocketOption sock ReuseAddr 1
                bind sock (addrAddress addr)
                listen sock 5
                port <- getPort sock
                action port
  where
    listenHints =
        defaultHints{addrSocketType = Stream}

getPort :: Socket -> IO Int
getPort sock = do
    name <- getSocketName sock
    case name of
        SockAddrInet port _ ->
            pure (fromIntegral port)
        _ ->
            fail "unexpected address family"

-- | Find the check by name and run it against the given env.
runCheck :: Text -> AppEnv -> IO CheckOutcome
runCheck name env =
    case filter (\c -> checkName c == name) checks of
        [] -> fail ("no check named " <> T.unpack name)
        (c : _) -> checkRun c env

assertContainsText :: String -> Text -> Text -> IO ()
assertContainsText label needle haystack =
    if T.isInfixOf needle haystack
        then pure ()
        else
            fail
                ( label
                    <> ": expected "
                    <> show needle
                    <> " in "
                    <> show haystack
                )

-- | Build a minimal AppEnv pointing at the given SMTP host/port.
mkEnv :: Text -> Int -> AppEnv
mkEnv smtpHost smtpPort =
    AppEnv
        { appConfig =
            Config
                { configDatabase =
                    DatabaseConfig
                        { databaseUrl = "postgresql://hauth:hauth@localhost:5432/hauth"
                        , databasePoolSize = 1
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
                        , siteAllowedRedirectUrls = []
                        }
                , configEmail =
                    EmailConfig
                        { emailFrom = "noreply@example.com"
                        , emailSmtpHost = smtpHost
                        , emailSmtpPort = smtpPort
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
        , appLogger = Logger \_level _msg -> pure ()
        , appConnectionPool = error "smtp tests do not use the connection pool"
        , appTemplateCache = error "template cache not used in smtp checks"
        , appEnvWebhookWorker = Nothing
        }
