module Spec.Verify.SmtpSpec (spec) where

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
import Test.Hspec (Spec, describe, expectationFailure, it, shouldBe, shouldSatisfy)

spec :: Spec
spec = do
    describe "smtp.tcp" $ do
        it "returns CheckFail when port is not listening" $ do
            let env = mkEnv "127.0.0.1" 1
            outcome <- runCheck "smtp.tcp" env
            case outcome of
                CheckFail msg ->
                    msg `shouldSatisfy` T.isInfixOf "connection refused"
                other ->
                    expectationFailure ("expected CheckFail, got " <> show other)

        it "returns CheckOk when connecting to a listening socket" $
            withListeningSocket $ \port -> do
                let env = mkEnv "127.0.0.1" port
                outcome <- runCheck "smtp.tcp" env
                outcome `shouldBe` CheckOk

    describe "smtp.handshake" $ do
        it "returns CheckFail when port is not listening" $ do
            let env = mkEnv "127.0.0.1" 1
            outcome <- runCheck "smtp.handshake" env
            case outcome of
                CheckFail _ -> pure ()
                other -> expectationFailure ("expected CheckFail for closed port, got " <> show other)

-- | Bind a listening socket on an ephemeral port, run an action with the port number.
withListeningSocket :: (Int -> IO a) -> IO a
withListeningSocket action = do
    addrs <- getAddrInfo (Just listenHints) (Just "127.0.0.1") (Just "0")
    case addrs of
        [] -> fail "could not resolve 127.0.0.1"
        (addr : _) ->
            bracket (socket (addrFamily addr) Stream (addrProtocol addr)) close $ \sock -> do
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
        , appLogger = Logger $ \_level _msg -> pure ()
        , appConnectionPool = error "smtp tests do not use the connection pool"
        , appTemplateCache = error "template cache not used in smtp checks"
        , appBackgroundServiceStatuses = error "background services not used in smtp checks"
        , appHookHttpManager = error "http manager not used in smtp checks"
        , appEmailSender = error "email sender not used in smtp checks"
        }
