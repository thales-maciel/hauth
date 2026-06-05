module Spec.Email.SmtpSpec (spec) where

import Control.Concurrent (forkIO, threadDelay)
import Control.Concurrent.MVar (MVar, newEmptyMVar, putMVar, takeMVar)
import Control.Exception (bracket)
import qualified Data.ByteString as BS
import qualified Data.Text as T
import Hauth.Config (
    EmailConfig (..),
 )
import Hauth.Email (
    EmailError (..),
    EmailMessage (..),
    EmailSender (..),
    sendEmail,
 )
import Hauth.Email.Smtp (makeSMTPSender)
import Network.Socket (
    AddrInfo (..),
    Family (..),
    SockAddr (..),
    Socket,
    SocketOption (..),
    SocketType (..),
    accept,
    bind,
    close,
    defaultHints,
    getAddrInfo,
    listen,
    setSocketOption,
    socket,
    socketPort,
 )
import qualified Network.Socket.ByteString as NSB
import Test.Hspec (Spec, describe, it, shouldBe, shouldSatisfy)

spec :: Spec
spec = do
    describe "makeSMTPSender" $ do
        it "returns EmailSendError when the server refuses connection" $ do
            let cfg =
                    EmailConfig
                        { emailFrom = "noreply@example.com"
                        , emailSmtpHost = "127.0.0.1"
                        , emailSmtpPort = 1
                        , emailUsername = Nothing
                        , emailPassword = Nothing
                        }
            let sender = makeSMTPSender cfg
            result <- sendEmail sender dummyMsg
            case result of
                Left (EmailSendError msg) ->
                    msg `shouldSatisfy` (not . T.null)
                Left other -> error ("expected EmailSendError, got " <> show other)
                Right () -> error "expected failure, got success"

        it "delivers a message to a minimal SMTP sink and returns Right ()" $ do
            withSMTPSink \port -> do
                let cfg =
                        EmailConfig
                            { emailFrom = "noreply@example.com"
                            , emailSmtpHost = "127.0.0.1"
                            , emailSmtpPort = port
                            , emailUsername = Nothing
                            , emailPassword = Nothing
                            }
                let sender = makeSMTPSender cfg
                result <- sendEmail sender dummyMsg
                result `shouldBe` Right ()

        it "sends MAIL FROM and RCPT TO matching the message addresses" $ do
            capturedLines <- newEmptyMVar
            withCapturingSink capturedLines \port -> do
                let cfg =
                        EmailConfig
                            { emailFrom = "noreply@example.com"
                            , emailSmtpHost = "127.0.0.1"
                            , emailSmtpPort = port
                            , emailUsername = Nothing
                            , emailPassword = Nothing
                            }
                let sender = makeSMTPSender cfg
                _ <- sendEmail sender dummyMsg
                pure ()
            captured <- takeMVar capturedLines
            captured `shouldSatisfy` any (BS.isInfixOf "MAIL FROM:<sender@example.com>")
            captured `shouldSatisfy` any (BS.isInfixOf "RCPT TO:<recipient@example.com>")

-- | Dummy message used in tests.
dummyMsg :: EmailMessage
dummyMsg =
    EmailMessage
        { emailTo = "recipient@example.com"
        , emailFrom = "sender@example.com"
        , emailSubject = "Test Subject"
        , emailTextBody = "Test body text"
        , emailHtmlBody = Just "<p>Test body html</p>"
        }

-- | Bind a listening socket on a free ephemeral port.
bindFreeSocket :: IO Socket
bindFreeSocket = do
    addrs <-
        getAddrInfo
            (Just defaultHints{addrSocketType = Stream})
            (Just "127.0.0.1")
            (Just "0")
    case addrs of
        [] -> fail "could not resolve 127.0.0.1"
        (addr : _) -> do
            sock <- socket (addrFamily addr) Stream (addrProtocol addr)
            setSocketOption sock ReuseAddr 1
            bind sock (addrAddress addr)
            listen sock 5
            pure sock

getPort :: Socket -> IO Int
getPort sock = do
    name <- socketPort sock
    pure (fromIntegral name)

{- | Spin up a minimal SMTP sink that accepts one connection and responds
positively to every SMTP command.
-}
withSMTPSink :: (Int -> IO a) -> IO a
withSMTPSink action = do
    ready <- newEmptyMVar
    bracket bindFreeSocket close \listenSock -> do
        port <- getPort listenSock
        _ <- forkIO $ do
            putMVar ready ()
            (conn, _) <- accept listenSock
            serveSmtp conn
            close conn
        takeMVar ready
        threadDelay 5000
        action port

-- | Capture SMTP command lines into an MVar for assertion.
withCapturingSink :: MVar [BS.ByteString] -> (Int -> IO a) -> IO a
withCapturingSink capturedLines action = do
    ready <- newEmptyMVar
    bracket bindFreeSocket close \listenSock -> do
        port <- getPort listenSock
        _ <- forkIO $ do
            putMVar ready ()
            (conn, _) <- accept listenSock
            lines' <- captureSmtp conn
            close conn
            putMVar capturedLines lines'
        takeMVar ready
        threadDelay 5000
        action port

-- | Serve a minimal SMTP session that accepts everything.
serveSmtp :: Socket -> IO ()
serveSmtp sock = do
    NSB.sendAll sock "220 localhost SMTP\r\n"
    loop
  where
    loop = do
        line <- recvLine sock
        case BS.take 4 line of
            "QUIT" -> NSB.sendAll sock "221 Bye\r\n"
            "DATA" -> do
                NSB.sendAll sock "354 Start input\r\n"
                drainData sock
                NSB.sendAll sock "250 OK\r\n"
                loop
            _ -> do
                NSB.sendAll sock "250 OK\r\n"
                loop

-- | Capture all received lines from a minimal SMTP session.
captureSmtp :: Socket -> IO [BS.ByteString]
captureSmtp sock = do
    NSB.sendAll sock "220 localhost SMTP\r\n"
    go []
  where
    go acc = do
        line <- recvLine sock
        case BS.take 4 line of
            "QUIT" -> do
                NSB.sendAll sock "221 Bye\r\n"
                pure (reverse acc)
            "DATA" -> do
                NSB.sendAll sock "354 Start input\r\n"
                drainData sock
                NSB.sendAll sock "250 OK\r\n"
                go (line : acc)
            _ -> do
                NSB.sendAll sock "250 OK\r\n"
                go (line : acc)

-- | Drain the DATA section (terminated by a lone dot on its own line).
drainData :: Socket -> IO ()
drainData sock = do
    line <- recvLine sock
    if line == "." || line == ".\r" || line == BS.singleton 46
        then pure ()
        else drainData sock

recvLine :: Socket -> IO BS.ByteString
recvLine sock = go BS.empty
  where
    go acc = do
        chunk <- NSB.recv sock 256
        let acc' = acc <> chunk
        if "\n" `BS.isSuffixOf` acc'
            then pure (BS.dropWhileEnd (\c -> c == 10 || c == 13) acc')
            else go acc'
