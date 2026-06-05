-- | Real SMTP email delivery using plain TCP with optional LOGIN auth.
module Hauth.Email.Smtp (
    makeSMTPSender,
) where

import Control.Exception (IOException, try)
import Control.Monad (when)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Base64 as B64
import Data.List (intercalate)
import qualified Data.Text as T
import qualified Data.Text.Encoding as TE
import Hauth.Config (EmailConfig (EmailConfig, emailPassword, emailSmtpHost, emailSmtpPort, emailUsername))
import Hauth.Email (EmailError (..), EmailMessage (..), EmailSender (..))
import Network.Socket (
    AddrInfo (..),
    AddrInfoFlag (..),
    Socket,
    SocketType (..),
    close,
    connect,
    defaultHints,
    getAddrInfo,
    socket,
 )
import qualified Network.Socket.ByteString as NSB

-- | Build an 'EmailSender' backed by the given 'EmailConfig'.
makeSMTPSender :: EmailConfig -> EmailSender
makeSMTPSender cfg =
    EmailSender
        { sendEmail = \msg -> do
            result <- try (deliver cfg msg) :: IO (Either IOException ())
            pure $ case result of
                Left err -> Left (EmailSendError (T.pack (show err)))
                Right () -> Right ()
        }

-- | Open a TCP connection to the SMTP host:port.
openSock :: String -> Int -> IO Socket
openSock host port = do
    let hints =
            defaultHints
                { addrFlags = [AI_NUMERICSERV]
                , addrSocketType = Stream
                }
    addrs <- getAddrInfo (Just hints) (Just host) (Just (show port))
    case addrs of
        [] -> ioError (userError ("SMTP: name resolution failed for " <> host))
        (addr : _) -> do
            sock <- socket (addrFamily addr) Stream (addrProtocol addr)
            connect sock (addrAddress addr)
            pure sock

-- | Read an SMTP response line (up to first CRLF).
recvLine :: Socket -> IO BS.ByteString
recvLine sock = go BS.empty
  where
    go acc = do
        chunk <- NSB.recv sock 512
        let acc' = acc <> chunk
        if "\n" `BS.isSuffixOf` acc'
            then pure (BS.dropWhileEnd (\c -> c == 10 || c == 13) acc')
            else go acc'

-- | Send a line terminated with CRLF.
sendLine :: Socket -> BS.ByteString -> IO ()
sendLine sock line = NSB.sendAll sock (line <> "\r\n")

-- | Read a response; fail if the code is not the expected one.
expectCode :: Socket -> Int -> IO ()
expectCode sock expected = do
    line <- recvLine sock
    let code = BS.take 3 line
    if code == TE.encodeUtf8 (T.pack (show expected))
        then pure ()
        else
            ioError
                ( userError
                    ( "SMTP: expected "
                        <> show expected
                        <> ", got: "
                        <> T.unpack (TE.decodeUtf8 line)
                    )
                )

-- | Read lines until one with a space after the code (final line per RFC 5321).
drainMultiLine :: Socket -> IO ()
drainMultiLine sock = do
    line <- recvLine sock
    -- Multi-line responses have code + '-'; single-line has code + ' ' or nothing
    when (BS.length line > 3 && BS.index line 3 == fromIntegral (fromEnum '-')) $
        drainMultiLine sock

base64Enc :: BS.ByteString -> BS.ByteString
base64Enc = B64.encode

-- | Perform full SMTP delivery of one message.
deliver :: EmailConfig -> EmailMessage -> IO ()
deliver EmailConfig{emailSmtpHost, emailSmtpPort, emailUsername, emailPassword} msg = do
    let host = T.unpack emailSmtpHost
        port = emailSmtpPort
        msgFrom = emailFrom msg
        msgTo = emailTo msg
    sock <- openSock host port
    -- Banner
    expectCode sock 220
    -- EHLO
    sendLine sock "EHLO hauth.mailer"
    drainMultiLine sock
    -- AUTH LOGIN when credentials are set
    case (emailUsername, emailPassword) of
        (Just user, Just pass) -> do
            sendLine sock "AUTH LOGIN"
            expectCode sock 334
            sendLine sock (base64Enc (TE.encodeUtf8 user))
            expectCode sock 334
            sendLine sock (base64Enc (TE.encodeUtf8 pass))
            expectCode sock 235
        _ -> pure ()
    -- Envelope
    sendLine sock ("MAIL FROM:<" <> TE.encodeUtf8 msgFrom <> ">")
    expectCode sock 250
    sendLine sock ("RCPT TO:<" <> TE.encodeUtf8 msgTo <> ">")
    expectCode sock 250
    sendLine sock "DATA"
    expectCode sock 354
    -- Headers + body
    let payload = buildMimePayload msg
    NSB.sendAll sock payload
    -- End of data
    sendLine sock "."
    expectCode sock 250
    sendLine sock "QUIT"
    _ <- recvLine sock
    close sock

-- | Build a minimal RFC 5321/5322 MIME payload.
buildMimePayload :: EmailMessage -> BS.ByteString
buildMimePayload msg =
    let from = emailFrom msg
        to = emailTo msg
        subj = emailSubject msg
        txt = emailTextBody msg
        mHtml = emailHtmlBody msg
     in case mHtml of
            Nothing ->
                TE.encodeUtf8 $
                    T.unlines
                        [ "From: " <> from
                        , "To: " <> to
                        , "Subject: " <> subj
                        , "MIME-Version: 1.0"
                        , "Content-Type: text/plain; charset=UTF-8"
                        , "Content-Transfer-Encoding: 8bit"
                        , ""
                        , txt
                        ]
            Just html ->
                let boundary = "hauth-boundary-abc123def456"
                    parts =
                        T.pack $
                            intercalate
                                "\r\n"
                                [ "--" <> boundary
                                , "Content-Type: text/plain; charset=UTF-8"
                                , "Content-Transfer-Encoding: 8bit"
                                , ""
                                , T.unpack txt
                                , "--" <> boundary
                                , "Content-Type: text/html; charset=UTF-8"
                                , "Content-Transfer-Encoding: 8bit"
                                , ""
                                , T.unpack html
                                , "--" <> boundary <> "--"
                                ]
                 in TE.encodeUtf8 $
                        T.unlines
                            [ "From: " <> from
                            , "To: " <> to
                            , "Subject: " <> subj
                            , "MIME-Version: 1.0"
                            , "Content-Type: multipart/alternative; boundary=\"" <> T.pack boundary <> "\""
                            , ""
                            , parts
                            ]
