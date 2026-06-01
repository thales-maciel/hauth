module Hauth.Verify.Smtp (checks) where

import Control.Exception (IOException, try)
import Data.Char (isDigit)
import Data.Text (Text)
import qualified Data.Text as T
import qualified Data.Text.Encoding as TE
import Hauth.Config (Config (..), EmailConfig (..))
import Hauth.Env (AppEnv (..))
import Hauth.Verify.Types (Check (..), CheckOutcome (..))
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
import System.IO.Error (isDoesNotExistError)

checks :: [Check]
checks =
    [ tcpCheck
    , handshakeCheck
    ]

tcpCheck :: Check
tcpCheck =
    Check
        { checkName = "smtp.tcp"
        , checkLabel = "SMTP TCP reachability"
        , checkRun = runTcpCheck
        }

handshakeCheck :: Check
handshakeCheck =
    Check
        { checkName = "smtp.handshake"
        , checkLabel = "SMTP EHLO handshake"
        , checkRun = runHandshakeCheck
        }

runTcpCheck :: AppEnv -> IO CheckOutcome
runTcpCheck AppEnv{appConfig = Config{configEmail}} = do
    let host = T.unpack (emailSmtpHost configEmail)
        port = show (emailSmtpPort configEmail)
        detail = emailSmtpHost configEmail <> ":" <> T.pack port
    result <- try (openSock host port >>= close) :: IO (Either IOException ())
    case result of
        Right () ->
            pure CheckOk
        Left err ->
            pure (CheckFail (classifyError detail err))

runHandshakeCheck :: AppEnv -> IO CheckOutcome
runHandshakeCheck AppEnv{appConfig = Config{configEmail}} = do
    let host = T.unpack (emailSmtpHost configEmail)
        port = show (emailSmtpPort configEmail)
        detail = emailSmtpHost configEmail <> ":" <> T.pack port
    result <- try (doHandshake host port) :: IO (Either IOException CheckOutcome)
    case result of
        Left err ->
            pure (CheckFail (classifyError detail err))
        Right outcome ->
            pure outcome

openSock :: String -> String -> IO Socket
openSock host port = do
    addrs <- getAddrInfo (Just hints) (Just host) (Just port)
    case addrs of
        [] -> ioError (userError "name resolution failed")
        (addr : _) -> do
            sock <- socket (addrFamily addr) Stream (addrProtocol addr)
            connect sock (addrAddress addr)
            pure sock

doHandshake :: String -> String -> IO CheckOutcome
doHandshake host port = do
    sock <- openSock host port
    -- Read SMTP banner (expect 220 ...)
    banner <- recvLine sock
    if not (isSMTPCode banner)
        then do
            close sock
            pure (CheckFail "server did not send a valid SMTP banner")
        else do
            -- Send EHLO
            NSB.sendAll sock (TE.encodeUtf8 "EHLO hauth.verify\r\n")
            response <- recvLine sock
            close sock
            if "250" `isPrefixOf` T.unpack response
                then pure CheckOk
                else pure (CheckFail ("unexpected EHLO response: " <> T.take 80 response))

-- | Read bytes until CRLF, return as Text (strips trailing CR/LF).
recvLine :: Socket -> IO Text
recvLine sock = go ""
  where
    go acc = do
        chunk <- NSB.recv sock 256
        let acc' = acc <> TE.decodeUtf8 chunk
        if "\n" `T.isSuffixOf` acc'
            then pure (T.stripEnd acc')
            else go acc'

hints :: AddrInfo
hints =
    defaultHints
        { addrFlags = [AI_NUMERICSERV]
        , addrSocketType = Stream
        }

classifyError :: Text -> IOException -> Text
classifyError detail err
    | "connection refused" `T.isInfixOf` msg = "connection refused to " <> detail
    | "timed out" `T.isInfixOf` msg = "timed out after 5s connecting to " <> detail
    | "name resolution" `T.isInfixOf` msg || "does not exist" `T.isInfixOf` msg && not ("connection" `T.isInfixOf` msg) = "name resolution failed for " <> detail
    | isDoesNotExistError err && not ("connection" `T.isInfixOf` msg) = "name resolution failed for " <> detail
    | otherwise = "connection failed to " <> detail <> ": " <> T.pack (show err)
  where
    msg = T.toLower (T.pack (show err))

isSMTPCode :: Text -> Bool
isSMTPCode line =
    T.length line >= 3 && T.all isDigit (T.take 3 line)

isPrefixOf :: String -> String -> Bool
isPrefixOf prefix str = take (length prefix) str == prefix
