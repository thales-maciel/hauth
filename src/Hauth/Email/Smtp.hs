{- | Real SMTP email delivery backed by the @smtp-mail@ library.

Using @smtp-mail@ instead of a hand-rolled raw-socket implementation
eliminates an entire class of wire-protocol correctness bugs:
dot-stuffing, CRLF normalisation, RFC 2047 encoded-word subjects,
multipart MIME boundaries, and socket lifecycle are all handled by the
library.  STARTTLS is used automatically when credentials are supplied
(port 587 / LOGIN flow); unauthenticated plain-text delivery is used
otherwise.
-}
module Hauth.Email.Smtp (
    makeSMTPSender,
) where

import Control.Exception (SomeException, try)
import qualified Data.Text as T
import qualified Data.Text.Lazy as TL
import Hauth.Config (EmailConfig (EmailConfig, emailFrom, emailPassword, emailSmtpHost, emailSmtpPort, emailUsername))
import Hauth.Email (EmailError (..), EmailMessage (..), EmailSender (..))
import Network.Mail.Mime (Address (..), htmlPart, plainPart)
import Network.Mail.SMTP (
    sendMail',
    sendMailWithLoginSTARTTLS',
    simpleMail,
 )
import Network.Socket (PortNumber)

{- | Build an 'EmailSender' backed by the given 'EmailConfig'.

* When both @emailUsername@ and @emailPassword@ are set, uses
  @sendMailWithLoginSTARTTLS'@ (SMTP with AUTH LOGIN over STARTTLS,
  port as configured — typically 587).
* Otherwise uses plain @sendMail'@ (unauthenticated, for local relays
  such as MailHog).

Any 'IOException' thrown by @smtp-mail@ is caught and re-raised as an
'EmailSendError' so callers never need to handle library-specific exceptions.
-}
makeSMTPSender :: EmailConfig -> EmailSender
makeSMTPSender cfg =
    EmailSender
        { sendEmail = \msg -> do
            result <- try (deliver cfg msg) :: IO (Either SomeException ())
            pure $ case result of
                Left err -> Left (EmailSendError (T.pack (show err)))
                Right () -> Right ()
        }

-- | Perform full SMTP delivery of one message using @smtp-mail@.
deliver :: EmailConfig -> EmailMessage -> IO ()
deliver EmailConfig{emailSmtpHost, emailSmtpPort, emailUsername, emailPassword, emailFrom = cfgFrom} msg = do
    let host = T.unpack emailSmtpHost
        port = fromIntegral emailSmtpPort :: PortNumber
        fromAddr = Address Nothing cfgFrom
        toAddr = Address Nothing (emailTo msg)
        subject = emailSubject msg
        parts = case emailHtmlBody msg of
            Nothing ->
                [plainPart (TL.fromStrict (emailTextBody msg))]
            Just html ->
                [ plainPart (TL.fromStrict (emailTextBody msg))
                , htmlPart (TL.fromStrict html)
                ]
        mail = simpleMail fromAddr [toAddr] [] [] subject parts
    case (emailUsername, emailPassword) of
        (Just user, Just pass) ->
            sendMailWithLoginSTARTTLS' host port (T.unpack user) (T.unpack pass) mail
        _ ->
            sendMail' host port mail
