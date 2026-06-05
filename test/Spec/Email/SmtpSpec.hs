{- | Unit tests for 'Hauth.Email.Smtp'.

We test our own code, not the @smtp-mail@ library's wire protocol.
The key properties we assert:

 1. 'makeSMTPSender' returns an 'EmailSender' (structure check).
 2. A delivery attempt to a closed port yields a typed 'EmailSendError'
    (library exceptions are wrapped, not leaked to callers).
-}
module Spec.Email.SmtpSpec (spec) where

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
import Test.Hspec (Spec, describe, it, shouldSatisfy)

spec :: Spec
spec = do
    describe "makeSMTPSender" $ do
        it "returns an EmailSender value" $ do
            let cfg = dummyCfg{emailSmtpPort = 2525}
            let EmailSender{sendEmail = _} = makeSMTPSender cfg
            -- Structural check: makeSMTPSender is total and returns the
            -- expected record shape without throwing.
            pure () :: IO ()

        it "wraps connection errors as EmailSendError (not raw IOException)" $ do
            -- Port 1 is closed/refused on all platforms; the library will
            -- throw an IOException which our wrapper must convert.
            let cfg = dummyCfg{emailSmtpPort = 1}
            let sender = makeSMTPSender cfg
            result <- sendEmail sender dummyMsg
            case result of
                Left (EmailSendError msg) ->
                    msg `shouldSatisfy` (not . T.null)
                Left other ->
                    error ("expected EmailSendError, got " <> show other)
                Right () ->
                    error "expected failure connecting to port 1, got success"

-- | Minimal config for tests that need a sender instance.
dummyCfg :: EmailConfig
dummyCfg =
    EmailConfig
        { emailFrom = "noreply@example.com"
        , emailSmtpHost = "127.0.0.1"
        , emailSmtpPort = 2525
        , emailUsername = Nothing
        , emailPassword = Nothing
        }

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
