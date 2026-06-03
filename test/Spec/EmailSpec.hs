module Spec.EmailSpec (spec) where

import Control.Monad (when)
import Data.Text (Text)
import qualified Data.Text as T
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
import Test.Hspec (Spec, describe, expectationFailure, it, shouldBe, shouldSatisfy)

spec :: Spec
spec = do
    let fromAddr = "noreply@example.com" :: Text

    describe "renderEmail" $
        mapM_ (renderEmailTest fromAddr sampleTemplateData) [minBound .. maxBound]

    describe "substituteVars" $
        it "substitutes known placeholders and passes through unknown ones" $ do
            let tdata =
                    TemplateData
                        { templateRecipientEmail = "u@x.com"
                        , templateActionUrl = "https://x.com/action"
                        , templateSiteUrl = "https://x.com"
                        , templateTokenHash = "tok"
                        }
                input = "Hello {{recipient_email}} visit {{action_url}} ref {{token_hash}} unknown {{nope}}"
                result = substituteVars tdata input
            result `shouldSatisfy` T.isInfixOf "u@x.com"
            result `shouldSatisfy` T.isInfixOf "https://x.com/action"
            result `shouldSatisfy` T.isInfixOf "tok"
            result `shouldSatisfy` T.isInfixOf "{{nope}}"

    describe "stubSender" $
        it "returns EmailSendError" $ do
            stubResult <- sendEmail stubSender (dummyEmailMessage fromAddr)
            case stubResult of
                Left (EmailSendError _) -> pure ()
                other -> expectationFailure ("expected EmailSendError, got " <> show other)

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
renderEmailTest :: Text -> TemplateData -> TemplateKind -> Spec
renderEmailTest from tdata kind =
    it ("renders " <> show kind) $
        case renderEmail kind from tdata of
            Left err ->
                expectationFailure ("unexpected error: " <> show err)
            Right msg -> do
                emailTo msg `shouldBe` templateRecipientEmail tdata
                emailFrom msg `shouldBe` from
                assertNonEmptyNoNewline (show kind) (emailSubject msg)
                assertSubstituted (emailTextBody msg) tdata
                case emailHtmlBody msg of
                    Nothing ->
                        expectationFailure (show kind <> ": expected Just htmlBody, got Nothing")
                    Just html ->
                        assertSubstituted html tdata

-- | Assert that a subject is non-empty and contains no newlines.
assertNonEmptyNoNewline :: String -> Text -> IO ()
assertNonEmptyNoNewline label subj = do
    when (T.null subj) $
        expectationFailure (label <> " subject: expected non-empty subject")
    when (T.any (== '\n') subj) $
        expectationFailure (label <> " subject: unexpected newline in subject")

-- | Assert that all four placeholder variables were substituted in a body.
assertSubstituted :: Text -> TemplateData -> IO ()
assertSubstituted body tdata = do
    body `shouldSatisfy` T.isInfixOf (templateRecipientEmail tdata)
    body `shouldSatisfy` T.isInfixOf (templateActionUrl tdata)
    body `shouldSatisfy` T.isInfixOf (templateSiteUrl tdata)
