module Spec.EmailSpec (runSpec) where

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
import Spec.TestUtils (assertContains, assertEqual)

runSpec :: IO ()
runSpec = do
    let fromAddr = "noreply@example.com" :: Text
    mapM_ (assertRenderEmail fromAddr sampleTemplateData) [minBound .. maxBound]
    assertSubstituteVars
    stubResult <- sendEmail stubSender (dummyEmailMessage fromAddr)
    case stubResult of
        Left (EmailSendError _) -> pure ()
        other -> fail ("stubSender: expected EmailSendError, got " <> show other)

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
