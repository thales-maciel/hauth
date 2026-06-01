{-# LANGUAGE TemplateHaskell #-}

module Hauth.Email (
    EmailMessage (..),
    TemplateKind (..),
    TemplateData (..),
    EmailError (..),
    EmailSender (..),
    renderEmail,
    renderEmailCached,
    stubSender,
    substituteVars,
) where

import Data.ByteString (ByteString)
import Data.FileEmbed (embedDir)
import Data.Text (Text)
import qualified Data.Text as T
import qualified Data.Text.Encoding as TE
import Hauth.Email.TemplateCache (Template (..), TemplateCache, lookupTemplate)

-- | A fully-rendered email message ready for delivery.
data EmailMessage = EmailMessage
    { emailTo :: Text
    , emailFrom :: Text
    , emailSubject :: Text
    , emailTextBody :: Text
    , emailHtmlBody :: Maybe Text
    }
    deriving stock (Eq, Show)

-- | The four v0.1 email template kinds.
data TemplateKind
    = Confirmation
    | Recovery
    | Invite
    | EmailChange
    deriving stock (Eq, Show, Enum, Bounded)

-- | Variable bindings used when rendering a template.
data TemplateData = TemplateData
    { templateRecipientEmail :: Text
    , templateActionUrl :: Text
    , templateSiteUrl :: Text
    , templateTokenHash :: Text
    }
    deriving stock (Eq, Show)

-- | Errors that can occur during email rendering or sending.
data EmailError
    = EmailSendError Text
    | EmailTemplateError Text
    deriving stock (Eq, Show)

-- | A pluggable email sender.
newtype EmailSender = EmailSender
    { sendEmail :: EmailMessage -> IO (Either EmailError ())
    }

-- | Embedded template files bundled at compile time.
embeddedTemplates :: [(FilePath, ByteString)]
embeddedTemplates = $(embedDir "templates")

-- | Look up an embedded template by filename.
lookupEmbeddedTemplate :: FilePath -> Either EmailError Text
lookupEmbeddedTemplate name =
    case lookup name embeddedTemplates of
        Nothing ->
            Left (EmailTemplateError ("missing embedded template: " <> T.pack name))
        Just bytes ->
            Right (TE.decodeUtf8 bytes)

-- | Map a 'TemplateKind' to its filename prefix.
kindPrefix :: TemplateKind -> String
kindPrefix Confirmation = "confirmation"
kindPrefix Recovery = "recovery"
kindPrefix Invite = "invite"
kindPrefix EmailChange = "email_change"

{- | Replace all known @{{var}}@ placeholders in a text.
Unknown placeholders are left as-is.
-}
substituteVars :: TemplateData -> Text -> Text
substituteVars TemplateData{..} t =
    foldr
        (\(placeholder, value) acc -> T.replace placeholder value acc)
        t
        [ ("{{recipient_email}}", templateRecipientEmail)
        , ("{{action_url}}", templateActionUrl)
        , ("{{site_url}}", templateSiteUrl)
        , ("{{token_hash}}", templateTokenHash)
        ]

{- | Render a template into an 'EmailMessage'.

Returns 'Left' 'EmailTemplateError' only if a template file is missing from
the embedded bundle (a build-time bug). The subject is stripped of a
trailing newline; a subject containing internal newlines is an error.
-}
renderEmail ::
    TemplateKind ->
    -- | Sender address (typically @EmailConfig.emailFrom@)
    Text ->
    TemplateData ->
    Either EmailError EmailMessage
renderEmail kind from tdata = do
    let prefix = kindPrefix kind
    rawSubject <- lookupEmbeddedTemplate (prefix <> ".subject")
    rawTxt <- lookupEmbeddedTemplate (prefix <> ".txt")
    rawHtml <- lookupEmbeddedTemplate (prefix <> ".html")
    let subst = substituteVars tdata
        subject0 = subst rawSubject
        -- Strip a single trailing newline added by text editors
        subject1 = T.dropWhileEnd (== '\n') subject0
    if T.any (== '\n') subject1
        then Left (EmailTemplateError "subject contains newline")
        else
            Right
                EmailMessage
                    { emailTo = templateRecipientEmail tdata
                    , emailFrom = from
                    , emailSubject = subject1
                    , emailTextBody = subst rawTxt
                    , emailHtmlBody = Just (subst rawHtml)
                    }

{- | A stub sender that always fails with 'EmailSendError'.
Used as the default until real SMTP delivery is wired.
-}
stubSender :: EmailSender
stubSender =
    EmailSender
        { sendEmail = \_msg ->
            pure (Left (EmailSendError "smtp not wired"))
        }

{- | Render an email via the 'TemplateCache', falling back to embedded templates
when no DB row exists for the given kind.
-}
renderEmailCached ::
    TemplateCache ->
    TemplateKind ->
    -- | Sender address
    Text ->
    TemplateData ->
    IO (Either EmailError EmailMessage)
renderEmailCached cache kind from tdata = do
    let name = kindPrefix kind
    t <- lookupTemplate cache (T.pack name)
    let subst = substituteVars tdata
        subject0 = subst (templateSubject t)
    if T.any (== '\n') subject0
        then pure (Left (EmailTemplateError "subject contains newline"))
        else
            pure $
                Right
                    EmailMessage
                        { emailTo = templateRecipientEmail tdata
                        , emailFrom = from
                        , emailSubject = subject0
                        , emailTextBody = subst (templateBodyText t)
                        , emailHtmlBody = Just (subst (templateBodyHtml t))
                        }
