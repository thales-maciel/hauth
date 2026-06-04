{- | Wire types for the admin email-templates surface: list, get, put, and
the legacy provider-style list/put pair retained for older clients.
-}
module Hauth.API.Types.EmailTemplates (
    EmailTemplateCrudRequest (..),
    EmailTemplateRow (..),
    EmailTemplatesListResponse (..),
    EmailTemplatesResponse (..),
    UpdateEmailTemplatesRequest (..),
) where

import Data.Aeson (FromJSON (..), ToJSON (toJSON), object, (.=))
import qualified Data.Aeson as Aeson
import Data.Text (Text)
import Data.Time (UTCTime)
import GHC.Generics (Generic)

-- | Request body for PUT /admin/email-templates/{name}.
data EmailTemplateCrudRequest = EmailTemplateCrudRequest
    { emailTemplateCrudSubject :: Text
    , emailTemplateCrudBodyText :: Text
    , emailTemplateCrudBodyHtml :: Text
    }
    deriving stock (Eq, Generic, Show)

instance FromJSON EmailTemplateCrudRequest where
    parseJSON = Aeson.withObject "EmailTemplateCrudRequest" \o ->
        EmailTemplateCrudRequest
            <$> o Aeson..: "subject"
            <*> o Aeson..: "body_text"
            <*> o Aeson..: "body_html"

instance ToJSON EmailTemplateCrudRequest where
    toJSON EmailTemplateCrudRequest{emailTemplateCrudSubject, emailTemplateCrudBodyText, emailTemplateCrudBodyHtml} =
        object
            [ "subject" .= emailTemplateCrudSubject
            , "body_text" .= emailTemplateCrudBodyText
            , "body_html" .= emailTemplateCrudBodyHtml
            ]

-- | A single email template row, returned by GET and PUT.
data EmailTemplateRow = EmailTemplateRow
    { emailTemplateRowName :: Text
    , emailTemplateRowSubject :: Text
    , emailTemplateRowBodyText :: Text
    , emailTemplateRowBodyHtml :: Text
    , emailTemplateRowUpdatedAt :: UTCTime
    }
    deriving stock (Eq, Generic, Show)

instance ToJSON EmailTemplateRow where
    toJSON EmailTemplateRow{..} =
        object
            [ "name" .= emailTemplateRowName
            , "subject" .= emailTemplateRowSubject
            , "body_text" .= emailTemplateRowBodyText
            , "body_html" .= emailTemplateRowBodyHtml
            , "updated_at" .= emailTemplateRowUpdatedAt
            ]

instance FromJSON EmailTemplateRow where
    parseJSON = Aeson.withObject "EmailTemplateRow" \o ->
        EmailTemplateRow
            <$> o Aeson..: "name"
            <*> o Aeson..: "subject"
            <*> o Aeson..: "body_text"
            <*> o Aeson..: "body_html"
            <*> o Aeson..: "updated_at"

-- | Response body for GET /admin/email-templates.
newtype EmailTemplatesListResponse = EmailTemplatesListResponse
    { emailTemplatesList :: [EmailTemplateRow]
    }
    deriving stock (Eq, Generic, Show)

instance ToJSON EmailTemplatesListResponse where
    toJSON EmailTemplatesListResponse{emailTemplatesList} =
        object ["templates" .= emailTemplatesList]

instance FromJSON EmailTemplatesListResponse where
    parseJSON = Aeson.withObject "EmailTemplatesListResponse" \o ->
        EmailTemplatesListResponse <$> o Aeson..: "templates"

newtype EmailTemplatesResponse = EmailTemplatesResponse
    { emailTemplates :: [Text]
    }
    deriving stock (Eq, Generic, Show)

instance FromJSON EmailTemplatesResponse where
    parseJSON = Aeson.withObject "EmailTemplatesResponse" \o ->
        EmailTemplatesResponse <$> o Aeson..: "templates"

instance ToJSON EmailTemplatesResponse where
    toJSON EmailTemplatesResponse{emailTemplates} =
        object ["templates" .= emailTemplates]

newtype UpdateEmailTemplatesRequest = UpdateEmailTemplatesRequest
    { updateEmailTemplates :: [Text]
    }
    deriving stock (Eq, Generic, Show)

instance FromJSON UpdateEmailTemplatesRequest where
    parseJSON = Aeson.withObject "UpdateEmailTemplatesRequest" \o ->
        UpdateEmailTemplatesRequest <$> o Aeson..: "templates"

instance ToJSON UpdateEmailTemplatesRequest where
    toJSON UpdateEmailTemplatesRequest{updateEmailTemplates} =
        object ["templates" .= updateEmailTemplates]
