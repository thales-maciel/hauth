module Hauth.Server.EmailTemplates (
    listEmailTemplatesHandler,
    getEmailTemplateHandler,
    putEmailTemplateHandler,
    deleteEmailTemplateHandler,
) where

import Control.Monad (unless)
import Control.Monad.Except (throwError)
import Control.Monad.IO.Class (liftIO)
import Control.Monad.Reader (ReaderT, ask)
import qualified Data.Aeson as Aeson
import qualified Data.Text as T
import Data.Time.Clock (UTCTime, getCurrentTime)
import Database.PostgreSQL.Simple (execute, query, query_)
import Hauth.API.Auth (ServiceRolePrincipal)
import Hauth.API.Types (
    EmailTemplateCrudRequest (..),
    EmailTemplateRow (..),
    EmailTemplatesListResponse (..),
 )
import Hauth.Email.Templates (isKnownTemplate)
import Hauth.Env (AppEnv, withDatabaseConnection)
import Servant.Server (Handler, ServerError (errBody), err400, err404)

type AppHandler = ReaderT AppEnv Handler

listEmailTemplatesHandler :: ServiceRolePrincipal -> AppHandler EmailTemplatesListResponse
listEmailTemplatesHandler _ = do
    env <- ask
    rows <- liftIO $ withDatabaseConnection env \conn ->
        query_
            conn
            "SELECT name, subject, body_text, body_html, updated_at \
            \FROM auth.email_templates \
            \ORDER BY name"
    pure EmailTemplatesListResponse{emailTemplatesList = fmap rowToRecord rows}

getEmailTemplateHandler :: ServiceRolePrincipal -> T.Text -> AppHandler EmailTemplateRow
getEmailTemplateHandler _ name = do
    env <- ask
    rows <- liftIO $ withDatabaseConnection env \conn ->
        query
            conn
            "SELECT name, subject, body_text, body_html, updated_at \
            \FROM auth.email_templates \
            \WHERE name = ?"
            (pure name :: [T.Text])
    case rows of
        [] ->
            throwError
                err404
                    { errBody =
                        Aeson.encode $
                            Aeson.object
                                ["error" Aeson..= ("template_not_found" :: T.Text)]
                    }
        (r : _) -> pure (rowToRecord r)

putEmailTemplateHandler :: ServiceRolePrincipal -> T.Text -> EmailTemplateCrudRequest -> AppHandler EmailTemplateRow
putEmailTemplateHandler _ name req = do
    unless (isKnownTemplate name) $
        throwError
            err400
                { errBody =
                    Aeson.encode $
                        Aeson.object
                            [ "error" Aeson..= ("unknown_template" :: T.Text)
                            , "msg" Aeson..= ("Template name is not in the allowed set" :: T.Text)
                            ]
                }
    now <- liftIO getCurrentTime
    env <- ask
    rows <- liftIO $ withDatabaseConnection env \conn -> do
        _ <-
            execute
                conn
                "INSERT INTO auth.email_templates (name, subject, body_text, body_html, updated_at) \
                \VALUES (?, ?, ?, ?, ?) \
                \ON CONFLICT (name) DO UPDATE \
                \SET subject = EXCLUDED.subject, \
                \    body_text = EXCLUDED.body_text, \
                \    body_html = EXCLUDED.body_html, \
                \    updated_at = EXCLUDED.updated_at"
                ( name
                , emailTemplateCrudSubject req
                , emailTemplateCrudBodyText req
                , emailTemplateCrudBodyHtml req
                , now
                )
        query
            conn
            "SELECT name, subject, body_text, body_html, updated_at \
            \FROM auth.email_templates \
            \WHERE name = ?"
            (pure name :: [T.Text])
    case rows of
        [] ->
            throwError
                err404
                    { errBody =
                        Aeson.encode $
                            Aeson.object
                                ["error" Aeson..= ("template_not_found" :: T.Text)]
                    }
        (r : _) -> pure (rowToRecord r)

deleteEmailTemplateHandler :: ServiceRolePrincipal -> T.Text -> AppHandler ()
deleteEmailTemplateHandler _ name = do
    env <- ask
    _ <- liftIO $ withDatabaseConnection env \conn ->
        execute
            conn
            "DELETE FROM auth.email_templates WHERE name = ?"
            (pure name :: [T.Text])
    pure ()

rowToRecord :: (T.Text, T.Text, T.Text, T.Text, UTCTime) -> EmailTemplateRow
rowToRecord (n, subj, bodyTxt, bodyHtml, updatedAt) =
    EmailTemplateRow
        { emailTemplateRowName = n
        , emailTemplateRowSubject = subj
        , emailTemplateRowBodyText = bodyTxt
        , emailTemplateRowBodyHtml = bodyHtml
        , emailTemplateRowUpdatedAt = updatedAt
        }
