{-# LANGUAGE NumericUnderscores #-}
{-# LANGUAGE TemplateHaskell #-}

module Hauth.Email.TemplateCache (
    Template (..),
    TemplateCache,
    newTemplateCache,
    lookupTemplate,
) where

import Control.Concurrent (forkIO, threadDelay)
import Control.Exception (SomeException, catch, try)
import Control.Monad (void)
import Data.ByteString (ByteString)
import Data.FileEmbed (embedDir)
import Data.IORef (IORef, newIORef, readIORef, writeIORef)
import Data.Map.Strict (Map)
import qualified Data.Map.Strict as Map
import Data.Text (Text)
import qualified Data.Text as T
import qualified Data.Text.Encoding as TE
import Database.PostgreSQL.Simple (Connection, connectPostgreSQL, execute_, query_)
import qualified Database.PostgreSQL.Simple.Notification as N

-- | A fully-loaded email template from the database (or embedded fallback).
data Template = Template
    { templateSubject :: Text
    , templateBodyText :: Text
    , templateBodyHtml :: Text
    }
    deriving stock (Eq, Show)

-- | Opaque in-memory cache backed by an 'IORef'.
newtype TemplateCache = TemplateCache
    { cacheRef :: IORef (Map Text Template)
    }

-- | TH-embedded template files for fallback.
embeddedTemplateFiles :: [(FilePath, ByteString)]
embeddedTemplateFiles = $(embedDir "templates")

lookupEmbedded :: FilePath -> Maybe Text
lookupEmbedded name =
    TE.decodeUtf8 <$> lookup name embeddedTemplateFiles

-- | Build a 'Template' from the embedded files for a given name prefix.
embeddedTemplate :: Text -> Maybe Template
embeddedTemplate name = do
    let prefix = T.unpack name
    subj <- lookupEmbedded (prefix <> ".subject")
    txt <- lookupEmbedded (prefix <> ".txt")
    html <- lookupEmbedded (prefix <> ".html")
    pure
        Template
            { templateSubject = T.dropWhileEnd (== '\n') subj
            , templateBodyText = txt
            , templateBodyHtml = html
            }

{- | Load all rows from auth.email_templates. Returns an empty map if the
table doesn't exist yet (pre-migration deployments / unit-test setups
without a migrated schema). The lookupTemplate fallback then serves
embedded defaults.
-}
loadFromDb :: Connection -> IO (Map Text Template)
loadFromDb conn = do
    result <-
        try @SomeException $
            query_
                conn
                "SELECT name, subject, body_text, body_html \
                \FROM auth.email_templates"
    case result of
        Left _ -> pure Map.empty
        Right rows ->
            pure $
                Map.fromList
                    [ (name, Template{templateSubject = subj, templateBodyText = txt, templateBodyHtml = html})
                    | (name, subj, txt, html) <- rows
                    ]

{- | Create a new 'TemplateCache' backed by the DB, with LISTEN/NOTIFY reload.
Starts a background thread that listens on "email_templates_updated".
Takes the Postgres connection string directly to avoid a circular import with Hauth.Env.

If the initial connection fails (DB unreachable, e.g. operator hasn't
migrated yet, or a unit-test environment with a bogus URL), returns an
empty in-memory cache; lookupTemplate falls back to embedded defaults.
The background reconnect loop will pick up the DB once it comes online.
-}
newTemplateCache :: Text -> IO TemplateCache
newTemplateCache databaseUrl = do
    result <- try @SomeException (connectPostgreSQL (TE.encodeUtf8 databaseUrl))
    ref <- newIORef Map.empty
    let cache = TemplateCache ref
    case result of
        Left _ -> do
            _ <- forkIO (reconnectLoop ref databaseUrl)
            pure cache
        Right conn -> do
            initial <- loadFromDb conn
            writeIORef ref initial
            _ <- forkIO (listenLoop conn ref databaseUrl)
            pure cache

listenLoop :: Connection -> IORef (Map Text Template) -> Text -> IO ()
listenLoop conn ref databaseUrl = do
    result <- try @SomeException (setupListen conn)
    case result of
        Left _ -> reconnectLoop ref databaseUrl
        Right () -> notifyLoop conn ref databaseUrl

setupListen :: Connection -> IO ()
setupListen conn =
    void (execute_ conn "LISTEN email_templates_updated")

notifyLoop :: Connection -> IORef (Map Text Template) -> Text -> IO ()
notifyLoop conn ref databaseUrl = do
    result <- try @SomeException (N.getNotification conn)
    case result of
        Left _ ->
            reconnectLoop ref databaseUrl
        Right _ -> do
            refreshCache conn ref
            notifyLoop conn ref databaseUrl

refreshCache :: Connection -> IORef (Map Text Template) -> IO ()
refreshCache conn ref = do
    result <- try @SomeException (loadFromDb conn)
    case result of
        Left _ -> pure ()
        Right m -> writeIORef ref m

reconnectLoop :: IORef (Map Text Template) -> Text -> IO ()
reconnectLoop ref databaseUrl = do
    threadDelay 1_000_000
    result <- try @SomeException (connectPostgreSQL (TE.encodeUtf8 databaseUrl))
    case result of
        Left _ -> reconnectLoop ref databaseUrl
        Right conn -> do
            _ <-
                (loadFromDb conn >>= writeIORef ref)
                    `catch` (\(_ :: SomeException) -> pure ())
            listenLoop conn ref databaseUrl

{- | Look up a template by name.
Returns the DB row if cached, falls back to embedded, errors for unknown names.
-}
lookupTemplate :: TemplateCache -> Text -> IO Template
lookupTemplate TemplateCache{cacheRef} name = do
    m <- readIORef cacheRef
    case Map.lookup name m of
        Just t -> pure t
        Nothing ->
            case embeddedTemplate name of
                Just t -> pure t
                Nothing ->
                    error
                        ( "lookupTemplate: unknown template name "
                            <> show name
                            <> " (not in DB or embedded bundle)"
                        )
