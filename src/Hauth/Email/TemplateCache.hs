{-# LANGUAGE NumericUnderscores #-}
{-# LANGUAGE TemplateHaskell #-}

{- | Email template cache.

Construction is split into two pieces so callers can build a usable cache
during 'AppEnv' setup (cheap, no DB I/O, embedded-only fallback) and start the
DB-backed LISTEN/NOTIFY listener after migrations have run:

* 'newTemplateCache' — pure data structure; 'lookupTemplate' against this
  always succeeds via the embedded fallback.
* 'startTemplateCacheListener' — opens a dedicated Postgres connection, loads
  rows from @auth.email_templates@, and spawns a managed thread that reloads
  on @email_templates_updated@ NOTIFY. Returns an opaque handle whose
  lifetime is bounded by 'stopTemplateCacheListener'.

This separation removes the eager-startup coupling that previously forced
@createAppEnv@ to tolerate an un-migrated schema.
-}
module Hauth.Email.TemplateCache (
    Template (..),
    TemplateCache,
    TemplateCacheListener,
    newTemplateCache,
    startTemplateCacheListener,
    stopTemplateCacheListener,
    lookupTemplate,
) where

import Control.Concurrent (threadDelay)
import Control.Concurrent.Async (Async, async, cancel)
import Control.Exception (
    SomeAsyncException,
    SomeException,
    bracket_,
    fromException,
    throwIO,
    try,
 )
import Control.Monad (void)
import Data.ByteString (ByteString)
import Data.FileEmbed (embedDir)
import Data.IORef (IORef, newIORef, readIORef, writeIORef)
import Data.Map.Strict (Map)
import qualified Data.Map.Strict as Map
import Data.Text (Text)
import qualified Data.Text as T
import qualified Data.Text.Encoding as TE
import Database.PostgreSQL.Simple (Connection, close, connectPostgreSQL, execute_, query_)
import qualified Database.PostgreSQL.Simple.Notification as N

-- | A fully-loaded email template from the database (or embedded fallback).
data Template = Template
    { templateSubject :: Text
    , templateBodyText :: Text
    , templateBodyHtml :: Text
    }
    deriving stock (Eq, Show)

{- | Read-side cache: an in-memory map updated by a background listener (when
one is running). 'lookupTemplate' against an empty map falls back to the
TH-embedded template bundle, so a cache without a listener is still usable
— it just never picks up DB overrides.
-}
newtype TemplateCache = TemplateCache
    { cacheRef :: IORef (Map Text Template)
    }

{- | Handle for the DB-backed listener thread + its dedicated Postgres
connection. Created by 'startTemplateCacheListener'; must be released by
'stopTemplateCacheListener' — neither the thread nor the connection are
GC-rooted from anywhere else.
-}
data TemplateCacheListener = TemplateCacheListener
    { listenerThread :: Async ()
    , listenerConnRef :: IORef (Maybe Connection)
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
table doesn't exist yet (pre-migration deployments / test setups without a
migrated schema). The 'lookupTemplate' fallback then serves embedded defaults.
-}
loadFromDb :: Connection -> IO (Map Text Template)
loadFromDb conn = do
    result <-
        tryNoAsync $
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

{- | Create an empty 'TemplateCache'. Pure construction — no I/O beyond
allocating an 'IORef'. Lookups against the returned cache will always fall
through to the embedded template bundle until 'startTemplateCacheListener'
populates the map from the DB.
-}
newTemplateCache :: IO TemplateCache
newTemplateCache = TemplateCache <$> newIORef Map.empty

{- | Open a Postgres connection, load the initial template rows, and spawn a
managed background thread that reloads on @email_templates_updated@ NOTIFY.

Tolerates an unreachable DB at startup (operator hasn't migrated yet; tests
without a Postgres harness): the cache stays empty, lookups fall back to
embedded, and the managed reconnect loop picks up the DB when it comes online.

The returned handle must be released by 'stopTemplateCacheListener'.
-}
startTemplateCacheListener :: Text -> TemplateCache -> IO TemplateCacheListener
startTemplateCacheListener url TemplateCache{cacheRef = ref} = do
    connRef <- newIORef Nothing
    initial <- tryNoAsync (connectPostgreSQL (TE.encodeUtf8 url))
    t <- case initial of
        Right conn -> do
            writeIORef connRef (Just conn)
            loadInto ref conn
            async (loopWithConn ref connRef url conn)
        Left _ ->
            async (reconnect ref connRef url)
    pure
        TemplateCacheListener
            { listenerThread = t
            , listenerConnRef = connRef
            }

{- | Cancel the listener thread and close its dedicated connection. Idempotent.
Must be called when the owning 'AppEnv' is shut down — otherwise the listener
thread + Postgres session leak.
-}
stopTemplateCacheListener :: TemplateCacheListener -> IO ()
stopTemplateCacheListener TemplateCacheListener{listenerThread, listenerConnRef} = do
    cancel listenerThread
    -- bracket_ inside loopWithConn closes the conn on cancel-induced exit and
    -- writes Nothing to listenerConnRef; the lookup below is defence-in-depth
    -- for the narrow window between connect-success and bracket entry.
    mConn <- readIORef listenerConnRef
    case mConn of
        Just c -> do
            _ <- tryNoAsync (close c)
            writeIORef listenerConnRef Nothing
        Nothing -> pure ()

loadInto :: IORef (Map Text Template) -> Connection -> IO ()
loadInto ref conn = do
    r <- tryNoAsync (loadFromDb conn)
    case r of
        Left _ -> pure ()
        Right m -> writeIORef ref m

loopWithConn ::
    IORef (Map Text Template) ->
    IORef (Maybe Connection) ->
    Text ->
    Connection ->
    IO ()
loopWithConn ref connRef url conn = do
    bracket_
        (writeIORef connRef (Just conn))
        ( do
            _ <- tryNoAsync (close conn)
            writeIORef connRef Nothing
        )
        ( do
            r <- tryNoAsync (setupListen conn)
            case r of
                Left _ -> pure ()
                Right () -> notifyLoop ref conn
        )
    -- Connection is closed; loop into reconnect.
    reconnect ref connRef url

notifyLoop :: IORef (Map Text Template) -> Connection -> IO ()
notifyLoop ref conn = do
    -- getNotification blocks; an async exception (cancel) interrupts it and
    -- propagates up through bracket_ to release the connection.
    r <- tryNoAsync (N.getNotification conn)
    case r of
        Left _ -> pure () -- connection error → outer bracket closes, then reconnect
        Right _ -> do
            loadInto ref conn
            notifyLoop ref conn

reconnect ::
    IORef (Map Text Template) ->
    IORef (Maybe Connection) ->
    Text ->
    IO ()
reconnect ref connRef url = do
    threadDelay 1_000_000
    r <- tryNoAsync (connectPostgreSQL (TE.encodeUtf8 url))
    case r of
        Left _ -> reconnect ref connRef url
        Right c -> do
            loadInto ref c
            loopWithConn ref connRef url c

setupListen :: Connection -> IO ()
setupListen conn =
    void (execute_ conn "LISTEN email_templates_updated")

{- | 'try' that catches synchronous exceptions only — async exceptions (e.g.
'AsyncCancelled' from 'cancel') re-raise so the managed thread terminates
cleanly. Without this, 'try @SomeException' would silently swallow the
cancellation signal and the loop would never exit.
-}
tryNoAsync :: IO a -> IO (Either SomeException a)
tryNoAsync action =
    try action >>= \case
        Right x -> pure (Right x)
        Left e
            | Just (_ :: SomeAsyncException) <- fromException e -> throwIO e
            | otherwise -> pure (Left e)

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
