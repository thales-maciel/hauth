module Hauth.Session (
    SessionId (..),
    RefreshTokenId (..),
    Session (..),
    RefreshToken (..),
    NewSession (..),
    createSession,
    getSession,
    updateSessionAalFactor,
    getActiveRefreshTokenForSession,
    listUserSessions,
    revokeSession,
    createRefreshToken,
    lookupRefreshToken,
    lookupRefreshTokenRaw,
    lookupRefreshTokenRawForUpdate,
    revokeRefreshToken,
    revokeSessionRefreshTokens,
    touchSessionRefreshedAt,
    generateOpaqueToken,
) where

import qualified Crypto.Random as CR
import qualified Data.ByteString.Base64.URL as B64URL
import Data.Int (Int64)
import Data.Text (Text)
import qualified Data.Text.Encoding as TE
import Data.Time (UTCTime)
import Data.UUID (UUID)
import qualified Data.UUID as UUID
import qualified Data.UUID.V4 as UUID4
import Database.PostgreSQL.Simple (Connection, Only (..), execute, query)
import Database.PostgreSQL.Simple.FromRow (FromRow (..), field)

-- | Wrapper around a session UUID primary key.
newtype SessionId = SessionId {unSessionId :: UUID}
    deriving stock (Eq, Show)

-- | Wrapper around a refresh token bigserial primary key.
newtype RefreshTokenId = RefreshTokenId {unRefreshTokenId :: Int64}
    deriving stock (Eq, Show)

-- | A persisted session row from @auth.sessions@.
data Session = Session
    { sessionId :: SessionId
    , sessionUserId :: UUID
    , sessionCreatedAt :: UTCTime
    , sessionUpdatedAt :: UTCTime
    , sessionFactorId :: Maybe UUID
    , sessionAal :: Text
    , sessionNotAfter :: Maybe UTCTime
    , sessionRefreshedAt :: Maybe UTCTime
    , sessionUserAgent :: Maybe Text
    , sessionIp :: Maybe Text
    }
    deriving stock (Eq, Show)

-- | Values required to create a new session.
data NewSession = NewSession
    { newSessionUserId :: UUID
    , newSessionAal :: Text
    , newSessionFactorId :: Maybe UUID
    , newSessionUserAgent :: Maybe Text
    , newSessionIp :: Maybe Text
    , newSessionNotAfter :: Maybe UTCTime
    }
    deriving stock (Eq, Show)

-- | A persisted refresh token row from @auth.refresh_tokens@.
data RefreshToken = RefreshToken
    { refreshTokenId :: RefreshTokenId
    , refreshTokenToken :: Text
    , refreshTokenSessionId :: SessionId
    , refreshTokenUserId :: UUID
    , refreshTokenParent :: Maybe Text
    , refreshTokenRevoked :: Bool
    , refreshTokenCreatedAt :: UTCTime
    , refreshTokenUpdatedAt :: UTCTime
    }
    deriving stock (Eq, Show)

instance FromRow Session where
    fromRow =
        Session . SessionId
            <$> field
            <*> field
            <*> field
            <*> field
            <*> field
            <*> field
            <*> field
            <*> field
            <*> field
            <*> field

{- | Parse a 'RefreshToken' from a query result.

The @user_id@ column in @auth.refresh_tokens@ is @text@ in the schema
(GoTrue compatibility).  All queries against this table cast it to @uuid@
in SQL so that postgresql-simple can read it directly as 'UUID'.
-}
instance FromRow RefreshToken where
    fromRow =
        RefreshToken . RefreshTokenId
            <$> field
            <*> field
            <*> (SessionId <$> field)
            <*> field
            <*> field
            <*> field
            <*> field
            <*> field

{- | Insert a new session into @auth.sessions@ and return the persisted row.

A fresh UUID is generated via 'Data.UUID.V4.nextRandom' so that the
caller never has to supply one.
-}
createSession :: Connection -> NewSession -> IO Session
createSession conn NewSession{..} = do
    sid <- UUID4.nextRandom
    rows <-
        query
            conn
            "INSERT INTO auth.sessions \
            \  (id, user_id, aal, factor_id, user_agent, ip, not_after) \
            \VALUES \
            \  (?, ?, ?, ?, ?, ?::inet, ?) \
            \RETURNING \
            \  id, user_id, created_at, updated_at, factor_id, aal, \
            \  not_after, refreshed_at, user_agent, ip::text"
            ( sid
            , newSessionUserId
            , newSessionAal
            , newSessionFactorId
            , newSessionUserAgent
            , newSessionIp
            , newSessionNotAfter
            )
    case rows of
        [row] -> pure row
        _ -> fail "createSession: expected exactly one row returned"

-- | Look up a session by its primary key; returns 'Nothing' when absent.
getSession :: Connection -> SessionId -> IO (Maybe Session)
getSession conn (SessionId sid) = do
    rows <-
        query
            conn
            "SELECT \
            \  id, user_id, created_at, updated_at, factor_id, aal, \
            \  not_after, refreshed_at, user_agent, ip::text \
            \FROM auth.sessions \
            \WHERE id = ?"
            (Only sid)
    pure $ case rows of
        [row] -> Just row
        _ -> Nothing

{- | Update the @aal@ and @factor_id@ columns for an existing session.

Also touches @refreshed_at@ and @updated_at@ to @now()@.  Returns the
updated 'Session' row, or 'Nothing' when no row with the given id exists.
-}
updateSessionAalFactor :: Connection -> SessionId -> Text -> Maybe UUID -> IO (Maybe Session)
updateSessionAalFactor conn (SessionId sid) aal mFactorId = do
    rows <-
        query
            conn
            "UPDATE auth.sessions \
            \SET aal = ?, factor_id = ?, refreshed_at = now(), updated_at = now() \
            \WHERE id = ? \
            \RETURNING \
            \  id, user_id, created_at, updated_at, factor_id, aal, \
            \  not_after, refreshed_at, user_agent, ip::text"
            (aal, mFactorId, sid)
    pure $ case rows of
        [row] -> Just row
        _ -> Nothing

{- | Find the most-recent active (non-revoked) refresh token for a session.

Returns 'Nothing' when the session has no active tokens.
-}
getActiveRefreshTokenForSession :: Connection -> SessionId -> IO (Maybe RefreshToken)
getActiveRefreshTokenForSession conn (SessionId sid) = do
    rows <-
        query
            conn
            "SELECT \
            \  id, token, session_id, user_id::uuid, parent, revoked, \
            \  created_at, updated_at \
            \FROM auth.refresh_tokens \
            \WHERE session_id = ? AND revoked = false \
            \ORDER BY created_at DESC \
            \LIMIT 1"
            (Only sid)
    pure $ case rows of
        [row] -> Just row
        _ -> Nothing

-- | List all sessions for a user, newest first.
listUserSessions :: Connection -> UUID -> IO [Session]
listUserSessions conn uid =
    query
        conn
        "SELECT \
        \  id, user_id, created_at, updated_at, factor_id, aal, \
        \  not_after, refreshed_at, user_agent, ip::text \
        \FROM auth.sessions \
        \WHERE user_id = ? \
        \ORDER BY created_at DESC"
        (Only uid)

{- | Delete a session by primary key.

The @ON DELETE CASCADE@ constraint on @auth.refresh_tokens.session_id@
automatically removes all associated refresh tokens.
-}
revokeSession :: Connection -> SessionId -> IO ()
revokeSession conn (SessionId sid) = do
    _ <-
        execute
            conn
            "DELETE FROM auth.sessions WHERE id = ?"
            (Only sid)
    pure ()

{- | Create a new refresh token linked to an existing session.

The opaque token bytes are generated via 'generateOpaqueToken'.  The
@user_id@ is resolved from the session row so callers do not have to
supply it redundantly.  The @user_id@ column in @auth.refresh_tokens@ is
stored as @text@ (GoTrue compatibility).
-}
createRefreshToken :: Connection -> SessionId -> Maybe Text -> IO RefreshToken
createRefreshToken conn (SessionId sidUUID) mParent = do
    token <- generateOpaqueToken
    -- Resolve user_id from the session.
    sessionRows <-
        query
            conn
            "SELECT user_id FROM auth.sessions WHERE id = ?"
            (Only sidUUID)
    userId <- case sessionRows of
        [Only uid] -> pure (uid :: UUID)
        _ -> fail "createRefreshToken: session not found"
    rows <-
        query
            conn
            "INSERT INTO auth.refresh_tokens \
            \  (token, session_id, user_id, parent) \
            \VALUES \
            \  (?, ?, ?, ?) \
            \RETURNING \
            \  id, token, session_id, user_id::uuid, parent, revoked, \
            \  created_at, updated_at"
            (token, sidUUID, UUID.toString userId, mParent)
    case rows of
        [row] -> pure row
        _ -> fail "createRefreshToken: expected exactly one row returned"

-- | Find an active (non-revoked) refresh token by its token string.
lookupRefreshToken :: Connection -> Text -> IO (Maybe RefreshToken)
lookupRefreshToken conn token = do
    rows <-
        query
            conn
            "SELECT \
            \  id, token, session_id, user_id::uuid, parent, revoked, \
            \  created_at, updated_at \
            \FROM auth.refresh_tokens \
            \WHERE token = ? AND revoked = false"
            (Only token)
    pure $ case rows of
        [row] -> Just row
        _ -> Nothing

{- | Look up a refresh token by its token value, returning the row even if
revoked.  Callers are responsible for inspecting 'refreshTokenRevoked' and
deciding how to respond.  Used by the rotation flow for reuse-detection.
-}
lookupRefreshTokenRaw :: Connection -> Text -> IO (Maybe RefreshToken)
lookupRefreshTokenRaw conn token = do
    rows <-
        query
            conn
            "SELECT \
            \  id, token, session_id, user_id::uuid, parent, revoked, \
            \  created_at, updated_at \
            \FROM auth.refresh_tokens \
            \WHERE token = ?"
            (Only token)
    pure $ case rows of
        [row] -> Just row
        _ -> Nothing

{- | Same as 'lookupRefreshTokenRaw' but locks the row with @FOR UPDATE@.

MUST be called inside a transaction; otherwise the lock is released
immediately and the call degenerates to an unlocked read.  Used by the
rotation flow to serialize concurrent refresh requests sharing one token.
-}
lookupRefreshTokenRawForUpdate :: Connection -> Text -> IO (Maybe RefreshToken)
lookupRefreshTokenRawForUpdate conn token = do
    rows <-
        query
            conn
            "SELECT \
            \  id, token, session_id, user_id::uuid, parent, revoked, \
            \  created_at, updated_at \
            \FROM auth.refresh_tokens \
            \WHERE token = ? \
            \FOR UPDATE"
            (Only token)
    pure $ case rows of
        [row] -> Just row
        _ -> Nothing

-- | Mark a refresh token as revoked.
revokeRefreshToken :: Connection -> RefreshTokenId -> IO ()
revokeRefreshToken conn (RefreshTokenId tid) = do
    _ <-
        execute
            conn
            "UPDATE auth.refresh_tokens \
            \SET revoked = true, updated_at = now() \
            \WHERE id = ?"
            (Only tid)
    pure ()

{- | Revoke all refresh tokens belonging to a session.

Used during reuse-detection: when a previously-rotated token is replayed,
every token in the family (all tokens sharing the same @session_id@) is
revoked to prevent any further use.  Returns the number of rows updated.
-}
revokeSessionRefreshTokens :: Connection -> SessionId -> IO Int64
revokeSessionRefreshTokens conn (SessionId sid) =
    execute
        conn
        "UPDATE auth.refresh_tokens \
        \SET revoked = true, updated_at = now() \
        \WHERE session_id = ? AND revoked = false"
        (Only sid)

-- | Update the @refreshed_at@ timestamp for a session to @now()@.
touchSessionRefreshedAt :: Connection -> SessionId -> IO ()
touchSessionRefreshedAt conn (SessionId sid) = do
    _ <-
        execute
            conn
            "UPDATE auth.sessions \
            \SET refreshed_at = now(), updated_at = now() \
            \WHERE id = ?"
            (Only sid)
    pure ()

{- | Generate a cryptographically random opaque token.

Produces 32 random bytes, base64url-encodes them without padding, and
returns the result as 'Text'.  The output is always 43 characters long
(ceil(32 * 8 / 6) = 43 base64url characters with no padding).
-}
generateOpaqueToken :: IO Text
generateOpaqueToken = do
    bytes <- CR.getRandomBytes 32
    pure $ TE.decodeUtf8 (B64URL.encodeUnpadded bytes)
