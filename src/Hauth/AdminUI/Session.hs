{- | Admin UI browser sessions: opaque cookie tokens backed by
@auth.admin_ui_sessions@. Deliberately separate from @auth.sessions@ —
admin UI sessions are not user-linked and never carry a JWT.

Tokens are random 256-bit values handed to the browser; the database only
stores their SHA-256 digest, so a leaked table cannot mint valid cookies.
-}
module Hauth.AdminUI.Session (
    AdminUISessionRow (..),
    adminSessionCookieName,
    buildSessionCookie,
    clearSessionCookie,
    createAdminUISession,
    deleteAdminUISession,
    deleteExpiredAdminUISessions,
    hashSessionToken,
    lookupAdminUISession,
    lookupSessionCookie,
    newSessionToken,
) where

import Crypto.Hash (Digest, SHA256, hash)
import Crypto.Random (getRandomBytes)
import Data.ByteArray.Encoding (Base (Base64URLUnpadded), convertToBase)
import Data.ByteString (ByteString)
import qualified Data.ByteString.Char8 as BSC
import Data.Text (Text)
import qualified Data.Text as T
import qualified Data.Text.Encoding as TE
import Data.Time (UTCTime)
import Database.PostgreSQL.Simple (Connection, Only (Only), execute, execute_, query)
import Database.PostgreSQL.Simple.FromRow (FromRow (fromRow), field)

data AdminUISessionRow = AdminUISessionRow
    { adminUISessionTokenHash :: Text
    , adminUISessionUsername :: Text
    , adminUISessionExpiresAt :: UTCTime
    }
    deriving stock (Eq, Show)

instance FromRow AdminUISessionRow where
    fromRow =
        AdminUISessionRow
            <$> field
            <*> field
            <*> field

adminSessionCookieName :: Text
adminSessionCookieName = "hauth_admin_session"

-- | Fresh random session token: 32 bytes, base64url without padding.
newSessionToken :: IO Text
newSessionToken = do
    bytes <- getRandomBytes 32 :: IO ByteString
    pure (TE.decodeUtf8 (convertToBase Base64URLUnpadded bytes))

-- | SHA-256 hex digest of the cookie token; this is what the DB stores.
hashSessionToken :: Text -> Text
hashSessionToken token =
    T.pack (show (hash (TE.encodeUtf8 token) :: Digest SHA256))

{- | Render the @Set-Cookie@ value for a fresh session. HttpOnly, Secure,
SameSite=Lax per #206. @Path=/admin/ui@ (no trailing slash) is deliberate:
it must cover @GET /admin/ui@ itself, at the cost of RFC 6265 prefix
matching also sending the cookie to a hypothetical @/admin/uifoo@ — no
such route exists and none is planned.
-}
buildSessionCookie :: Text -> Int -> Text
buildSessionCookie token ttlSeconds =
    adminSessionCookieName
        <> "="
        <> token
        <> "; Path=/admin/ui; Max-Age="
        <> T.pack (show ttlSeconds)
        <> "; HttpOnly; Secure; SameSite=Lax"

-- | Render the @Set-Cookie@ value that expires the session cookie now.
clearSessionCookie :: Text
clearSessionCookie =
    adminSessionCookieName
        <> "=; Path=/admin/ui; Max-Age=0; HttpOnly; Secure; SameSite=Lax"

{- | Extract the admin session token from a raw @Cookie@ header value.
Returns the first non-empty @hauth_admin_session@ pair.
-}
lookupSessionCookie :: ByteString -> Maybe Text
lookupSessionCookie raw =
    lookupFirst (fmap pair (BSC.split ';' raw))
  where
    pair chunk =
        let (name, rest) = BSC.break (== '=') (BSC.dropWhile (== ' ') chunk)
         in (TE.decodeUtf8 name, TE.decodeUtf8 (BSC.drop 1 rest))
    lookupFirst pairs =
        case [v | (n, v) <- pairs, n == adminSessionCookieName, not (T.null v)] of
            (v : _) -> Just v
            [] -> Nothing

createAdminUISession :: Connection -> Text -> Text -> Int -> IO ()
createAdminUISession conn tokenHash username ttlSeconds = do
    _ <-
        execute
            conn
            "INSERT INTO auth.admin_ui_sessions (token_hash, username, expires_at) \
            \VALUES (?, ?, now() + make_interval(secs => ?))"
            (tokenHash, username, ttlSeconds)
    pure ()

-- | Look up an unexpired session by token digest.
lookupAdminUISession :: Connection -> Text -> IO (Maybe AdminUISessionRow)
lookupAdminUISession conn tokenHash = do
    rows <-
        query
            conn
            "SELECT token_hash, username, expires_at \
            \FROM auth.admin_ui_sessions \
            \WHERE token_hash = ? AND expires_at > now()"
            (Only tokenHash)
    pure case rows of
        (row : _) -> Just row
        [] -> Nothing

deleteAdminUISession :: Connection -> Text -> IO ()
deleteAdminUISession conn tokenHash = do
    _ <-
        execute
            conn
            "DELETE FROM auth.admin_ui_sessions WHERE token_hash = ?"
            (Only tokenHash)
    pure ()

-- | Opportunistic sweep run on each successful login.
deleteExpiredAdminUISessions :: Connection -> IO ()
deleteExpiredAdminUISessions conn = do
    _ <- execute_ conn "DELETE FROM auth.admin_ui_sessions WHERE expires_at <= now()"
    pure ()
