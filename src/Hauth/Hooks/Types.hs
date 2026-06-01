module Hauth.Hooks.Types (
    HookPoint (..),
    hookPointName,
    parseHookPoint,
    HookConfig (..),
    loadHookConfig,
) where

import Data.ByteString (ByteString)
import Data.Text (Text)
import qualified Data.Text as T
import Data.UUID (UUID)
import Database.PostgreSQL.Simple (Connection, Only (..), query)
import Database.PostgreSQL.Simple.FromField (FromField (..), ResultError (..), returnError)
import Database.PostgreSQL.Simple.FromRow (FromRow (..), field)

-- | The four synchronous hook points supported by hauth.
data HookPoint
    = HookBeforeUserCreated
    | HookCustomAccessToken
    | HookMfaVerificationAttempt
    | HookPasswordVerificationAttempt
    deriving stock (Eq, Show, Ord, Enum, Bounded)

-- | Canonical text name for a 'HookPoint' as stored in @auth.hooks.hook_point@.
hookPointName :: HookPoint -> Text
hookPointName HookBeforeUserCreated = "before-user-created"
hookPointName HookCustomAccessToken = "custom-access-token"
hookPointName HookMfaVerificationAttempt = "mfa-verification-attempt"
hookPointName HookPasswordVerificationAttempt = "password-verification-attempt"

{- | Parse a 'HookPoint' from its canonical text name. Returns 'Nothing' for
unrecognised values.
-}
parseHookPoint :: Text -> Maybe HookPoint
parseHookPoint t = case t of
    "before-user-created" -> Just HookBeforeUserCreated
    "custom-access-token" -> Just HookCustomAccessToken
    "mfa-verification-attempt" -> Just HookMfaVerificationAttempt
    "password-verification-attempt" -> Just HookPasswordVerificationAttempt
    _ -> Nothing

-- | A persisted, enabled row from @auth.hooks@.
data HookConfig = HookConfig
    { hookConfigId :: UUID
    , hookConfigPoint :: HookPoint
    , hookConfigUrl :: Text
    , hookConfigSecret :: ByteString
    , hookConfigTimeoutMs :: Int
    , hookConfigFailOpen :: Bool
    }
    deriving stock (Eq, Show)

-- ---------------------------------------------------------------------------
-- postgresql-simple instances
-- ---------------------------------------------------------------------------

instance FromField HookPoint where
    fromField f mdata = do
        t <- fromField f mdata
        case parseHookPoint (t :: Text) of
            Just hp -> pure hp
            Nothing ->
                returnError
                    Incompatible
                    f
                    ("unknown hook_point: " <> T.unpack t)

instance FromRow HookConfig where
    fromRow =
        HookConfig
            <$> field
            <*> field
            <*> field
            <*> field
            <*> field
            <*> field

-- ---------------------------------------------------------------------------
-- Database operations
-- ---------------------------------------------------------------------------

{- | Load the enabled hook configuration for the given 'HookPoint', or
'Nothing' if no enabled row exists.
-}
loadHookConfig :: Connection -> HookPoint -> IO (Maybe HookConfig)
loadHookConfig conn hp = do
    rows <-
        query
            conn
            "SELECT id, hook_point, url, secret::bytea, timeout_ms, fail_open \
            \FROM auth.hooks \
            \WHERE hook_point = ? \
            \  AND enabled = true"
            (Only (hookPointName hp))
    pure $ case rows of
        (cfg : _) -> Just cfg
        [] -> Nothing
