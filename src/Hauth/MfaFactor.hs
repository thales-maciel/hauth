module Hauth.MfaFactor (
    MfaFactorId (..),
    MfaFactor (..),
    NewMfaFactor (..),
    FactorStatus (..),
    FactorType (..),
    createFactor,
    listFactorsForUser,
    getFactor,
    updateFactorStatus,
) where

import Data.Text (Text)
import qualified Data.Text as T
import Data.Time (UTCTime)
import Data.UUID (UUID)
import Database.PostgreSQL.Simple (Connection, Only (..), execute, query)
import Database.PostgreSQL.Simple.FromField (FromField (..), ResultError (..), returnError)
import Database.PostgreSQL.Simple.FromRow (FromRow (..), field)
import Database.PostgreSQL.Simple.ToField (ToField (..))

-- | Wrapper around a factor UUID primary key.
newtype MfaFactorId = MfaFactorId {unMfaFactorId :: UUID}
    deriving stock (Eq, Show)

-- | Factor type. v0.1 supports TOTP only.
data FactorType = FactorTypeTotp
    deriving stock (Eq, Show)

-- | Factor status.
data FactorStatus
    = FactorUnverified
    | FactorVerified
    deriving stock (Eq, Show)

-- | A persisted row from @auth.mfa_factors@.
data MfaFactor = MfaFactor
    { mfaFactorId :: MfaFactorId
    , mfaFactorUserId :: UUID
    , mfaFactorFriendlyName :: Maybe Text
    , mfaFactorType :: FactorType
    , mfaFactorStatus :: FactorStatus
    , mfaFactorSecret :: Text
    -- ^ BASE32-encoded secret as stored in DB.
    , mfaFactorCreatedAt :: UTCTime
    , mfaFactorUpdatedAt :: UTCTime
    }
    deriving stock (Eq, Show)

-- | Values required to insert a new factor.
data NewMfaFactor = NewMfaFactor
    { newMfaFactorUserId :: UUID
    , newMfaFactorFriendlyName :: Maybe Text
    , newMfaFactorType :: FactorType
    , newMfaFactorSecret :: Text
    -- ^ BASE32-encoded secret.
    }
    deriving stock (Eq, Show)

-- ---------------------------------------------------------------------------
-- postgresql-simple instances
-- ---------------------------------------------------------------------------

instance FromField FactorType where
    fromField f mdata = do
        t <- fromField f mdata
        case (t :: Text) of
            "totp" -> pure FactorTypeTotp
            other -> returnError Incompatible f ("unknown factor_type: " <> T.unpack other)

instance FromField FactorStatus where
    fromField f mdata = do
        t <- fromField f mdata
        case (t :: Text) of
            "unverified" -> pure FactorUnverified
            "verified" -> pure FactorVerified
            other -> returnError Incompatible f ("unknown factor status: " <> T.unpack other)

instance ToField FactorType where
    toField FactorTypeTotp = toField ("totp" :: Text)

instance ToField FactorStatus where
    toField FactorUnverified = toField ("unverified" :: Text)
    toField FactorVerified = toField ("verified" :: Text)

instance FromRow MfaFactor where
    fromRow =
        MfaFactor . MfaFactorId
            <$> field
            <*> field
            <*> field
            <*> field
            <*> field
            <*> field
            <*> field
            <*> field

-- ---------------------------------------------------------------------------
-- Database operations
-- ---------------------------------------------------------------------------

-- | Insert a new factor with status @unverified@, returning the persisted row.
createFactor :: Connection -> NewMfaFactor -> IO MfaFactor
createFactor conn NewMfaFactor{..} = do
    rows <-
        query
            conn
            "INSERT INTO auth.mfa_factors \
            \    (user_id, friendly_name, factor_type, status, secret) \
            \VALUES \
            \    (?, ?, ?, 'unverified', ?) \
            \RETURNING id, user_id, friendly_name, factor_type, status, secret, \
            \          created_at, updated_at"
            ( newMfaFactorUserId
            , newMfaFactorFriendlyName
            , newMfaFactorType
            , newMfaFactorSecret
            )
    case rows of
        (f : _) -> pure f
        [] -> fail "createFactor: INSERT returned no rows"

-- | List all factors for a user, ordered by creation time.
listFactorsForUser :: Connection -> UUID -> IO [MfaFactor]
listFactorsForUser conn uid =
    query
        conn
        "SELECT id, user_id, friendly_name, factor_type, status, secret, \
        \       created_at, updated_at \
        \FROM auth.mfa_factors \
        \WHERE user_id = ? \
        \ORDER BY created_at"
        (Only uid)

-- | Look up a single factor by its primary key.
getFactor :: Connection -> MfaFactorId -> IO (Maybe MfaFactor)
getFactor conn (MfaFactorId fid) = do
    rows <-
        query
            conn
            "SELECT id, user_id, friendly_name, factor_type, status, secret, \
            \       created_at, updated_at \
            \FROM auth.mfa_factors \
            \WHERE id = ?"
            (Only fid)
    pure $ case rows of
        (f : _) -> Just f
        [] -> Nothing

-- | Update the status of an existing factor (used by challenge\/verify, issue #25).
updateFactorStatus :: Connection -> MfaFactorId -> FactorStatus -> IO ()
updateFactorStatus conn (MfaFactorId fid) status = do
    _ <-
        execute
            conn
            "UPDATE auth.mfa_factors \
            \SET status = ?, updated_at = now() \
            \WHERE id = ?"
            (status, fid)
    pure ()
