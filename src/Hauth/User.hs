module Hauth.User (
    UserId (..),
    User (..),
    NewUser (..),
    UserUpdate (..),
    SignupError (..),
    applyUserUpdate,
    createUser,
    emptyUserUpdate,
    generateConfirmationToken,
    getUserByConfirmationToken,
    getUserByEmail,
    getUserById,
    markEmailConfirmed,
    setConfirmationToken,
    validateSignupEmail,
    validateSignupPassword,
) where

import qualified Crypto.Random as CR
import Data.Aeson (Value)
import qualified Data.ByteString.Base64.URL as B64URL
import qualified Data.ByteString.Char8 as BSC
import Data.List (intercalate)
import Data.Maybe (catMaybes)
import Data.Text (Text)
import qualified Data.Text as T
import qualified Data.Text.Encoding as TE
import Data.Time (UTCTime)
import Data.UUID (UUID)
import qualified Data.UUID.V4 as UUID4
import Database.PostgreSQL.Simple (Connection, Only (..), query)
import Database.PostgreSQL.Simple.FromRow (FromRow (..), field)
import Database.PostgreSQL.Simple.ToField (Action, ToField (..))
import Database.PostgreSQL.Simple.ToRow (ToRow (..))
import Database.PostgreSQL.Simple.Types (Query (..))
import Hauth.Crypto.Password (
    PasswordPolicyError (..),
    checkPasswordPolicy,
    defaultPasswordPolicy,
 )

-- | Wrapper around a user UUID primary key.
newtype UserId = UserId {unUserId :: UUID}
    deriving stock (Eq, Show)

-- | A persisted user row from @auth.users@.
data User = User
    { userId :: UserId
    , userEmail :: Maybe Text
    , userEncryptedPassword :: Maybe Text
    , userEmailConfirmedAt :: Maybe UTCTime
    , userConfirmationToken :: Maybe Text
    , userConfirmationSentAt :: Maybe UTCTime
    , userRawAppMetaData :: Value
    , userRawUserMetaData :: Value
    , userRole :: Text
    , userAud :: Text
    , userCreatedAt :: UTCTime
    , userUpdatedAt :: UTCTime
    }
    deriving stock (Eq, Show)

-- | Values required to create a new user.
data NewUser = NewUser
    { newUserEmail :: Text
    , newUserEncryptedPassword :: Text
    , newUserConfirmationToken :: Maybe Text
    , newUserUserMetadata :: Value
    , newUserAud :: Text
    }
    deriving stock (Eq, Show)

-- | Errors that can occur during signup validation.
data SignupError
    = SignupEmailInvalid Text
    | SignupEmailExists
    | SignupPasswordTooShort Int Int
    deriving stock (Eq, Show)

{- | Describes the fields that can be updated on an existing user.

All fields are optional; only the non-'Nothing' ones are written to the
database.  The caller is responsible for hashing the password before
putting it in 'updateEncryptedPassword'.
-}
data UserUpdate = UserUpdate
    { updateEmailChange :: Maybe Text
    -- ^ Pending email change (not yet confirmed).
    , updateEncryptedPassword :: Maybe Text
    -- ^ PHC-encoded Argon2id hash.
    , updateRawUserMetaData :: Maybe Value
    -- ^ Replaces @raw_user_meta_data@ entirely (merge semantics deferred to v0.2).
    , updateEmailChangeToken :: Maybe Text
    -- ^ Token used to confirm the pending email change.
    }
    deriving stock (Eq, Show)

-- | A 'UserUpdate' with all fields set to 'Nothing'.
emptyUserUpdate :: UserUpdate
emptyUserUpdate =
    UserUpdate
        { updateEmailChange = Nothing
        , updateEncryptedPassword = Nothing
        , updateRawUserMetaData = Nothing
        , updateEmailChangeToken = Nothing
        }

instance FromRow User where
    fromRow =
        User . UserId
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
            <*> field
            <*> field

instance ToRow NewUser where
    toRow NewUser{..} =
        toRow
            ( newUserEmail
            , newUserEncryptedPassword
            , newUserConfirmationToken
            , newUserConfirmationToken -- confirmation_sent_at derives from token presence
            , newUserUserMetadata
            , newUserAud
            )

-- | Insert a new user into @auth.users@ and return the persisted row.
createUser :: Connection -> NewUser -> IO User
createUser conn NewUser{..} = do
    uid <- UUID4.nextRandom
    rows <-
        query
            conn
            "INSERT INTO auth.users \
            \  (id, email, encrypted_password, confirmation_token, \
            \   confirmation_sent_at, raw_user_meta_data, raw_app_meta_data, \
            \   aud, role) \
            \VALUES \
            \  (?, ?, ?, ?, \
            \   CASE WHEN ? IS NOT NULL THEN now() ELSE NULL END, \
            \   ?, '{}', \
            \   ?, 'authenticated') \
            \RETURNING \
            \  id, email, encrypted_password, email_confirmed_at, \
            \  confirmation_token, confirmation_sent_at, \
            \  raw_app_meta_data, raw_user_meta_data, \
            \  role, aud, created_at, updated_at"
            ( uid
            , newUserEmail
            , newUserEncryptedPassword
            , newUserConfirmationToken
            , newUserConfirmationToken
            , newUserUserMetadata
            , newUserAud
            )
    case rows of
        [row] -> pure row
        _ -> fail "createUser: expected exactly one row returned"

-- | Look up a user by email address, excluding soft-deleted rows.
getUserByEmail :: Connection -> Text -> IO (Maybe User)
getUserByEmail conn email = do
    rows <-
        query
            conn
            "SELECT \
            \  id, email, encrypted_password, email_confirmed_at, \
            \  confirmation_token, confirmation_sent_at, \
            \  raw_app_meta_data, raw_user_meta_data, \
            \  role, aud, created_at, updated_at \
            \FROM auth.users \
            \WHERE email = ? AND deleted_at IS NULL"
            (Only email)
    pure $ case rows of
        [row] -> Just row
        _ -> Nothing

-- | Look up a user by primary key.
getUserById :: Connection -> UserId -> IO (Maybe User)
getUserById conn (UserId uid) = do
    rows <-
        query
            conn
            "SELECT \
            \  id, email, encrypted_password, email_confirmed_at, \
            \  confirmation_token, confirmation_sent_at, \
            \  raw_app_meta_data, raw_user_meta_data, \
            \  role, aud, created_at, updated_at \
            \FROM auth.users \
            \WHERE id = ? AND deleted_at IS NULL"
            (Only uid)
    pure $ case rows of
        [row] -> Just row
        _ -> Nothing

-- | Look up a user by their @confirmation_token@ value, excluding soft-deleted rows.
getUserByConfirmationToken :: Connection -> Text -> IO (Maybe User)
getUserByConfirmationToken conn token = do
    rows <-
        query
            conn
            "SELECT \
            \  id, email, encrypted_password, email_confirmed_at, \
            \  confirmation_token, confirmation_sent_at, \
            \  raw_app_meta_data, raw_user_meta_data, \
            \  role, aud, created_at, updated_at \
            \FROM auth.users \
            \WHERE confirmation_token = ? AND deleted_at IS NULL"
            (Only token)
    pure $ case rows of
        [row] -> Just row
        _ -> Nothing

{- | Update @confirmation_token@ and set @confirmation_sent_at@ to @now()@.

Used by the resend flow to issue a fresh token.
-}
setConfirmationToken :: Connection -> UserId -> Text -> IO ()
setConfirmationToken conn (UserId uid) token = do
    _ <-
        query
            conn
            "UPDATE auth.users \
            \SET confirmation_token = ?, confirmation_sent_at = now(), updated_at = now() \
            \WHERE id = ? \
            \RETURNING id"
            (token, uid) ::
            IO [Only UUID]
    pure ()

-- | Set @email_confirmed_at@ to the current time for a user.
markEmailConfirmed :: Connection -> UserId -> IO ()
markEmailConfirmed conn (UserId uid) = do
    _ <-
        query
            conn
            "UPDATE auth.users \
            \SET email_confirmed_at = now(), confirmation_token = NULL, updated_at = now() \
            \WHERE id = ? \
            \RETURNING id"
            (Only uid) ::
            IO [Only UUID]
    pure ()

{- | Apply a 'UserUpdate' to the user identified by 'UserId'.

Only the non-'Nothing' fields in the update record are written to the
database; @updated_at@ is always bumped to @now()@.  Returns the updated
user row, or 'Nothing' if no row with the given id exists.

If the 'UserUpdate' has all fields 'Nothing', we still issue an UPDATE to
bump @updated_at@ and re-fetch the current row.
-}
applyUserUpdate :: Connection -> UserId -> UserUpdate -> IO (Maybe User)
applyUserUpdate conn (UserId uid) upd = do
    let assignments = buildAssignments upd
        allClauses = assignments <> [("updated_at", toField ("now()" :: Text))]
        setFragment =
            BSC.pack $
                intercalate ", " $
                    fmap (\(col, _) -> col <> " = ?") allClauses
        params = fmap snd allClauses <> [toField uid]
        sqlStr =
            "UPDATE auth.users SET "
                <> setFragment
                <> " WHERE id = ? AND deleted_at IS NULL \
                   \RETURNING \
                   \  id, email, encrypted_password, email_confirmed_at, \
                   \  confirmation_token, confirmation_sent_at, \
                   \  raw_app_meta_data, raw_user_meta_data, \
                   \  role, aud, created_at, updated_at"
    rows <- query conn (Query sqlStr) params
    pure $ case rows of
        [row] -> Just row
        _ -> Nothing

{- | Build a list of @(column_name_string, Action)@ pairs for the non-Nothing
fields of a 'UserUpdate'.  When an email change is requested we also set
@email_change_sent_at@ to @now()@.
-}
buildAssignments :: UserUpdate -> [(String, Action)]
buildAssignments UserUpdate{..} =
    catMaybes
        [ fmap (\v -> ("email_change", toField v)) updateEmailChange
        , fmap (\v -> ("encrypted_password", toField v)) updateEncryptedPassword
        , fmap (\v -> ("raw_user_meta_data", toField v)) updateRawUserMetaData
        , fmap (\v -> ("email_change_token_new", toField v)) updateEmailChangeToken
        , fmap (const ("email_change_sent_at", toField ("now()" :: Text))) updateEmailChange
        ]

{- | Generate a cryptographically random confirmation token.

Produces 32 random bytes, base64url-encodes them without padding, and
returns the result as 'Text'.  The output is always 43 characters long
(ceil(32 * 8 / 6) = 43 base64url characters with no padding).
-}
generateConfirmationToken :: IO Text
generateConfirmationToken = do
    bytes <- CR.getRandomBytes 32
    pure $ TE.decodeUtf8 (B64URL.encodeUnpadded bytes)

-- | Validate an email address for signup. Returns the email or a 'SignupError'.
validateSignupEmail :: Text -> Either SignupError Text
validateSignupEmail email =
    if isEmailLike email
        then Right email
        else Left (SignupEmailInvalid email)

-- | Validate a password for signup, delegating to 'checkPasswordPolicy'.
validateSignupPassword :: Text -> Either SignupError Text
validateSignupPassword pw =
    case checkPasswordPolicy defaultPasswordPolicy pw of
        Left (PasswordTooShort minLen actual) ->
            Left (SignupPasswordTooShort minLen actual)
        Right () ->
            Right pw

-- | Minimal email validation: non-empty local and domain parts around @\@@.
isEmailLike :: Text -> Bool
isEmailLike value =
    case T.splitOn "@" value of
        [localPart, domain]
            | not (T.null localPart) && not (T.null domain) ->
                True
        _ ->
            False
