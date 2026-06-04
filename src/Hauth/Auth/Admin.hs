module Hauth.Auth.Admin (
    AdminError (..),
    Pagination (..),
    defaultPagination,
    computeNextPage,
    parsePagination,
    validateAdminCreate,
    validateAdminUpdate,
    validateInvite,
) where

import Data.Text (Text)
import qualified Data.Text as T
import Hauth.API.Types (AdminCreateUserRequest (..), AdminUpdateUserRequest (..), InviteUserRequest (..), Password (..), unEmail)
import Hauth.Auth.Role (isReservedRole)
import Hauth.Crypto.Password (PasswordPolicyError (..), checkPasswordPolicy, defaultPasswordPolicy)

-- | Errors from admin request validation.
data AdminError
    = AdminEmailRequired
    | AdminEmailInvalid Text
    | -- | @(minLen, actual)@
      AdminPasswordPolicy Int Int
    | AdminUserNotFound
    | -- | Admin attempted to assign a reserved control-plane role; the
      -- offending role string is included verbatim.
      AdminRoleReserved Text
    deriving stock (Eq, Show)

-- ---------------------------------------------------------------------------
-- Pagination
-- ---------------------------------------------------------------------------

-- | Pagination parameters derived from query params.
data Pagination = Pagination
    { pagPage :: Int
    -- ^ 1-based page number.
    , pagPerPage :: Int
    -- ^ Rows per page.
    }
    deriving stock (Eq, Show)

-- | Default pagination: page 1, 50 rows per page.
defaultPagination :: Pagination
defaultPagination = Pagination{pagPage = 1, pagPerPage = 50}

-- | Maximum rows per page accepted from callers.
maxPerPage :: Int
maxPerPage = 100

{- | Derive a 'Pagination' from optional raw query parameters.

Both values are clamped to sane bounds:

- @page@: clamped to [@1@, ∞).
- @per_page@: clamped to [@1@, 'maxPerPage'] (currently 100).

Missing parameters fall back to 'defaultPagination'.
-}
parsePagination :: Maybe Int -> Maybe Int -> Pagination
parsePagination mPage mPerPage =
    Pagination
        { pagPage = maybe (pagPage defaultPagination) (max 1) mPage
        , pagPerPage =
            maybe
                (pagPerPage defaultPagination)
                (max 1 . min maxPerPage)
                mPerPage
        }

{- | Compute the next page number given the current pagination and total row count.

Returns 'Nothing' when all rows fit on pages up to the current one; returns
@Just (page + 1)@ otherwise.
-}
computeNextPage :: Pagination -> Int -> Maybe Int
computeNextPage Pagination{pagPage, pagPerPage} totalCount
    | pagPage * pagPerPage < totalCount = Just (pagPage + 1)
    | otherwise = Nothing

-- ---------------------------------------------------------------------------
-- Validation helpers
-- ---------------------------------------------------------------------------

-- | Minimal email-like check: non-empty local and domain around @\@@.
isEmailLike :: Text -> Bool
isEmailLike value =
    case T.splitOn "@" value of
        [localPart, domain]
            | not (T.null localPart) && not (T.null domain) ->
                True
        _ ->
            False

validateEmail :: Text -> Either AdminError ()
validateEmail email
    | T.null email = Left AdminEmailRequired
    | not (isEmailLike email) = Left (AdminEmailInvalid email)
    | otherwise = Right ()

validateOptionalPassword :: Maybe Password -> Either AdminError ()
validateOptionalPassword Nothing = Right ()
validateOptionalPassword (Just (Password pw)) =
    case checkPasswordPolicy defaultPasswordPolicy pw of
        Left (PasswordTooShort minLen actual) ->
            Left (AdminPasswordPolicy minLen actual)
        Right () ->
            Right ()

-- ---------------------------------------------------------------------------
-- Public validators
-- ---------------------------------------------------------------------------

{- | Validate an 'AdminCreateUserRequest'.

Email must be present and well-formed.  Password is optional for admin-created
users; when provided it is checked against the default policy.
-}
validateAdminCreate :: AdminCreateUserRequest -> Either AdminError ()
validateAdminCreate AdminCreateUserRequest{adminCreateUserEmail, adminCreateUserPassword} = do
    validateEmail (unEmail adminCreateUserEmail)
    validateOptionalPassword adminCreateUserPassword

{- | Validate an 'AdminUpdateUserRequest'.

Only validates fields that are present; all-Nothing is valid (no-op update).
-}
validateAdminUpdate :: AdminUpdateUserRequest -> Either AdminError ()
validateAdminUpdate AdminUpdateUserRequest{adminUpdateUserEmail, adminUpdateUserPassword, adminUpdateUserRole} = do
    case adminUpdateUserEmail of
        Nothing -> pure ()
        Just em -> validateEmail (unEmail em)
    validateOptionalPassword adminUpdateUserPassword
    case adminUpdateUserRole of
        Just r | isReservedRole r -> Left (AdminRoleReserved r)
        _ -> pure ()

-- | Validate an 'InviteUserRequest'.
validateInvite :: InviteUserRequest -> Either AdminError ()
validateInvite InviteUserRequest{inviteUserEmail} =
    validateEmail (unEmail inviteUserEmail)
