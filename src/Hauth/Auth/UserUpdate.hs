module Hauth.Auth.UserUpdate (
    UpdateUserError (..),
    validateUpdateRequest,
) where

import Data.Aeson (Value)
import Data.Text (Text)
import qualified Data.Text as T
import Hauth.API.Types (Email (..), Password (..), UpdateUserRequest (..))
import Hauth.Crypto.Password (
    PasswordPolicyError (..),
    checkPasswordPolicy,
    defaultPasswordPolicy,
 )

-- | Errors that can occur when validating a user-update request.
data UpdateUserError
    = UpdateUserEmailInvalid Text
    | UpdateUserPasswordTooShort Int Int
    deriving stock (Eq, Show)

{- | Validate an 'UpdateUserRequest' and extract the validated fields.

Returns 'Left' on the first validation error encountered, or 'Right' with
a triple of (maybe-email, maybe-plaintext-password, maybe-metadata).
All fields are optional; an empty request is valid and returns
@Right (Nothing, Nothing, Nothing)@.
-}
validateUpdateRequest ::
    UpdateUserRequest ->
    Either UpdateUserError (Maybe Text, Maybe Text, Maybe Value)
validateUpdateRequest UpdateUserRequest{updateUserEmail, updateUserPassword, updateUserData} = do
    mEmail <- case updateUserEmail of
        Nothing -> Right Nothing
        Just (Email e) ->
            if isEmailLike e
                then Right (Just e)
                else Left (UpdateUserEmailInvalid e)
    mPassword <- case updateUserPassword of
        Nothing -> Right Nothing
        Just (Password pw) ->
            case checkPasswordPolicy defaultPasswordPolicy pw of
                Left (PasswordTooShort minLen actual) ->
                    Left (UpdateUserPasswordTooShort minLen actual)
                Right () ->
                    Right (Just pw)
    pure (mEmail, mPassword, updateUserData)

-- | Minimal email validation: non-empty local and domain parts around @\@@.
isEmailLike :: Text -> Bool
isEmailLike value =
    case T.splitOn "@" value of
        [localPart, domain]
            | not (T.null localPart) && not (T.null domain) ->
                True
        _ ->
            False
