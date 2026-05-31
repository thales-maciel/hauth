module Spec.Auth.UserUpdateSpec (runSpec) where

import Data.Aeson (Object)
import qualified Data.Aeson as Aeson
import qualified Data.Aeson.KeyMap as KeyMap
import qualified Data.ByteString.Lazy as BSL
import qualified Data.Text as T
import Data.Time.Clock (getCurrentTime)
import qualified Data.UUID as UUID
import Hauth.API.Types (
    Email (..),
    Password (..),
    UpdateUserRequest (..),
    buildUserResponse,
 )
import Hauth.Auth.UserUpdate (UpdateUserError (..), validateUpdateRequest)
import Hauth.User (
    User (..),
    UserId (..),
    UserUpdate (..),
    emptyUserUpdate,
 )
import Spec.TestUtils (assertEqual)

runSpec :: IO ()
runSpec = do
    assertEqual
        "validateUpdateRequest empty"
        (Right (Nothing, Nothing, Nothing))
        ( validateUpdateRequest
            UpdateUserRequest
                { updateUserEmail = Nothing
                , updateUserPassword = Nothing
                , updateUserData = Nothing
                }
        )
    assertEqual
        "validateUpdateRequest valid email"
        (Right (Just "new@example.com", Nothing, Nothing))
        ( validateUpdateRequest
            UpdateUserRequest
                { updateUserEmail = Just (Email "new@example.com")
                , updateUserPassword = Nothing
                , updateUserData = Nothing
                }
        )
    case validateUpdateRequest
        UpdateUserRequest
            { updateUserEmail = Just (Email "invalid-no-at")
            , updateUserPassword = Nothing
            , updateUserData = Nothing
            } of
        Left (UpdateUserEmailInvalid _) -> pure ()
        other -> fail ("validateUpdateRequest bad email: expected UpdateUserEmailInvalid, got " <> show other)
    case validateUpdateRequest
        UpdateUserRequest
            { updateUserEmail = Nothing
            , updateUserPassword = Just (Password "short")
            , updateUserData = Nothing
            } of
        Left (UpdateUserPasswordTooShort _ _) -> pure ()
        other -> fail ("validateUpdateRequest short password: expected UpdateUserPasswordTooShort, got " <> show other)
    let testMeta = Aeson.object ["key" Aeson..= ("value" :: T.Text)]
    case validateUpdateRequest
        UpdateUserRequest
            { updateUserEmail = Just (Email "all@fields.com")
            , updateUserPassword = Just (Password "validpassword")
            , updateUserData = Just testMeta
            } of
        Right (Just _, Just _, Just _) -> pure ()
        other -> fail ("validateUpdateRequest all fields: expected Right (Just, Just, Just), got " <> show other)
    assertEqual "emptyUserUpdate emailChange" Nothing (updateEmailChange emptyUserUpdate)
    assertEqual "emptyUserUpdate encryptedPassword" Nothing (updateEncryptedPassword emptyUserUpdate)
    assertEqual "emptyUserUpdate rawUserMetaData" Nothing (updateRawUserMetaData emptyUserUpdate)
    assertEqual "emptyUserUpdate emailChangeToken" Nothing (updateEmailChangeToken emptyUserUpdate)
    now6 <- getCurrentTime
    let testUserForResponse =
            User
                { userId = UserId UUID.nil
                , userEmail = Just "resp@example.com"
                , userEncryptedPassword = Just "$argon2id$v=19$..."
                , userEmailConfirmedAt = Just now6
                , userConfirmationToken = Nothing
                , userConfirmationSentAt = Nothing
                , userRawAppMetaData = Aeson.object []
                , userRawUserMetaData = Aeson.object []
                , userRole = "authenticated"
                , userAud = "authenticated"
                , userCreatedAt = now6
                , userUpdatedAt = now6
                }
        userResp = buildUserResponse testUserForResponse
        userRespJson = BSL.toStrict (Aeson.encode userResp)
    case Aeson.decodeStrict' userRespJson of
        Nothing -> fail "UserResponse: JSON decode failed"
        Just (obj :: Object) -> do
            let requiredUserRespKeys =
                    [ "id"
                    , "aud"
                    , "role"
                    , "email"
                    , "email_confirmed_at"
                    , "created_at"
                    , "updated_at"
                    , "app_metadata"
                    , "user_metadata"
                    ]
            mapM_
                ( \k ->
                    if KeyMap.member k obj
                        then pure ()
                        else fail ("UserResponse JSON: missing key: " <> show k)
                )
                requiredUserRespKeys
