module Spec.Auth.UserUpdateSpec (spec) where

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
import Test.Hspec (Spec, describe, expectationFailure, it, shouldBe)

spec :: Spec
spec = do
    describe "validateUpdateRequest" $ do
        it "accepts empty request" $
            validateUpdateRequest
                UpdateUserRequest
                    { updateUserEmail = Nothing
                    , updateUserPassword = Nothing
                    , updateUserData = Nothing
                    }
                `shouldBe` Right (Nothing, Nothing, Nothing)

        it "accepts valid email" $
            validateUpdateRequest
                UpdateUserRequest
                    { updateUserEmail = Just (Email "new@example.com")
                    , updateUserPassword = Nothing
                    , updateUserData = Nothing
                    }
                `shouldBe` Right (Just "new@example.com", Nothing, Nothing)

        it "rejects bad email" $
            case validateUpdateRequest
                UpdateUserRequest
                    { updateUserEmail = Just (Email "invalid-no-at")
                    , updateUserPassword = Nothing
                    , updateUserData = Nothing
                    } of
                Left (UpdateUserEmailInvalid _) -> pure ()
                other -> expectationFailure ("expected UpdateUserEmailInvalid, got " <> show other)

        it "rejects short password" $
            case validateUpdateRequest
                UpdateUserRequest
                    { updateUserEmail = Nothing
                    , updateUserPassword = Just (Password "short")
                    , updateUserData = Nothing
                    } of
                Left (UpdateUserPasswordTooShort _ _) -> pure ()
                other -> expectationFailure ("expected UpdateUserPasswordTooShort, got " <> show other)

        it "accepts all fields together" $ do
            let testMeta = Aeson.object ["key" Aeson..= ("value" :: T.Text)]
            case validateUpdateRequest
                UpdateUserRequest
                    { updateUserEmail = Just (Email "all@fields.com")
                    , updateUserPassword = Just (Password "validpassword")
                    , updateUserData = Just testMeta
                    } of
                Right (Just _, Just _, Just _) -> pure ()
                other -> expectationFailure ("expected Right (Just, Just, Just), got " <> show other)

    describe "emptyUserUpdate" $ do
        it "has Nothing emailChange" $
            updateEmailChange emptyUserUpdate `shouldBe` Nothing
        it "has Nothing encryptedPassword" $
            updateEncryptedPassword emptyUserUpdate `shouldBe` Nothing
        it "has Nothing rawUserMetaData" $
            updateRawUserMetaData emptyUserUpdate `shouldBe` Nothing
        it "has Nothing emailChangeToken" $
            updateEmailChangeToken emptyUserUpdate `shouldBe` Nothing

    describe "buildUserResponse JSON" $
        it "encodes the required keys" $ do
            now <- getCurrentTime
            let testUserForResponse =
                    User
                        { userId = UserId UUID.nil
                        , userEmail = Just "resp@example.com"
                        , userEncryptedPassword = Just "$argon2id$v=19$..."
                        , userEmailConfirmedAt = Just now
                        , userConfirmationToken = Nothing
                        , userConfirmationSentAt = Nothing
                        , userRawAppMetaData = Aeson.object []
                        , userRawUserMetaData = Aeson.object []
                        , userRole = "authenticated"
                        , userAud = "authenticated"
                        , userCreatedAt = now
                        , userUpdatedAt = now
                        }
                userResp = buildUserResponse testUserForResponse
                userRespJson = BSL.toStrict (Aeson.encode userResp)
            case Aeson.decodeStrict' userRespJson of
                Nothing -> expectationFailure "JSON decode failed"
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
                                else expectationFailure ("missing key: " <> show k)
                        )
                        requiredUserRespKeys
