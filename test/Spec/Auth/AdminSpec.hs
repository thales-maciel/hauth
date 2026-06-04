{-# LANGUAGE ScopedTypeVariables #-}

module Spec.Auth.AdminSpec (spec) where

import Data.Aeson (Object, Value (..))
import qualified Data.Aeson as Aeson
import qualified Data.Aeson.KeyMap as KeyMap
import qualified Data.Text as T
import Data.Time.Clock (UTCTime, getCurrentTime)
import qualified Data.UUID as UUID
import Hauth.API.Types (
    AdminCreateUserRequest (..),
    AdminUpdateUserRequest (..),
    DeletedUserResponse (..),
    Email (..),
    InviteUserRequest (..),
    ListIdentitiesResponse (..),
    ListUsersResponse (..),
    Password (..),
    buildIdentityResponse,
    buildUserResponse,
 )
import Hauth.Auth.Admin (
    AdminError (..),
    Pagination (..),
    computeNextPage,
    defaultPagination,
    parsePagination,
    validateAdminCreate,
    validateAdminUpdate,
    validateInvite,
 )
import Hauth.Identity (Identity (..), IdentityId (..))
import Hauth.User (
    User (..),
    UserId (..),
 )
import Test.Hspec (Spec, describe, expectationFailure, it, shouldBe)

sampleUser :: UTCTime -> User
sampleUser now =
    User
        { userId = UserId UUID.nil
        , userEmail = Just "list@example.com"
        , userEncryptedPassword = Nothing
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

sampleIdentity :: UTCTime -> Identity
sampleIdentity now =
    Identity
        { identityIdentityId = IdentityId "provider-id-123"
        , identityUserId = UUID.nil
        , identityProvider = "email"
        , identityProviderId = "provider-id-123"
        , identityIdentityData = Aeson.object ["email" Aeson..= ("user@example.com" :: T.Text)]
        , identityEmail = Just "user@example.com"
        , identityCreatedAt = now
        , identityUpdatedAt = now
        , identityLastSignInAt = Nothing
        }

spec :: Spec
spec = do
    describe "parsePagination" $ do
        it "Nothing Nothing == defaultPagination" $
            parsePagination Nothing Nothing `shouldBe` defaultPagination
        it "defaults page=1" $
            pagPage (parsePagination Nothing Nothing) `shouldBe` 1
        it "defaults per_page=50" $
            pagPerPage (parsePagination Nothing Nothing) `shouldBe` 50
        it "clamps page 0 -> 1" $
            pagPage (parsePagination (Just 0) (Just 200)) `shouldBe` 1
        it "clamps per_page 200 -> 100" $
            pagPerPage (parsePagination (Just 0) (Just 200)) `shouldBe` 100
        it "explicit page=3 per_page=20" $
            parsePagination (Just 3) (Just 20) `shouldBe` Pagination{pagPage = 3, pagPerPage = 20}

    describe "computeNextPage" $ do
        it "on last page -> Nothing" $
            computeNextPage (Pagination 1 50) 50 `shouldBe` Nothing
        it "exactly full page -> Nothing" $
            computeNextPage (Pagination 1 50) 50 `shouldBe` Nothing
        it "one more row -> Just 2" $
            computeNextPage (Pagination 1 50) 51 `shouldBe` Just 2
        it "page 2 of 3" $
            computeNextPage (Pagination 2 10) 25 `shouldBe` Just 3
        it "zero total -> Nothing" $
            computeNextPage (Pagination 1 50) 0 `shouldBe` Nothing

    describe "validateAdminCreate" $ do
        it "empty email -> AdminEmailRequired" $
            validateAdminCreate
                AdminCreateUserRequest
                    { adminCreateUserEmail = Email ""
                    , adminCreateUserPassword = Nothing
                    , adminCreateUserConfirmed = False
                    , adminCreateUserUserMetadata = Nothing
                    , adminCreateUserAppMetadata = Nothing
                    }
                `shouldBe` Left AdminEmailRequired
        it "bad email -> AdminEmailInvalid" $
            case validateAdminCreate
                AdminCreateUserRequest
                    { adminCreateUserEmail = Email "notanemail"
                    , adminCreateUserPassword = Nothing
                    , adminCreateUserConfirmed = False
                    , adminCreateUserUserMetadata = Nothing
                    , adminCreateUserAppMetadata = Nothing
                    } of
                Left (AdminEmailInvalid _) -> pure ()
                other ->
                    expectationFailure
                        ("validateAdminCreate bad email: expected AdminEmailInvalid, got " <> show other)
        it "short password -> AdminPasswordPolicy" $
            case validateAdminCreate
                AdminCreateUserRequest
                    { adminCreateUserEmail = Email "user@example.com"
                    , adminCreateUserPassword = Just (Password "short")
                    , adminCreateUserConfirmed = False
                    , adminCreateUserUserMetadata = Nothing
                    , adminCreateUserAppMetadata = Nothing
                    } of
                Left (AdminPasswordPolicy _ _) -> pure ()
                other ->
                    expectationFailure
                        ("validateAdminCreate short password: expected AdminPasswordPolicy, got " <> show other)
        it "email-only -> Right ()" $
            validateAdminCreate
                AdminCreateUserRequest
                    { adminCreateUserEmail = Email "user@example.com"
                    , adminCreateUserPassword = Nothing
                    , adminCreateUserConfirmed = False
                    , adminCreateUserUserMetadata = Nothing
                    , adminCreateUserAppMetadata = Nothing
                    }
                `shouldBe` Right ()

    describe "validateAdminUpdate" $ do
        let emptyUpdate =
                AdminUpdateUserRequest
                    { adminUpdateUserEmail = Nothing
                    , adminUpdateUserPassword = Nothing
                    , adminUpdateUserEmailConfirm = Nothing
                    , adminUpdateUserBannedUntil = Nothing
                    , adminUpdateUserRole = Nothing
                    , adminUpdateUserUserMetadata = Nothing
                    , adminUpdateUserAppMetadata = Nothing
                    }
            updateWithRole r = emptyUpdate{adminUpdateUserRole = Just r}
        it "no-op update -> Right ()" $
            validateAdminUpdate emptyUpdate `shouldBe` Right ()
        it "role=authenticated -> Right ()" $
            validateAdminUpdate (updateWithRole "authenticated") `shouldBe` Right ()
        it "role=custom_app_role -> Right ()" $
            validateAdminUpdate (updateWithRole "custom_app_role") `shouldBe` Right ()
        it "role=service_role -> AdminRoleReserved" $
            validateAdminUpdate (updateWithRole "service_role")
                `shouldBe` Left (AdminRoleReserved "service_role")
        it "role=anon -> AdminRoleReserved" $
            validateAdminUpdate (updateWithRole "anon")
                `shouldBe` Left (AdminRoleReserved "anon")
        it "role=supabase_admin -> AdminRoleReserved" $
            validateAdminUpdate (updateWithRole "supabase_admin")
                `shouldBe` Left (AdminRoleReserved "supabase_admin")
        it "role=supabase_auth_admin -> AdminRoleReserved" $
            validateAdminUpdate (updateWithRole "supabase_auth_admin")
                `shouldBe` Left (AdminRoleReserved "supabase_auth_admin")
        it "invalid email beats reserved role" $
            case validateAdminUpdate
                emptyUpdate
                    { adminUpdateUserEmail = Just (Email "notanemail")
                    , adminUpdateUserRole = Just "service_role"
                    } of
                Left (AdminEmailInvalid _) -> pure ()
                other ->
                    expectationFailure
                        ("expected AdminEmailInvalid to take precedence, got " <> show other)

    describe "validateInvite" $ do
        it "empty email -> AdminEmailRequired" $
            validateInvite InviteUserRequest{inviteUserEmail = Email "", inviteUserData = Nothing}
                `shouldBe` Left AdminEmailRequired
        it "valid email -> Right ()" $
            validateInvite
                InviteUserRequest{inviteUserEmail = Email "invite@example.com", inviteUserData = Nothing}
                `shouldBe` Right ()

    describe "ListUsersResponse JSON" $
        it "encodes users, aud, and next_page" $ do
            now7 <- getCurrentTime
            let sampleUserResp = buildUserResponse (sampleUser now7)
                listUsersResp =
                    ListUsersResponse
                        { listUsers = [sampleUserResp]
                        , listUsersAud = "authenticated"
                        , listUsersNextPage = Just 2
                        }
            case Aeson.decode (Aeson.encode listUsersResp) of
                Nothing -> expectationFailure "ListUsersResponse: JSON decode failed"
                Just (obj :: Object) -> do
                    mapM_
                        ( \k ->
                            if KeyMap.member k obj
                                then pure ()
                                else expectationFailure ("ListUsersResponse JSON: missing key: " <> show k)
                        )
                        ["users", "aud", "next_page"]
                    KeyMap.lookup "aud" obj `shouldBe` Just (String "authenticated")

    describe "DeletedUserResponse JSON" $
        it "encodes user key" $ do
            now7 <- getCurrentTime
            let sampleUserResp = buildUserResponse (sampleUser now7)
                deletedResp = DeletedUserResponse{deletedUser = sampleUserResp}
            case Aeson.decode (Aeson.encode deletedResp) of
                Nothing -> expectationFailure "DeletedUserResponse: JSON decode failed"
                Just (obj :: Object) ->
                    if KeyMap.member "user" obj
                        then pure ()
                        else expectationFailure "DeletedUserResponse JSON: missing 'user' key"

    describe "Identity" $ do
        it "identityId" $ do
            now7 <- getCurrentTime
            identityIdentityId (sampleIdentity now7) `shouldBe` IdentityId "provider-id-123"
        it "userId" $ do
            now7 <- getCurrentTime
            identityUserId (sampleIdentity now7) `shouldBe` UUID.nil
        it "provider" $ do
            now7 <- getCurrentTime
            identityProvider (sampleIdentity now7) `shouldBe` "email"
        it "email" $ do
            now7 <- getCurrentTime
            identityEmail (sampleIdentity now7) `shouldBe` Just "user@example.com"

    describe "IdentityResponse JSON" $
        it "encodes required keys" $ do
            now7 <- getCurrentTime
            let identResp = buildIdentityResponse (sampleIdentity now7)
            case Aeson.decode (Aeson.encode identResp) of
                Nothing -> expectationFailure "IdentityResponse: JSON decode failed"
                Just (obj :: Object) ->
                    mapM_
                        ( \k ->
                            if KeyMap.member k obj
                                then pure ()
                                else expectationFailure ("IdentityResponse JSON: missing key: " <> show k)
                        )
                        [ "id"
                        , "user_id"
                        , "provider"
                        , "provider_id"
                        , "identity_data"
                        , "created_at"
                        , "updated_at"
                        ]

    describe "ListIdentitiesResponse JSON" $
        it "encodes identities key" $ do
            now7 <- getCurrentTime
            let identResp = buildIdentityResponse (sampleIdentity now7)
                listIdResp = ListIdentitiesResponse{listIdentities = [identResp]}
            case Aeson.decode (Aeson.encode listIdResp) of
                Nothing -> expectationFailure "ListIdentitiesResponse: JSON decode failed"
                Just (obj :: Object) ->
                    if KeyMap.member "identities" obj
                        then pure ()
                        else expectationFailure "ListIdentitiesResponse JSON: missing 'identities' key"
