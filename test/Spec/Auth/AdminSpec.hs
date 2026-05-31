module Spec.Auth.AdminSpec (runSpec) where

import Data.Aeson (Object, Value (..))
import qualified Data.Aeson as Aeson
import qualified Data.Aeson.KeyMap as KeyMap
import qualified Data.Text as T
import Data.Time.Clock (getCurrentTime)
import qualified Data.UUID as UUID
import Hauth.API.Types (
    AdminCreateUserRequest (..),
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
    validateInvite,
 )
import Hauth.Identity (Identity (..), IdentityId (..))
import Hauth.User (
    User (..),
    UserId (..),
 )
import Spec.TestUtils (assertEqual)

runSpec :: IO ()
runSpec = do
    assertEqual
        "parsePagination Nothing Nothing == defaultPagination"
        defaultPagination
        (parsePagination Nothing Nothing)
    assertEqual
        "parsePagination defaults page=1"
        1
        (pagPage (parsePagination Nothing Nothing))
    assertEqual
        "parsePagination defaults per_page=50"
        50
        (pagPerPage (parsePagination Nothing Nothing))
    assertEqual
        "parsePagination clamps page 0 → 1"
        1
        (pagPage (parsePagination (Just 0) (Just 200)))
    assertEqual
        "parsePagination clamps per_page 200 → 100"
        100
        (pagPerPage (parsePagination (Just 0) (Just 200)))
    assertEqual
        "parsePagination explicit page=3 per_page=20"
        (Pagination{pagPage = 3, pagPerPage = 20})
        (parsePagination (Just 3) (Just 20))
    assertEqual
        "computeNextPage on last page → Nothing"
        Nothing
        (computeNextPage (Pagination 1 50) 50)
    assertEqual
        "computeNextPage exactly full page → Nothing"
        Nothing
        (computeNextPage (Pagination 1 50) 50)
    assertEqual
        "computeNextPage one more row → Just 2"
        (Just 2)
        (computeNextPage (Pagination 1 50) 51)
    assertEqual
        "computeNextPage page 2 of 3"
        (Just 3)
        (computeNextPage (Pagination 2 10) 25)
    assertEqual
        "computeNextPage zero total → Nothing"
        Nothing
        (computeNextPage (Pagination 1 50) 0)
    assertEqual
        "validateAdminCreate empty email → AdminEmailRequired"
        (Left AdminEmailRequired)
        ( validateAdminCreate
            AdminCreateUserRequest
                { adminCreateUserEmail = Email ""
                , adminCreateUserPassword = Nothing
                , adminCreateUserConfirmed = False
                , adminCreateUserUserMetadata = Nothing
                , adminCreateUserAppMetadata = Nothing
                }
        )
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
            fail ("validateAdminCreate bad email: expected AdminEmailInvalid, got " <> show other)
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
            fail ("validateAdminCreate short password: expected AdminPasswordPolicy, got " <> show other)
    assertEqual
        "validateAdminCreate email-only → Right ()"
        (Right ())
        ( validateAdminCreate
            AdminCreateUserRequest
                { adminCreateUserEmail = Email "user@example.com"
                , adminCreateUserPassword = Nothing
                , adminCreateUserConfirmed = False
                , adminCreateUserUserMetadata = Nothing
                , adminCreateUserAppMetadata = Nothing
                }
        )
    assertEqual
        "validateInvite empty email → AdminEmailRequired"
        (Left AdminEmailRequired)
        (validateInvite InviteUserRequest{inviteUserEmail = Email "", inviteUserData = Nothing})
    assertEqual
        "validateInvite valid email → Right ()"
        (Right ())
        (validateInvite InviteUserRequest{inviteUserEmail = Email "invite@example.com", inviteUserData = Nothing})
    now7 <- getCurrentTime
    let sampleUserResp =
            buildUserResponse
                User
                    { userId = UserId UUID.nil
                    , userEmail = Just "list@example.com"
                    , userEncryptedPassword = Nothing
                    , userEmailConfirmedAt = Just now7
                    , userConfirmationToken = Nothing
                    , userConfirmationSentAt = Nothing
                    , userRawAppMetaData = Aeson.object []
                    , userRawUserMetaData = Aeson.object []
                    , userRole = "authenticated"
                    , userAud = "authenticated"
                    , userCreatedAt = now7
                    , userUpdatedAt = now7
                    }
        listUsersResp =
            ListUsersResponse
                { listUsers = [sampleUserResp]
                , listUsersAud = "authenticated"
                , listUsersNextPage = Just 2
                }
    case Aeson.decode (Aeson.encode listUsersResp) of
        Nothing -> fail "ListUsersResponse: JSON decode failed"
        Just (obj :: Object) -> do
            mapM_
                ( \k ->
                    if KeyMap.member k obj
                        then pure ()
                        else fail ("ListUsersResponse JSON: missing key: " <> show k)
                )
                ["users", "aud", "next_page"]
            assertEqual
                "ListUsersResponse aud"
                (Just (String "authenticated"))
                (KeyMap.lookup "aud" obj)
    let deletedResp = DeletedUserResponse{deletedUser = sampleUserResp}
    case Aeson.decode (Aeson.encode deletedResp) of
        Nothing -> fail "DeletedUserResponse: JSON decode failed"
        Just (obj :: Object) -> do
            if KeyMap.member "user" obj
                then pure ()
                else fail "DeletedUserResponse JSON: missing 'user' key"
    let sampleIdentity =
            Identity
                { identityIdentityId = IdentityId "provider-id-123"
                , identityUserId = UUID.nil
                , identityProvider = "email"
                , identityProviderId = "provider-id-123"
                , identityIdentityData = Aeson.object ["email" Aeson..= ("user@example.com" :: T.Text)]
                , identityEmail = Just "user@example.com"
                , identityCreatedAt = now7
                , identityUpdatedAt = now7
                , identityLastSignInAt = Nothing
                }
    assertEqual "identity identityId" (IdentityId "provider-id-123") (identityIdentityId sampleIdentity)
    assertEqual "identity userId" UUID.nil (identityUserId sampleIdentity)
    assertEqual "identity provider" "email" (identityProvider sampleIdentity)
    assertEqual "identity email" (Just "user@example.com") (identityEmail sampleIdentity)
    let identResp = buildIdentityResponse sampleIdentity
    case Aeson.decode (Aeson.encode identResp) of
        Nothing -> fail "IdentityResponse: JSON decode failed"
        Just (obj :: Object) -> do
            mapM_
                ( \k ->
                    if KeyMap.member k obj
                        then pure ()
                        else fail ("IdentityResponse JSON: missing key: " <> show k)
                )
                [ "id"
                , "user_id"
                , "provider"
                , "provider_id"
                , "identity_data"
                , "created_at"
                , "updated_at"
                ]
    let listIdResp = ListIdentitiesResponse{listIdentities = [identResp]}
    case Aeson.decode (Aeson.encode listIdResp) of
        Nothing -> fail "ListIdentitiesResponse: JSON decode failed"
        Just (obj :: Object) ->
            if KeyMap.member "identities" obj
                then pure ()
                else fail "ListIdentitiesResponse JSON: missing 'identities' key"
