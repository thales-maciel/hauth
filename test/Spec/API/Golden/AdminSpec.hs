{- | Wire-shape coverage for the admin surface: users, identities, invites,
providers, and email templates.
-}
module Spec.API.Golden.AdminSpec (spec) where

import qualified Data.Aeson as Aeson
import Hauth.API.Types
import Spec.API.Golden.Helpers (
    canonicalEmailTemplateRow,
    canonicalIdentityResponse,
    canonicalUserResponse,
    emailTemplateRowJson,
    identityResponseJson,
    roundTrip,
    t0,
    userResponseJson,
 )
import Test.Hspec (Spec, describe, it)

spec :: Spec
spec = describe "Admin" $ do
    it "ListUsersResponse" $
        roundTrip
            "ListUsersResponse"
            ListUsersResponse
                { listUsers = [canonicalUserResponse]
                , listUsersAud = "authenticated"
                , listUsersNextPage = Just 2
                }
            ("{\"users\":[" <> userResponseJson <> "],\"aud\":\"authenticated\",\"next_page\":2}")

    it "AdminCreateUserRequest" $
        roundTrip
            "AdminCreateUserRequest"
            AdminCreateUserRequest
                { adminCreateUserEmail = Email "alice@example.com"
                , adminCreateUserPassword = Just (Password "pw")
                , adminCreateUserConfirmed = True
                , adminCreateUserUserMetadata = Just (Aeson.object [])
                , adminCreateUserAppMetadata = Just (Aeson.object [])
                }
            "{\"email\":\"alice@example.com\",\"password\":\"pw\",\"email_confirm\":true,\"user_metadata\":{},\"app_metadata\":{}}"

    it "AdminUpdateUserRequest" $
        roundTrip
            "AdminUpdateUserRequest"
            AdminUpdateUserRequest
                { adminUpdateUserEmail = Just (Email "alice@example.com")
                , adminUpdateUserPassword = Just (Password "pw")
                , adminUpdateUserEmailConfirm = Just True
                , adminUpdateUserBannedUntil = Just t0
                , adminUpdateUserRole = Just "authenticated"
                , adminUpdateUserUserMetadata = Just (Aeson.object [])
                , adminUpdateUserAppMetadata = Just (Aeson.object [])
                }
            "{\"email\":\"alice@example.com\",\"password\":\"pw\",\"email_confirm\":true\
            \,\"banned_until\":\"2026-01-02T03:04:05Z\",\"role\":\"authenticated\"\
            \,\"user_metadata\":{},\"app_metadata\":{}}"

    it "DeletedUserResponse" $
        roundTrip
            "DeletedUserResponse"
            (DeletedUserResponse canonicalUserResponse)
            ("{\"user\":" <> userResponseJson <> "}")

    it "ListIdentitiesResponse" $
        roundTrip
            "ListIdentitiesResponse"
            ListIdentitiesResponse{listIdentities = [canonicalIdentityResponse]}
            ("{\"identities\":[" <> identityResponseJson <> "]}")

    it "GenerateLinkRequest" $
        roundTrip
            "GenerateLinkRequest"
            GenerateLinkRequest
                { generateLinkEmail = Email "alice@example.com"
                , generateLinkType = "signup"
                }
            "{\"email\":\"alice@example.com\",\"type\":\"signup\"}"

    it "GenerateLinkResponse" $
        roundTrip
            "GenerateLinkResponse"
            GenerateLinkResponse{generateLinkActionLink = "https://auth.example.com/verify?token=...&type=signup"}
            "{\"action_link\":\"https://auth.example.com/verify?token=...&type=signup\"}"

    it "InviteUserRequest" $
        roundTrip
            "InviteUserRequest"
            InviteUserRequest
                { inviteUserEmail = Email "alice@example.com"
                , inviteUserData = Just (Aeson.object [])
                }
            "{\"email\":\"alice@example.com\",\"data\":{}}"

    it "ProvidersResponse" $
        roundTrip
            "ProvidersResponse"
            ProvidersResponse{providers = ["google", "github"]}
            "{\"providers\":[\"google\",\"github\"]}"

    it "UpdateProvidersRequest" $
        roundTrip
            "UpdateProvidersRequest"
            UpdateProvidersRequest{updateProviders = ["google", "github"]}
            "{\"providers\":[\"google\",\"github\"]}"

    it "EmailTemplatesResponse" $
        roundTrip
            "EmailTemplatesResponse"
            EmailTemplatesResponse{emailTemplates = ["confirmation", "recovery"]}
            "{\"templates\":[\"confirmation\",\"recovery\"]}"

    it "UpdateEmailTemplatesRequest" $
        roundTrip
            "UpdateEmailTemplatesRequest"
            UpdateEmailTemplatesRequest{updateEmailTemplates = ["confirmation", "recovery"]}
            "{\"templates\":[\"confirmation\",\"recovery\"]}"

    it "EmailTemplateCrudRequest" $
        roundTrip
            "EmailTemplateCrudRequest"
            EmailTemplateCrudRequest
                { emailTemplateCrudSubject = "Confirm"
                , emailTemplateCrudBodyText = "txt"
                , emailTemplateCrudBodyHtml = "<p>html</p>"
                }
            "{\"subject\":\"Confirm\",\"body_text\":\"txt\",\"body_html\":\"<p>html</p>\"}"

    it "EmailTemplateRow" $
        roundTrip
            "EmailTemplateRow"
            canonicalEmailTemplateRow
            emailTemplateRowJson

    it "EmailTemplatesListResponse" $
        roundTrip
            "EmailTemplatesListResponse"
            EmailTemplatesListResponse{emailTemplatesList = [canonicalEmailTemplateRow]}
            ("{\"templates\":[" <> emailTemplateRowJson <> "]}")
