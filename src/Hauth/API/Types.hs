module Hauth.API.Types (
    AdminCreateUserRequest (..),
    AdminUpdateUserRequest (..),
    ChallengeFactorRequest (..),
    ChallengeFactorResponse (..),
    DeepHealthResponse (..),
    DeletedUserResponse (..),
    Email (..),
    EmailTemplatesResponse (..),
    EnrollFactorRequest (..),
    FactorId (..),
    FactorResponse (..),
    GenerateLinkRequest (..),
    GenerateLinkResponse (..),
    HealthResponse (..),
    IdentityId (..),
    InviteUserRequest (..),
    ListFactorsResponse (..),
    ListIdentitiesResponse (..),
    ListUsersResponse (..),
    MessageResponse (..),
    OAuthAuthorizeResponse (..),
    Password (..),
    ProvidersResponse (..),
    RecoverRequest (..),
    ResendRequest (..),
    SessionResponse (..),
    SettingsResponse (..),
    SignupRequest (..),
    TokenRequest (..),
    UpdateEmailTemplatesRequest (..),
    UpdateProvidersRequest (..),
    UpdateUserRequest (..),
    UserId (..),
    UserResponse (..),
    VerifyFactorRequest (..),
    VerifyFactorResponse (..),
    VerifyRequest (..),
    WebhookDeliveriesResponse (..),
    WebhookDeliveryId (..),
    WebhookDeliveryResponse (..),
) where

import Data.Text (Text)
import Data.Time (UTCTime)
import GHC.Generics (Generic)

newtype UserId = UserId {unUserId :: Text}
    deriving stock (Eq, Generic, Ord, Show)

newtype Email = Email {unEmail :: Text}
    deriving stock (Eq, Generic, Ord, Show)

newtype Password = Password {unPassword :: Text}
    deriving stock (Eq, Generic, Show)

newtype FactorId = FactorId {unFactorId :: Text}
    deriving stock (Eq, Generic, Ord, Show)

newtype IdentityId = IdentityId {unIdentityId :: Text}
    deriving stock (Eq, Generic, Ord, Show)

newtype WebhookDeliveryId = WebhookDeliveryId {unWebhookDeliveryId :: Text}
    deriving stock (Eq, Generic, Ord, Show)

newtype HealthResponse = HealthResponse
    { healthStatus :: Text
    }
    deriving stock (Eq, Generic, Show)

data DeepHealthResponse = DeepHealthResponse
    { deepHealthStatus :: Text
    , deepHealthChecks :: [Text]
    }
    deriving stock (Eq, Generic, Show)

data SettingsResponse = SettingsResponse
    { settingsExternalProviders :: [Text]
    , settingsDisableSignup :: Bool
    }
    deriving stock (Eq, Generic, Show)

data SignupRequest = SignupRequest
    { signupEmail :: Email
    , signupPassword :: Password
    , signupUserMetadata :: Maybe Text
    }
    deriving stock (Eq, Generic, Show)

data TokenRequest = TokenRequest
    { tokenEmail :: Maybe Email
    , tokenPassword :: Maybe Password
    , tokenRefreshToken :: Maybe Text
    , tokenCode :: Maybe Text
    }
    deriving stock (Eq, Generic, Show)

newtype RecoverRequest = RecoverRequest
    { recoverEmail :: Email
    }
    deriving stock (Eq, Generic, Show)

data VerifyRequest = VerifyRequest
    { verifyToken :: Text
    , verifyType :: Text
    }
    deriving stock (Eq, Generic, Show)

data ResendRequest = ResendRequest
    { resendEmail :: Email
    , resendType :: Text
    }
    deriving stock (Eq, Generic, Show)

data UpdateUserRequest = UpdateUserRequest
    { updateUserEmail :: Maybe Email
    , updateUserPassword :: Maybe Password
    , updateUserMetadata :: Maybe Text
    }
    deriving stock (Eq, Generic, Show)

data SessionResponse = SessionResponse
    { sessionAccessToken :: Text
    , sessionRefreshToken :: Text
    , sessionExpiresIn :: Int
    , sessionUser :: UserResponse
    }
    deriving stock (Eq, Generic, Show)

data UserResponse = UserResponse
    { userId :: UserId
    , userEmail :: Maybe Email
    , userRole :: Text
    , userCreatedAt :: UTCTime
    }
    deriving stock (Eq, Generic, Show)

newtype MessageResponse = MessageResponse
    { message :: Text
    }
    deriving stock (Eq, Generic, Show)

newtype OAuthAuthorizeResponse = OAuthAuthorizeResponse
    { oauthAuthorizeUrl :: Text
    }
    deriving stock (Eq, Generic, Show)

newtype ListFactorsResponse = ListFactorsResponse
    { listFactors :: [FactorResponse]
    }
    deriving stock (Eq, Generic, Show)

data EnrollFactorRequest = EnrollFactorRequest
    { enrollFactorType :: Text
    , enrollFactorFriendlyName :: Maybe Text
    }
    deriving stock (Eq, Generic, Show)

data FactorResponse = FactorResponse
    { factorId :: FactorId
    , factorType :: Text
    , factorStatus :: Text
    }
    deriving stock (Eq, Generic, Show)

newtype ChallengeFactorRequest = ChallengeFactorRequest
    { challengeFactorChannel :: Maybe Text
    }
    deriving stock (Eq, Generic, Show)

data ChallengeFactorResponse = ChallengeFactorResponse
    { challengeFactorId :: Text
    , challengeExpiresAt :: UTCTime
    }
    deriving stock (Eq, Generic, Show)

data VerifyFactorRequest = VerifyFactorRequest
    { verifyFactorChallengeId :: Text
    , verifyFactorCode :: Text
    }
    deriving stock (Eq, Generic, Show)

newtype VerifyFactorResponse = VerifyFactorResponse
    { verifyFactorSession :: SessionResponse
    }
    deriving stock (Eq, Generic, Show)

newtype ListUsersResponse = ListUsersResponse
    { listUsers :: [UserResponse]
    }
    deriving stock (Eq, Generic, Show)

data AdminCreateUserRequest = AdminCreateUserRequest
    { adminCreateUserEmail :: Email
    , adminCreateUserPassword :: Maybe Password
    , adminCreateUserConfirmed :: Bool
    }
    deriving stock (Eq, Generic, Show)

data AdminUpdateUserRequest = AdminUpdateUserRequest
    { adminUpdateUserEmail :: Maybe Email
    , adminUpdateUserPassword :: Maybe Password
    , adminUpdateUserBannedUntil :: Maybe UTCTime
    }
    deriving stock (Eq, Generic, Show)

newtype DeletedUserResponse = DeletedUserResponse
    { deletedUserId :: UserId
    }
    deriving stock (Eq, Generic, Show)

newtype ListIdentitiesResponse = ListIdentitiesResponse
    { listIdentities :: [Text]
    }
    deriving stock (Eq, Generic, Show)

data GenerateLinkRequest = GenerateLinkRequest
    { generateLinkEmail :: Email
    , generateLinkType :: Text
    }
    deriving stock (Eq, Generic, Show)

newtype GenerateLinkResponse = GenerateLinkResponse
    { generateLinkActionLink :: Text
    }
    deriving stock (Eq, Generic, Show)

newtype InviteUserRequest = InviteUserRequest
    { inviteUserEmail :: Email
    }
    deriving stock (Eq, Generic, Show)

newtype ProvidersResponse = ProvidersResponse
    { providers :: [Text]
    }
    deriving stock (Eq, Generic, Show)

newtype UpdateProvidersRequest = UpdateProvidersRequest
    { updateProviders :: [Text]
    }
    deriving stock (Eq, Generic, Show)

newtype EmailTemplatesResponse = EmailTemplatesResponse
    { emailTemplates :: [Text]
    }
    deriving stock (Eq, Generic, Show)

newtype UpdateEmailTemplatesRequest = UpdateEmailTemplatesRequest
    { updateEmailTemplates :: [Text]
    }
    deriving stock (Eq, Generic, Show)

newtype WebhookDeliveriesResponse = WebhookDeliveriesResponse
    { webhookDeliveries :: [WebhookDeliveryResponse]
    }
    deriving stock (Eq, Generic, Show)

data WebhookDeliveryResponse = WebhookDeliveryResponse
    { webhookDeliveryId :: WebhookDeliveryId
    , webhookDeliveryStatus :: Text
    , webhookDeliveryAttempts :: Int
    }
    deriving stock (Eq, Generic, Show)
