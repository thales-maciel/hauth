module Hauth.API.Types (
    AdminCreateUserRequest (..),
    AdminUpdateUserRequest (..),
    ChallengeFactorRequest (..),
    ChallengeFactorResponse (..),
    CheckOutcome (..),
    DeepHealthCheck (..),
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
    SignupResponse (..),
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
    buildSettingsResponse,
    buildSignupResponse,
) where

import Data.Aeson (FromJSON, ToJSON (toJSON), Value, object, (.=))
import qualified Data.Aeson as Aeson
import Data.Map.Strict (Map)
import qualified Data.Map.Strict as Map
import Data.Text (Text)
import qualified Data.Text as T
import Data.Time (UTCTime)
import Data.UUID (UUID)
import GHC.Generics (Generic)
import Hauth.Config (Config (..), OAuthConfig (..), OAuthProviderConfig (..))
import qualified Hauth.User as User
import Web.HttpApiData (FromHttpApiData, ToHttpApiData)

newtype UserId = UserId {unUserId :: Text}
    deriving stock (Eq, Generic, Ord, Show)
    deriving newtype (FromHttpApiData, FromJSON, ToHttpApiData, ToJSON)

newtype Email = Email {unEmail :: Text}
    deriving stock (Eq, Generic, Ord, Show)
    deriving newtype (FromJSON, ToJSON)

newtype Password = Password {unPassword :: Text}
    deriving stock (Eq, Generic, Show)
    deriving newtype (FromJSON, ToJSON)

newtype FactorId = FactorId {unFactorId :: Text}
    deriving stock (Eq, Generic, Ord, Show)
    deriving newtype (FromHttpApiData, FromJSON, ToHttpApiData, ToJSON)

newtype IdentityId = IdentityId {unIdentityId :: Text}
    deriving stock (Eq, Generic, Ord, Show)
    deriving newtype (FromHttpApiData, FromJSON, ToHttpApiData, ToJSON)

newtype WebhookDeliveryId = WebhookDeliveryId {unWebhookDeliveryId :: Text}
    deriving stock (Eq, Generic, Ord, Show)
    deriving newtype (FromHttpApiData, FromJSON, ToHttpApiData, ToJSON)

newtype HealthResponse = HealthResponse
    { healthStatus :: Text
    }
    deriving stock (Eq, Show)

instance ToJSON HealthResponse where
    toJSON HealthResponse{healthStatus} =
        object ["status" .= healthStatus]

data CheckOutcome
    = CheckOk
    | CheckFailed Text
    deriving stock (Eq, Show)

instance ToJSON CheckOutcome where
    toJSON CheckOk =
        Aeson.String "ok"
    toJSON (CheckFailed reason) =
        object
            [ "status" .= ("failed" :: Text)
            , "reason" .= reason
            ]

data DeepHealthCheck = DeepHealthCheck
    { deepHealthCheckName :: Text
    , deepHealthCheckOutcome :: CheckOutcome
    , deepHealthCheckLatencyMs :: Maybe Int
    }
    deriving stock (Eq, Show)

instance ToJSON DeepHealthCheck where
    toJSON DeepHealthCheck{deepHealthCheckName, deepHealthCheckOutcome, deepHealthCheckLatencyMs} =
        let base =
                [ "name" .= deepHealthCheckName
                , "latency_ms" .= deepHealthCheckLatencyMs
                ]
            statusFields = case deepHealthCheckOutcome of
                CheckOk -> ["status" .= ("ok" :: Text)]
                CheckFailed reason ->
                    [ "status" .= ("failed" :: Text)
                    , "reason" .= reason
                    ]
         in object (base <> statusFields)

data DeepHealthResponse = DeepHealthResponse
    { deepHealthStatus :: Text
    , deepHealthChecks :: [DeepHealthCheck]
    }
    deriving stock (Eq, Show)

instance ToJSON DeepHealthResponse where
    toJSON DeepHealthResponse{deepHealthStatus, deepHealthChecks} =
        object
            [ "status" .= deepHealthStatus
            , "checks" .= deepHealthChecks
            ]

data SettingsResponse = SettingsResponse
    { settingsExternal :: Map Text Bool
    , settingsExternalEmailEnabled :: Bool
    , settingsExternalPhoneEnabled :: Bool
    , settingsDisableSignup :: Bool
    , settingsMailerAutoconfirm :: Bool
    , settingsPhoneAutoconfirm :: Bool
    , settingsSmsProvider :: Text
    }
    deriving stock (Eq, Show)

instance ToJSON SettingsResponse where
    toJSON SettingsResponse{..} =
        object
            [ "external" .= settingsExternal
            , "external_email_enabled" .= settingsExternalEmailEnabled
            , "external_phone_enabled" .= settingsExternalPhoneEnabled
            , "disable_signup" .= settingsDisableSignup
            , "mailer_autoconfirm" .= settingsMailerAutoconfirm
            , "phone_autoconfirm" .= settingsPhoneAutoconfirm
            , "sms_provider" .= settingsSmsProvider
            ]

buildSettingsResponse :: Config -> SettingsResponse
buildSettingsResponse Config{configOAuth = OAuthConfig{oauthProviders}} =
    SettingsResponse
        { settingsExternal = externalMap
        , settingsExternalEmailEnabled = True
        , settingsExternalPhoneEnabled = False
        , settingsDisableSignup = False
        , settingsMailerAutoconfirm = False
        , settingsPhoneAutoconfirm = False
        , settingsSmsProvider = ""
        }
  where
    providerEntries =
        fmap
            (\OAuthProviderConfig{oauthProviderName} -> (T.toLower oauthProviderName, True))
            oauthProviders
    externalMap =
        Map.fromList $
            [("email", True), ("phone", False)]
                <> providerEntries

data SignupRequest = SignupRequest
    { signupEmail :: Email
    , signupPassword :: Password
    , signupData :: Maybe Value
    }
    deriving stock (Eq, Generic, Show)

instance FromJSON SignupRequest where
    parseJSON = Aeson.withObject "SignupRequest" \obj ->
        SignupRequest
            <$> obj Aeson..: "email"
            <*> obj Aeson..: "password"
            <*> obj Aeson..:? "data"

instance ToJSON SignupRequest where
    toJSON SignupRequest{signupEmail, signupPassword, signupData} =
        object
            [ "email" .= signupEmail
            , "password" .= signupPassword
            , "data" .= signupData
            ]

-- | Response body for a successful signup (unconfirmed user, no session).
data SignupResponse = SignupResponse
    { signupResponseId :: UUID
    , signupResponseAud :: Text
    , signupResponseRole :: Text
    , signupResponseEmail :: Maybe Text
    , signupResponseConfirmationSentAt :: Maybe UTCTime
    , signupResponseCreatedAt :: UTCTime
    , signupResponseUpdatedAt :: UTCTime
    , signupResponseAppMetadata :: Value
    , signupResponseUserMetadata :: Value
    }
    deriving stock (Eq, Show)

instance ToJSON SignupResponse where
    toJSON SignupResponse{..} =
        object
            [ "id" .= signupResponseId
            , "aud" .= signupResponseAud
            , "role" .= signupResponseRole
            , "email" .= signupResponseEmail
            , "confirmation_sent_at" .= signupResponseConfirmationSentAt
            , "created_at" .= signupResponseCreatedAt
            , "updated_at" .= signupResponseUpdatedAt
            , "app_metadata" .= signupResponseAppMetadata
            , "user_metadata" .= signupResponseUserMetadata
            ]

-- | Convert a persisted 'User.User' to a 'SignupResponse'.
buildSignupResponse :: User.User -> SignupResponse
buildSignupResponse User.User{..} =
    SignupResponse
        { signupResponseId = User.unUserId userId
        , signupResponseAud = userAud
        , signupResponseRole = userRole
        , signupResponseEmail = userEmail
        , signupResponseConfirmationSentAt = userConfirmationSentAt
        , signupResponseCreatedAt = userCreatedAt
        , signupResponseUpdatedAt = userUpdatedAt
        , signupResponseAppMetadata = userRawAppMetaData
        , signupResponseUserMetadata = userRawUserMetaData
        }

data TokenRequest = TokenRequest
    { tokenEmail :: Maybe Email
    , tokenPassword :: Maybe Password
    , tokenRefreshToken :: Maybe Text
    , tokenCode :: Maybe Text
    }
    deriving stock (Eq, Generic, Show)
    deriving anyclass (FromJSON, ToJSON)

newtype RecoverRequest = RecoverRequest
    { recoverEmail :: Email
    }
    deriving stock (Eq, Generic, Show)
    deriving anyclass (FromJSON, ToJSON)

data VerifyRequest = VerifyRequest
    { verifyToken :: Text
    , verifyType :: Text
    }
    deriving stock (Eq, Generic, Show)
    deriving anyclass (FromJSON, ToJSON)

data ResendRequest = ResendRequest
    { resendEmail :: Email
    , resendType :: Text
    }
    deriving stock (Eq, Generic, Show)
    deriving anyclass (FromJSON, ToJSON)

data UpdateUserRequest = UpdateUserRequest
    { updateUserEmail :: Maybe Email
    , updateUserPassword :: Maybe Password
    , updateUserMetadata :: Maybe Text
    }
    deriving stock (Eq, Generic, Show)
    deriving anyclass (FromJSON, ToJSON)

data SessionResponse = SessionResponse
    { sessionAccessToken :: Text
    , sessionRefreshToken :: Text
    , sessionExpiresIn :: Int
    , sessionUser :: UserResponse
    }
    deriving stock (Eq, Generic, Show)
    deriving anyclass (FromJSON, ToJSON)

data UserResponse = UserResponse
    { userId :: UserId
    , userEmail :: Maybe Email
    , userRole :: Text
    , userCreatedAt :: UTCTime
    }
    deriving stock (Eq, Generic, Show)
    deriving anyclass (FromJSON, ToJSON)

newtype MessageResponse = MessageResponse
    { message :: Text
    }
    deriving stock (Eq, Generic, Show)
    deriving anyclass (FromJSON, ToJSON)

newtype OAuthAuthorizeResponse = OAuthAuthorizeResponse
    { oauthAuthorizeUrl :: Text
    }
    deriving stock (Eq, Generic, Show)
    deriving anyclass (FromJSON, ToJSON)

newtype ListFactorsResponse = ListFactorsResponse
    { listFactors :: [FactorResponse]
    }
    deriving stock (Eq, Generic, Show)
    deriving anyclass (FromJSON, ToJSON)

data EnrollFactorRequest = EnrollFactorRequest
    { enrollFactorType :: Text
    , enrollFactorFriendlyName :: Maybe Text
    }
    deriving stock (Eq, Generic, Show)
    deriving anyclass (FromJSON, ToJSON)

data FactorResponse = FactorResponse
    { factorId :: FactorId
    , factorType :: Text
    , factorStatus :: Text
    }
    deriving stock (Eq, Generic, Show)
    deriving anyclass (FromJSON, ToJSON)

newtype ChallengeFactorRequest = ChallengeFactorRequest
    { challengeFactorChannel :: Maybe Text
    }
    deriving stock (Eq, Generic, Show)
    deriving anyclass (FromJSON, ToJSON)

data ChallengeFactorResponse = ChallengeFactorResponse
    { challengeFactorId :: Text
    , challengeExpiresAt :: UTCTime
    }
    deriving stock (Eq, Generic, Show)
    deriving anyclass (FromJSON, ToJSON)

data VerifyFactorRequest = VerifyFactorRequest
    { verifyFactorChallengeId :: Text
    , verifyFactorCode :: Text
    }
    deriving stock (Eq, Generic, Show)
    deriving anyclass (FromJSON, ToJSON)

newtype VerifyFactorResponse = VerifyFactorResponse
    { verifyFactorSession :: SessionResponse
    }
    deriving stock (Eq, Generic, Show)
    deriving anyclass (FromJSON, ToJSON)

newtype ListUsersResponse = ListUsersResponse
    { listUsers :: [UserResponse]
    }
    deriving stock (Eq, Generic, Show)
    deriving anyclass (FromJSON, ToJSON)

data AdminCreateUserRequest = AdminCreateUserRequest
    { adminCreateUserEmail :: Email
    , adminCreateUserPassword :: Maybe Password
    , adminCreateUserConfirmed :: Bool
    }
    deriving stock (Eq, Generic, Show)
    deriving anyclass (FromJSON, ToJSON)

data AdminUpdateUserRequest = AdminUpdateUserRequest
    { adminUpdateUserEmail :: Maybe Email
    , adminUpdateUserPassword :: Maybe Password
    , adminUpdateUserBannedUntil :: Maybe UTCTime
    }
    deriving stock (Eq, Generic, Show)
    deriving anyclass (FromJSON, ToJSON)

newtype DeletedUserResponse = DeletedUserResponse
    { deletedUserId :: UserId
    }
    deriving stock (Eq, Generic, Show)
    deriving anyclass (FromJSON, ToJSON)

newtype ListIdentitiesResponse = ListIdentitiesResponse
    { listIdentities :: [Text]
    }
    deriving stock (Eq, Generic, Show)
    deriving anyclass (FromJSON, ToJSON)

data GenerateLinkRequest = GenerateLinkRequest
    { generateLinkEmail :: Email
    , generateLinkType :: Text
    }
    deriving stock (Eq, Generic, Show)
    deriving anyclass (FromJSON, ToJSON)

newtype GenerateLinkResponse = GenerateLinkResponse
    { generateLinkActionLink :: Text
    }
    deriving stock (Eq, Generic, Show)
    deriving anyclass (FromJSON, ToJSON)

newtype InviteUserRequest = InviteUserRequest
    { inviteUserEmail :: Email
    }
    deriving stock (Eq, Generic, Show)
    deriving anyclass (FromJSON, ToJSON)

newtype ProvidersResponse = ProvidersResponse
    { providers :: [Text]
    }
    deriving stock (Eq, Generic, Show)
    deriving anyclass (FromJSON, ToJSON)

newtype UpdateProvidersRequest = UpdateProvidersRequest
    { updateProviders :: [Text]
    }
    deriving stock (Eq, Generic, Show)
    deriving anyclass (FromJSON, ToJSON)

newtype EmailTemplatesResponse = EmailTemplatesResponse
    { emailTemplates :: [Text]
    }
    deriving stock (Eq, Generic, Show)
    deriving anyclass (FromJSON, ToJSON)

newtype UpdateEmailTemplatesRequest = UpdateEmailTemplatesRequest
    { updateEmailTemplates :: [Text]
    }
    deriving stock (Eq, Generic, Show)
    deriving anyclass (FromJSON, ToJSON)

newtype WebhookDeliveriesResponse = WebhookDeliveriesResponse
    { webhookDeliveries :: [WebhookDeliveryResponse]
    }
    deriving stock (Eq, Generic, Show)
    deriving anyclass (FromJSON, ToJSON)

data WebhookDeliveryResponse = WebhookDeliveryResponse
    { webhookDeliveryId :: WebhookDeliveryId
    , webhookDeliveryStatus :: Text
    , webhookDeliveryAttempts :: Int
    }
    deriving stock (Eq, Generic, Show)
    deriving anyclass (FromJSON, ToJSON)
