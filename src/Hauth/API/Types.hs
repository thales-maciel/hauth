module Hauth.API.Types (
    AdminCreateUserRequest (..),
    AdminUpdateUserRequest (..),
    ChallengeFactorRequest (..),
    ChallengeFactorResponse (..),
    CheckOutcome (..),
    CreateWebhookSubscriptionRequest (..),
    DeepHealthCheck (..),
    DeepHealthResponse (..),
    DeletedUserResponse (..),
    Email (..),
    EmailTemplateCrudRequest (..),
    EmailTemplateRow (..),
    EmailTemplatesListResponse (..),
    EmailTemplatesResponse (..),
    EnrollError (..),
    EnrollFactorRequest (..),
    FactorId (..),
    FactorResponse (..),
    FactorTotpData (..),
    GenerateLinkRequest (..),
    GenerateLinkResponse (..),
    CreateHookRequest (..),
    GrantType (..),
    HealthResponse (..),
    HookId (..),
    HookRow (..),
    IdentityId (..),
    IdentityResponse (..),
    InviteUserRequest (..),
    ListFactorsResponse (..),
    ListIdentitiesResponse (..),
    ListUsersResponse (..),
    ListWebhookSubscriptionsResponse (..),
    MessageResponse (..),
    OAuthAuthorizeResponse (..),
    Password (..),
    ProvidersResponse (..),
    RecoverRequest (..),
    RefreshTokenError (..),
    ResendRequest (..),
    SessionResponse (..),
    SettingsResponse (..),
    SignupRequest (..),
    SignupResponse (..),
    TokenRequest (..),
    TokenResponse (..),
    ListHooksResponse (..),
    UpdateEmailTemplatesRequest (..),
    UpdateHookRequest (..),
    UpdateProvidersRequest (..),
    UpdateUserRequest (..),
    UpdateWebhookSubscriptionRequest (..),
    UserId (..),
    UserResponse (..),
    ValidRefreshToken (..),
    VerifyFactorRequest (..),
    VerifyFactorResponse (..),
    VerifyRequest (..),
    ListWebhookDeliveriesResponse (..),
    WebhookDeliveriesResponse (..),
    WebhookDeliveryId (..),
    WebhookDeliveryResponse (..),
    WebhookSubscriptionId (..),
    WebhookSubscriptionResponse (..),
    buildFactorResponse,
    buildIdentityResponse,
    buildSessionResponse,
    buildSettingsResponse,
    buildSignupResponse,
    buildUserResponse,
    classifyRefreshTokenLookup,
    parseGrantType,
    validateEnrollRequest,
) where

import Data.Aeson (FromJSON (..), ToJSON (toJSON), Value, object, withObject, (.:?), (.=))
import qualified Data.Aeson as Aeson
import Data.Map.Strict (Map)
import qualified Data.Map.Strict as Map
import Data.Text (Text)
import qualified Data.Text as T
import Data.Time (UTCTime)
import Data.UUID (UUID)
import qualified Data.UUID as UUID
import GHC.Generics (Generic)
import Hauth.Config (Config (..), OAuthConfig (..), OAuthProviderConfig (..))
import Hauth.Hooks.Types (HookPoint, hookPointName, parseHookPoint)
import qualified Hauth.Identity as Identity
import Hauth.Session (RefreshToken (..))
import qualified Hauth.User as User
import Web.HttpApiData (FromHttpApiData, ToHttpApiData)

newtype UserId = UserId {unUserId :: Text}
    deriving stock (Eq, Generic, Ord, Show)
    deriving newtype (FromHttpApiData, FromJSON, ToHttpApiData, ToJSON)

newtype Email = Email {unEmail :: Text}
    deriving stock (Eq, Generic, Ord, Show)
    deriving newtype (FromJSON, ToJSON, FromHttpApiData, ToHttpApiData)

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

newtype HookId = HookId {unHookId :: Text}
    deriving stock (Eq, Generic, Ord, Show)
    deriving newtype (FromHttpApiData, FromJSON, ToHttpApiData, ToJSON)

newtype HealthResponse = HealthResponse
    { healthStatus :: Text
    }
    deriving stock (Eq, Show)

instance ToJSON HealthResponse where
    toJSON HealthResponse{healthStatus} =
        object ["status" .= healthStatus]

{- | Outcome of one deep-health component check.

The @\"degraded\"@ status is reserved for optional components that failed
but should not flip the overall response to @\"unhealthy\"@ / 503. See
'Hauth.Server.Health.aggregateStatus' and the @\"Background services\"@
section of @docs\/PRODUCTION.md@ for the policy.
-}
data CheckOutcome
    = CheckOk
    | CheckFailed Text
    | CheckDegraded Text
    deriving stock (Eq, Show)

instance ToJSON CheckOutcome where
    toJSON CheckOk =
        Aeson.String "ok"
    toJSON (CheckFailed reason) =
        object
            [ "status" .= ("failed" :: Text)
            , "reason" .= reason
            ]
    toJSON (CheckDegraded reason) =
        object
            [ "status" .= ("degraded" :: Text)
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
                CheckDegraded reason ->
                    [ "status" .= ("degraded" :: Text)
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

-- | Assemble a 'SessionResponse' from its components.
buildSessionResponse :: Text -> Text -> Int -> UserResponse -> SessionResponse
buildSessionResponse accessToken refreshToken expiresIn userResp =
    SessionResponse
        { sessionAccessToken = accessToken
        , sessionRefreshToken = refreshToken
        , sessionExpiresIn = expiresIn
        , sessionUser = userResp
        }

{- | Unified request body for the @/token@ endpoint across all grant types.

Fields are all optional at the type level; the handler inspects @grant_type@
and validates that the required fields for the chosen grant are present.
Unknown JSON keys are silently ignored for forward compatibility.
-}
data TokenRequest = TokenRequest
    { tokenRequestRefreshToken :: Maybe Text
    -- ^ Used by @grant_type=refresh_token@.
    , tokenRequestEmail :: Maybe Email
    -- ^ Used by @grant_type=password@ (handled in issue #12).
    , tokenRequestPassword :: Maybe Password
    -- ^ Used by @grant_type=password@ (handled in issue #12).
    }
    deriving stock (Eq, Show)

instance FromJSON TokenRequest where
    parseJSON = withObject "TokenRequest" \o ->
        TokenRequest
            <$> o .:? "refresh_token"
            <*> o .:? "email"
            <*> o .:? "password"

-- | Discriminated grant type parsed from the @grant_type@ query parameter.
data GrantType
    = GrantRefreshToken
    | GrantPassword
    | GrantUnsupported Text
    deriving stock (Eq, Show)

-- | Parse the @grant_type@ query parameter into a 'GrantType'.
parseGrantType :: Maybe Text -> GrantType
parseGrantType (Just "refresh_token") = GrantRefreshToken
parseGrantType (Just "password") = GrantPassword
parseGrantType (Just other) = GrantUnsupported other
parseGrantType Nothing = GrantUnsupported ""

-- | Error outcomes from inspecting a looked-up refresh token.
data RefreshTokenError
    = -- | Token was not found in the database at all.
      InvalidGrant
    | -- | Token was found but is already revoked — reuse attack detected.
      RefreshTokenReuseDetected
    deriving stock (Eq, Show)

-- | A refresh token that has been verified as valid (present and not revoked).
newtype ValidRefreshToken = ValidRefreshToken {unValidRefreshToken :: RefreshToken}
    deriving stock (Eq, Show)

{- | Classify the result of a raw refresh token lookup into either an error or
a valid token.

- 'Nothing' → 'Left' 'InvalidGrant' (token not found).
- 'Just' rt where 'refreshTokenRevoked' is 'True' → 'Left' 'RefreshTokenReuseDetected'.
- 'Just' rt where 'refreshTokenRevoked' is 'False' → 'Right' ('ValidRefreshToken' rt).
-}
classifyRefreshTokenLookup :: Maybe RefreshToken -> Either RefreshTokenError ValidRefreshToken
classifyRefreshTokenLookup Nothing = Left InvalidGrant
classifyRefreshTokenLookup (Just rt)
    | refreshTokenRevoked rt = Left RefreshTokenReuseDetected
    | otherwise = Right (ValidRefreshToken rt)

-- | Response body for a successful token rotation (and password grant).
data TokenResponse = TokenResponse
    { tokenResponseAccessToken :: Text
    , tokenResponseTokenType :: Text
    -- ^ Always @"bearer"@.
    , tokenResponseExpiresIn :: Int
    , tokenResponseRefreshToken :: Text
    , tokenResponseUser :: Value
    -- ^ Embedded user object; shape matches Supabase contract.
    }
    deriving stock (Eq, Show)

instance ToJSON TokenResponse where
    toJSON TokenResponse{..} =
        object
            [ "access_token" .= tokenResponseAccessToken
            , "token_type" .= tokenResponseTokenType
            , "expires_in" .= tokenResponseExpiresIn
            , "refresh_token" .= tokenResponseRefreshToken
            , "user" .= tokenResponseUser
            ]

newtype RecoverRequest = RecoverRequest
    { recoverEmail :: Email
    }
    deriving stock (Eq, Generic, Show)

instance FromJSON RecoverRequest where
    parseJSON = Aeson.withObject "RecoverRequest" \o ->
        RecoverRequest <$> o Aeson..: "email"

instance ToJSON RecoverRequest where
    toJSON (RecoverRequest email) = Aeson.object ["email" Aeson..= email]

data VerifyRequest = VerifyRequest
    { verifyToken :: Text
    , verifyType :: Text
    , verifyEmail :: Maybe Text
    , verifyPassword :: Maybe Text
    }
    deriving stock (Eq, Generic, Show)

instance FromJSON VerifyRequest where
    parseJSON = Aeson.withObject "VerifyRequest" \o ->
        VerifyRequest
            <$> o Aeson..: "token"
            <*> o Aeson..: "type"
            <*> o Aeson..:? "email"
            <*> o Aeson..:? "password"

instance ToJSON VerifyRequest where
    toJSON VerifyRequest{verifyToken, verifyType, verifyEmail, verifyPassword} =
        object
            [ "token" .= verifyToken
            , "type" .= verifyType
            , "email" .= verifyEmail
            , "password" .= verifyPassword
            ]

data ResendRequest = ResendRequest
    { resendEmail :: Email
    , resendType :: Text
    }
    deriving stock (Eq, Generic, Show)

instance FromJSON ResendRequest where
    parseJSON = Aeson.withObject "ResendRequest" \o ->
        ResendRequest
            <$> o Aeson..: "email"
            <*> o Aeson..: "type"

instance ToJSON ResendRequest where
    toJSON ResendRequest{resendEmail, resendType} =
        object
            [ "email" .= resendEmail
            , "type" .= resendType
            ]

data UpdateUserRequest = UpdateUserRequest
    { updateUserEmail :: Maybe Email
    , updateUserPassword :: Maybe Password
    , updateUserData :: Maybe Value
    -- ^ User metadata; replaces @raw_user_meta_data@ entirely for v0.1.
    }
    deriving stock (Eq, Generic, Show)

instance FromJSON UpdateUserRequest where
    parseJSON = Aeson.withObject "UpdateUserRequest" \obj ->
        UpdateUserRequest
            <$> obj Aeson..:? "email"
            <*> obj Aeson..:? "password"
            <*> obj Aeson..:? "data"

instance ToJSON UpdateUserRequest where
    toJSON UpdateUserRequest{updateUserEmail, updateUserPassword, updateUserData} =
        object
            [ "email" .= updateUserEmail
            , "password" .= updateUserPassword
            , "data" .= updateUserData
            ]

data SessionResponse = SessionResponse
    { sessionAccessToken :: Text
    , sessionRefreshToken :: Text
    , sessionExpiresIn :: Int
    , sessionUser :: UserResponse
    }
    deriving stock (Eq, Generic, Show)

instance ToJSON SessionResponse where
    toJSON SessionResponse{..} =
        object
            [ "access_token" .= sessionAccessToken
            , "token_type" .= ("bearer" :: Text)
            , "expires_in" .= sessionExpiresIn
            , "refresh_token" .= sessionRefreshToken
            , "user" .= sessionUser
            ]

instance FromJSON SessionResponse where
    parseJSON = Aeson.withObject "SessionResponse" \o ->
        SessionResponse
            <$> o Aeson..: "access_token"
            <*> o Aeson..: "refresh_token"
            <*> o Aeson..: "expires_in"
            <*> o Aeson..: "user"

{- | Full user object matching the Supabase @/user@ response contract.

The JSON serialisation uses snake_case keys to match the Supabase wire format.
-}
data UserResponse = UserResponse
    { userResponseId :: UUID
    , userResponseAud :: Text
    , userResponseRole :: Text
    , userResponseEmail :: Maybe Text
    , userResponseEmailConfirmedAt :: Maybe UTCTime
    , userResponseCreatedAt :: UTCTime
    , userResponseUpdatedAt :: UTCTime
    , userResponseAppMetadata :: Value
    , userResponseUserMetadata :: Value
    }
    deriving stock (Eq, Generic, Show)

instance ToJSON UserResponse where
    toJSON UserResponse{..} =
        object
            [ "id" .= userResponseId
            , "aud" .= userResponseAud
            , "role" .= userResponseRole
            , "email" .= userResponseEmail
            , "email_confirmed_at" .= userResponseEmailConfirmedAt
            , "created_at" .= userResponseCreatedAt
            , "updated_at" .= userResponseUpdatedAt
            , "app_metadata" .= userResponseAppMetadata
            , "user_metadata" .= userResponseUserMetadata
            ]

instance FromJSON UserResponse where
    parseJSON = Aeson.withObject "UserResponse" \obj ->
        UserResponse
            <$> obj Aeson..: "id"
            <*> obj Aeson..: "aud"
            <*> obj Aeson..: "role"
            <*> obj Aeson..:? "email"
            <*> obj Aeson..:? "email_confirmed_at"
            <*> obj Aeson..: "created_at"
            <*> obj Aeson..: "updated_at"
            <*> obj Aeson..: "app_metadata"
            <*> obj Aeson..: "user_metadata"

buildUserResponse :: User.User -> UserResponse
buildUserResponse User.User{..} =
    UserResponse
        { userResponseId = User.unUserId userId
        , userResponseAud = userAud
        , userResponseRole = userRole
        , userResponseEmail = userEmail
        , userResponseEmailConfirmedAt = userEmailConfirmedAt
        , userResponseCreatedAt = userCreatedAt
        , userResponseUpdatedAt = userUpdatedAt
        , userResponseAppMetadata = userRawAppMetaData
        , userResponseUserMetadata = userRawUserMetaData
        }

newtype MessageResponse = MessageResponse
    { message :: Text
    }
    deriving stock (Eq, Generic, Show)

instance ToJSON MessageResponse where
    toJSON MessageResponse{message} =
        object ["message" .= message]

instance FromJSON MessageResponse where
    parseJSON = Aeson.withObject "MessageResponse" \o ->
        MessageResponse <$> o Aeson..: "message"

data OAuthAuthorizeResponse = OAuthAuthorizeResponse
    { oauthAuthorizeUrl :: Text
    , oauthAuthorizeState :: Text
    }
    deriving stock (Eq, Generic, Show)

instance ToJSON OAuthAuthorizeResponse where
    toJSON OAuthAuthorizeResponse{oauthAuthorizeUrl, oauthAuthorizeState} =
        object
            [ "url" .= oauthAuthorizeUrl
            , "state" .= oauthAuthorizeState
            ]

instance FromJSON OAuthAuthorizeResponse where
    parseJSON = Aeson.withObject "OAuthAuthorizeResponse" \o ->
        OAuthAuthorizeResponse
            <$> o Aeson..: "url"
            <*> o Aeson..: "state"

{- | Top-level response for @GET /factors@.

Matches the Supabase contract: all factors in @factors@, only verified TOTP
factors in @totp@, and an empty @phone@ list (phone not supported in v0.1).
-}
data ListFactorsResponse = ListFactorsResponse
    { listFactorsAll :: [FactorResponse]
    , listFactorsTotp :: [FactorResponse]
    , listFactorsPhone :: [Value]
    }
    deriving stock (Eq, Generic, Show)

instance ToJSON ListFactorsResponse where
    toJSON ListFactorsResponse{listFactorsAll, listFactorsTotp, listFactorsPhone} =
        object
            [ "factors" .= listFactorsAll
            , "totp" .= listFactorsTotp
            , "phone" .= listFactorsPhone
            ]

instance FromJSON ListFactorsResponse where
    parseJSON = Aeson.withObject "ListFactorsResponse" \o ->
        ListFactorsResponse
            <$> o Aeson..: "factors"
            <*> o Aeson..: "totp"
            <*> o Aeson..:? "phone" Aeson..!= []

-- | Request body for @POST /factors@.
data EnrollFactorRequest = EnrollFactorRequest
    { enrollFactorType :: Text
    , enrollFactorFriendlyName :: Maybe Text
    , enrollFactorIssuer :: Maybe Text
    }
    deriving stock (Eq, Generic, Show)

instance FromJSON EnrollFactorRequest where
    parseJSON = Aeson.withObject "EnrollFactorRequest" \o ->
        EnrollFactorRequest
            <$> o Aeson..: "factor_type"
            <*> o Aeson..:? "friendly_name"
            <*> o Aeson..:? "issuer"

instance ToJSON EnrollFactorRequest where
    toJSON EnrollFactorRequest{enrollFactorType, enrollFactorFriendlyName, enrollFactorIssuer} =
        object
            [ "factor_type" .= enrollFactorType
            , "friendly_name" .= enrollFactorFriendlyName
            , "issuer" .= enrollFactorIssuer
            ]

{- | TOTP-specific data embedded in a 'FactorResponse'.

For v0.1, @qr_code@ is the same otpauth URI as @uri@ — not an actual
PNG or SVG.  Rendering to an image is a frontend concern; Supabase clients
do the same.
-}
data FactorTotpData = FactorTotpData
    { factorTotpQrCode :: Text
    -- ^ @otpauth://@ URI (text, not image, for v0.1).
    , factorTotpSecret :: Text
    -- ^ BASE32-encoded secret.
    , factorTotpUri :: Text
    -- ^ Same @otpauth://@ URI.
    }
    deriving stock (Eq, Generic, Show)

instance ToJSON FactorTotpData where
    toJSON FactorTotpData{factorTotpQrCode, factorTotpSecret, factorTotpUri} =
        object
            [ "qr_code" .= factorTotpQrCode
            , "secret" .= factorTotpSecret
            , "uri" .= factorTotpUri
            ]

instance FromJSON FactorTotpData where
    parseJSON = Aeson.withObject "FactorTotpData" \o ->
        FactorTotpData
            <$> o Aeson..: "qr_code"
            <*> o Aeson..: "secret"
            <*> o Aeson..: "uri"

-- | Response body for a factor (enroll or list element).
data FactorResponse = FactorResponse
    { factorResponseId :: FactorId
    , factorResponseType :: Text
    , factorResponseFriendlyName :: Maybe Text
    , factorResponseStatus :: Text
    , factorResponseTotp :: Maybe FactorTotpData
    }
    deriving stock (Eq, Generic, Show)

instance ToJSON FactorResponse where
    toJSON FactorResponse{factorResponseId, factorResponseType, factorResponseFriendlyName, factorResponseStatus, factorResponseTotp} =
        object
            [ "id" .= factorResponseId
            , "type" .= factorResponseType
            , "friendly_name" .= factorResponseFriendlyName
            , "status" .= factorResponseStatus
            , "totp" .= factorResponseTotp
            ]

instance FromJSON FactorResponse where
    parseJSON = Aeson.withObject "FactorResponse" \o ->
        FactorResponse
            <$> o Aeson..: "id"
            <*> o Aeson..: "type"
            <*> o Aeson..:? "friendly_name"
            <*> o Aeson..: "status"
            <*> o Aeson..:? "totp"

-- | Errors from validating an enroll request.
newtype EnrollError
    = EnrollUnsupportedFactorType Text
    deriving stock (Eq, Show)

-- | Validate that the requested factor type is supported.
validateEnrollRequest :: EnrollFactorRequest -> Either EnrollError ()
validateEnrollRequest EnrollFactorRequest{enrollFactorType}
    | enrollFactorType == "totp" = Right ()
    | otherwise = Left (EnrollUnsupportedFactorType enrollFactorType)

{- | Build a 'FactorResponse' from a fresh 'MfaFactor' and the computed URI.

Imported from "Hauth.MfaFactor" by the Server module; re-exported here for
testability.  We use UUID text for the 'FactorId' wrapper.
-}
buildFactorResponse ::
    -- | Factor UUID
    UUID ->
    -- | Factor type string (@"totp"@)
    Text ->
    -- | Friendly name
    Maybe Text ->
    -- | Status string (@"unverified"@)
    Text ->
    -- | BASE32 secret
    Text ->
    -- | otpauth URI
    Text ->
    FactorResponse
buildFactorResponse fid ftype fname fstatus secret uri =
    FactorResponse
        { factorResponseId = FactorId (UUID.toText fid)
        , factorResponseType = ftype
        , factorResponseFriendlyName = fname
        , factorResponseStatus = fstatus
        , factorResponseTotp =
            Just
                FactorTotpData
                    { factorTotpQrCode = uri
                    , factorTotpSecret = secret
                    , factorTotpUri = uri
                    }
        }

newtype ChallengeFactorRequest = ChallengeFactorRequest
    { challengeFactorChannel :: Maybe Text
    }
    deriving stock (Eq, Generic, Show)

instance FromJSON ChallengeFactorRequest where
    parseJSON = Aeson.withObject "ChallengeFactorRequest" \o ->
        ChallengeFactorRequest <$> o Aeson..:? "channel"

instance ToJSON ChallengeFactorRequest where
    toJSON ChallengeFactorRequest{challengeFactorChannel} =
        object ["channel" .= challengeFactorChannel]

data ChallengeFactorResponse = ChallengeFactorResponse
    { challengeFactorId :: Text
    , challengeExpiresAt :: UTCTime
    }
    deriving stock (Eq, Generic, Show)

instance ToJSON ChallengeFactorResponse where
    toJSON ChallengeFactorResponse{challengeFactorId, challengeExpiresAt} =
        object
            [ "id" .= challengeFactorId
            , "type" .= ("totp" :: Text)
            , "expires_at" .= challengeExpiresAt
            ]

instance FromJSON ChallengeFactorResponse where
    parseJSON = withObject "ChallengeFactorResponse" \o ->
        ChallengeFactorResponse
            <$> o Aeson..: "id"
            <*> o Aeson..: "expires_at"

data VerifyFactorRequest = VerifyFactorRequest
    { verifyFactorChallengeId :: Text
    , verifyFactorCode :: Text
    }
    deriving stock (Eq, Generic, Show)

instance FromJSON VerifyFactorRequest where
    parseJSON = Aeson.withObject "VerifyFactorRequest" \o ->
        VerifyFactorRequest
            <$> o Aeson..: "challenge_id"
            <*> o Aeson..: "code"

instance ToJSON VerifyFactorRequest where
    toJSON (VerifyFactorRequest cid code) =
        Aeson.object ["challenge_id" Aeson..= cid, "code" Aeson..= code]

newtype VerifyFactorResponse = VerifyFactorResponse
    { verifyFactorSession :: SessionResponse
    }
    deriving stock (Eq, Generic, Show)

-- | Serialise as a flat session object (Supabase wire format).
instance ToJSON VerifyFactorResponse where
    toJSON (VerifyFactorResponse sess) = toJSON sess

instance FromJSON VerifyFactorResponse where
    parseJSON v = VerifyFactorResponse <$> parseJSON v

data ListUsersResponse = ListUsersResponse
    { listUsers :: [UserResponse]
    , listUsersAud :: Text
    , listUsersNextPage :: Maybe Int
    }
    deriving stock (Eq, Generic, Show)

instance ToJSON ListUsersResponse where
    toJSON ListUsersResponse{listUsers, listUsersAud, listUsersNextPage} =
        object
            [ "users" .= listUsers
            , "aud" .= listUsersAud
            , "next_page" .= listUsersNextPage
            ]

instance FromJSON ListUsersResponse where
    parseJSON = Aeson.withObject "ListUsersResponse" \o ->
        ListUsersResponse
            <$> o Aeson..: "users"
            <*> o Aeson..: "aud"
            <*> o Aeson..:? "next_page"

data AdminCreateUserRequest = AdminCreateUserRequest
    { adminCreateUserEmail :: Email
    , adminCreateUserPassword :: Maybe Password
    -- ^ Optional: if absent a random temporary password is generated.
    , adminCreateUserConfirmed :: Bool
    -- ^ If 'True', set @email_confirmed_at = now()@.
    , adminCreateUserUserMetadata :: Maybe Value
    , adminCreateUserAppMetadata :: Maybe Value
    }
    deriving stock (Eq, Generic, Show)

instance FromJSON AdminCreateUserRequest where
    parseJSON = Aeson.withObject "AdminCreateUserRequest" \o ->
        AdminCreateUserRequest
            <$> o Aeson..: "email"
            <*> o Aeson..:? "password"
            <*> (o Aeson..:? "email_confirm" Aeson..!= False)
            <*> o Aeson..:? "user_metadata"
            <*> o Aeson..:? "app_metadata"

instance ToJSON AdminCreateUserRequest where
    toJSON AdminCreateUserRequest{..} =
        object
            [ "email" .= adminCreateUserEmail
            , "password" .= adminCreateUserPassword
            , "email_confirm" .= adminCreateUserConfirmed
            , "user_metadata" .= adminCreateUserUserMetadata
            , "app_metadata" .= adminCreateUserAppMetadata
            ]

data AdminUpdateUserRequest = AdminUpdateUserRequest
    { adminUpdateUserEmail :: Maybe Email
    , adminUpdateUserPassword :: Maybe Password
    , adminUpdateUserEmailConfirm :: Maybe Bool
    -- ^ If 'Just True', confirm email; 'Just False' un-confirms; 'Nothing' leaves untouched.
    , adminUpdateUserBannedUntil :: Maybe UTCTime
    , adminUpdateUserRole :: Maybe Text
    , adminUpdateUserUserMetadata :: Maybe Value
    , adminUpdateUserAppMetadata :: Maybe Value
    }
    deriving stock (Eq, Generic, Show)

instance FromJSON AdminUpdateUserRequest where
    parseJSON = Aeson.withObject "AdminUpdateUserRequest" \o ->
        AdminUpdateUserRequest
            <$> o Aeson..:? "email"
            <*> o Aeson..:? "password"
            <*> o Aeson..:? "email_confirm"
            <*> o Aeson..:? "banned_until"
            <*> o Aeson..:? "role"
            <*> o Aeson..:? "user_metadata"
            <*> o Aeson..:? "app_metadata"

instance ToJSON AdminUpdateUserRequest where
    toJSON AdminUpdateUserRequest{..} =
        object
            [ "email" .= adminUpdateUserEmail
            , "password" .= adminUpdateUserPassword
            , "email_confirm" .= adminUpdateUserEmailConfirm
            , "banned_until" .= adminUpdateUserBannedUntil
            , "role" .= adminUpdateUserRole
            , "user_metadata" .= adminUpdateUserUserMetadata
            , "app_metadata" .= adminUpdateUserAppMetadata
            ]

newtype DeletedUserResponse = DeletedUserResponse
    { deletedUser :: UserResponse
    }
    deriving stock (Eq, Generic, Show)

instance ToJSON DeletedUserResponse where
    toJSON DeletedUserResponse{deletedUser} =
        object ["user" .= deletedUser]

instance FromJSON DeletedUserResponse where
    parseJSON = Aeson.withObject "DeletedUserResponse" \o ->
        DeletedUserResponse <$> o Aeson..: "user"

-- | Wire representation of an identity row for API responses.
data IdentityResponse = IdentityResponse
    { identityResponseId :: Text
    , identityResponseUserId :: UUID
    , identityResponseProvider :: Text
    , identityResponseProviderId :: Text
    , identityResponseIdentityData :: Value
    , identityResponseEmail :: Maybe Text
    , identityResponseCreatedAt :: UTCTime
    , identityResponseUpdatedAt :: UTCTime
    , identityResponseLastSignInAt :: Maybe UTCTime
    }
    deriving stock (Eq, Show)

instance ToJSON IdentityResponse where
    toJSON IdentityResponse{..} =
        object
            [ "id" .= identityResponseId
            , "user_id" .= identityResponseUserId
            , "provider" .= identityResponseProvider
            , "provider_id" .= identityResponseProviderId
            , "identity_data" .= identityResponseIdentityData
            , "email" .= identityResponseEmail
            , "created_at" .= identityResponseCreatedAt
            , "updated_at" .= identityResponseUpdatedAt
            , "last_sign_in_at" .= identityResponseLastSignInAt
            ]

instance FromJSON IdentityResponse where
    parseJSON = Aeson.withObject "IdentityResponse" \o ->
        IdentityResponse
            <$> o Aeson..: "id"
            <*> o Aeson..: "user_id"
            <*> o Aeson..: "provider"
            <*> o Aeson..: "provider_id"
            <*> o Aeson..: "identity_data"
            <*> o Aeson..:? "email"
            <*> o Aeson..: "created_at"
            <*> o Aeson..: "updated_at"
            <*> o Aeson..:? "last_sign_in_at"

-- | Build an 'IdentityResponse' from the domain 'Identity.Identity'.
buildIdentityResponse :: Identity.Identity -> IdentityResponse
buildIdentityResponse Identity.Identity{..} =
    IdentityResponse
        { identityResponseId = Identity.unIdentityId identityIdentityId
        , identityResponseUserId = identityUserId
        , identityResponseProvider = identityProvider
        , identityResponseProviderId = identityProviderId
        , identityResponseIdentityData = identityIdentityData
        , identityResponseEmail = identityEmail
        , identityResponseCreatedAt = identityCreatedAt
        , identityResponseUpdatedAt = identityUpdatedAt
        , identityResponseLastSignInAt = identityLastSignInAt
        }

newtype ListIdentitiesResponse = ListIdentitiesResponse
    { listIdentities :: [IdentityResponse]
    }
    deriving stock (Eq, Generic, Show)

instance ToJSON ListIdentitiesResponse where
    toJSON ListIdentitiesResponse{listIdentities} =
        object ["identities" .= listIdentities]

instance FromJSON ListIdentitiesResponse where
    parseJSON = Aeson.withObject "ListIdentitiesResponse" \o ->
        ListIdentitiesResponse <$> o Aeson..: "identities"

data GenerateLinkRequest = GenerateLinkRequest
    { generateLinkEmail :: Email
    , generateLinkType :: Text
    }
    deriving stock (Eq, Generic, Show)

instance FromJSON GenerateLinkRequest where
    parseJSON = Aeson.withObject "GenerateLinkRequest" \o ->
        GenerateLinkRequest
            <$> o Aeson..: "email"
            <*> o Aeson..: "type"

instance ToJSON GenerateLinkRequest where
    toJSON GenerateLinkRequest{generateLinkEmail, generateLinkType} =
        object
            [ "email" .= generateLinkEmail
            , "type" .= generateLinkType
            ]

newtype GenerateLinkResponse = GenerateLinkResponse
    { generateLinkActionLink :: Text
    }
    deriving stock (Eq, Generic, Show)

instance FromJSON GenerateLinkResponse where
    parseJSON = Aeson.withObject "GenerateLinkResponse" \o ->
        GenerateLinkResponse <$> o Aeson..: "action_link"

instance ToJSON GenerateLinkResponse where
    toJSON GenerateLinkResponse{generateLinkActionLink} =
        object ["action_link" .= generateLinkActionLink]

data InviteUserRequest = InviteUserRequest
    { inviteUserEmail :: Email
    , inviteUserData :: Maybe Value
    -- ^ Optional metadata to attach to the invited user.
    }
    deriving stock (Eq, Generic, Show)

instance FromJSON InviteUserRequest where
    parseJSON = Aeson.withObject "InviteUserRequest" \o ->
        InviteUserRequest
            <$> o Aeson..: "email"
            <*> o Aeson..:? "data"

instance ToJSON InviteUserRequest where
    toJSON InviteUserRequest{inviteUserEmail, inviteUserData} =
        object
            [ "email" .= inviteUserEmail
            , "data" .= inviteUserData
            ]

newtype ProvidersResponse = ProvidersResponse
    { providers :: [Text]
    }
    deriving stock (Eq, Generic, Show)

instance FromJSON ProvidersResponse where
    parseJSON = Aeson.withObject "ProvidersResponse" \o ->
        ProvidersResponse <$> o Aeson..: "providers"

instance ToJSON ProvidersResponse where
    toJSON ProvidersResponse{providers} =
        object ["providers" .= providers]

newtype UpdateProvidersRequest = UpdateProvidersRequest
    { updateProviders :: [Text]
    }
    deriving stock (Eq, Generic, Show)

instance FromJSON UpdateProvidersRequest where
    parseJSON = Aeson.withObject "UpdateProvidersRequest" \o ->
        UpdateProvidersRequest <$> o Aeson..: "providers"

instance ToJSON UpdateProvidersRequest where
    toJSON UpdateProvidersRequest{updateProviders} =
        object ["providers" .= updateProviders]

-- | Request body for PUT /admin/email-templates/{name}.
data EmailTemplateCrudRequest = EmailTemplateCrudRequest
    { emailTemplateCrudSubject :: Text
    , emailTemplateCrudBodyText :: Text
    , emailTemplateCrudBodyHtml :: Text
    }
    deriving stock (Eq, Generic, Show)

instance FromJSON EmailTemplateCrudRequest where
    parseJSON = Aeson.withObject "EmailTemplateCrudRequest" \o ->
        EmailTemplateCrudRequest
            <$> o Aeson..: "subject"
            <*> o Aeson..: "body_text"
            <*> o Aeson..: "body_html"

instance ToJSON EmailTemplateCrudRequest where
    toJSON EmailTemplateCrudRequest{emailTemplateCrudSubject, emailTemplateCrudBodyText, emailTemplateCrudBodyHtml} =
        object
            [ "subject" .= emailTemplateCrudSubject
            , "body_text" .= emailTemplateCrudBodyText
            , "body_html" .= emailTemplateCrudBodyHtml
            ]

-- | A single email template row, returned by GET and PUT.
data EmailTemplateRow = EmailTemplateRow
    { emailTemplateRowName :: Text
    , emailTemplateRowSubject :: Text
    , emailTemplateRowBodyText :: Text
    , emailTemplateRowBodyHtml :: Text
    , emailTemplateRowUpdatedAt :: UTCTime
    }
    deriving stock (Eq, Generic, Show)

instance ToJSON EmailTemplateRow where
    toJSON EmailTemplateRow{..} =
        object
            [ "name" .= emailTemplateRowName
            , "subject" .= emailTemplateRowSubject
            , "body_text" .= emailTemplateRowBodyText
            , "body_html" .= emailTemplateRowBodyHtml
            , "updated_at" .= emailTemplateRowUpdatedAt
            ]

instance FromJSON EmailTemplateRow where
    parseJSON = Aeson.withObject "EmailTemplateRow" \o ->
        EmailTemplateRow
            <$> o Aeson..: "name"
            <*> o Aeson..: "subject"
            <*> o Aeson..: "body_text"
            <*> o Aeson..: "body_html"
            <*> o Aeson..: "updated_at"

-- | Response body for GET /admin/email-templates.
newtype EmailTemplatesListResponse = EmailTemplatesListResponse
    { emailTemplatesList :: [EmailTemplateRow]
    }
    deriving stock (Eq, Generic, Show)

instance ToJSON EmailTemplatesListResponse where
    toJSON EmailTemplatesListResponse{emailTemplatesList} =
        object ["templates" .= emailTemplatesList]

instance FromJSON EmailTemplatesListResponse where
    parseJSON = Aeson.withObject "EmailTemplatesListResponse" \o ->
        EmailTemplatesListResponse <$> o Aeson..: "templates"

newtype EmailTemplatesResponse = EmailTemplatesResponse
    { emailTemplates :: [Text]
    }
    deriving stock (Eq, Generic, Show)

instance FromJSON EmailTemplatesResponse where
    parseJSON = Aeson.withObject "EmailTemplatesResponse" \o ->
        EmailTemplatesResponse <$> o Aeson..: "templates"

instance ToJSON EmailTemplatesResponse where
    toJSON EmailTemplatesResponse{emailTemplates} =
        object ["templates" .= emailTemplates]

newtype UpdateEmailTemplatesRequest = UpdateEmailTemplatesRequest
    { updateEmailTemplates :: [Text]
    }
    deriving stock (Eq, Generic, Show)

instance FromJSON UpdateEmailTemplatesRequest where
    parseJSON = Aeson.withObject "UpdateEmailTemplatesRequest" \o ->
        UpdateEmailTemplatesRequest <$> o Aeson..: "templates"

instance ToJSON UpdateEmailTemplatesRequest where
    toJSON UpdateEmailTemplatesRequest{updateEmailTemplates} =
        object ["templates" .= updateEmailTemplates]

-- | Full delivery row returned by GET single and POST retry.
data WebhookDeliveryResponse = WebhookDeliveryResponse
    { webhookDeliveryId :: UUID
    , webhookDeliverySubscriptionId :: UUID
    , webhookDeliveryEventType :: Text
    , webhookDeliveryPayload :: Value
    , webhookDeliveryStatus :: Text
    , webhookDeliveryAttempts :: Int
    , webhookDeliveryNextAttemptAt :: UTCTime
    , webhookDeliveryResponseStatus :: Maybe Int
    , webhookDeliveryResponseBody :: Maybe Text
    , webhookDeliveryLastError :: Maybe Text
    , webhookDeliveryCreatedAt :: UTCTime
    , webhookDeliveryUpdatedAt :: UTCTime
    }
    deriving stock (Eq, Show)

instance ToJSON WebhookDeliveryResponse where
    toJSON WebhookDeliveryResponse{..} =
        object
            [ "id" .= webhookDeliveryId
            , "subscription_id" .= webhookDeliverySubscriptionId
            , "event_type" .= webhookDeliveryEventType
            , "payload" .= webhookDeliveryPayload
            , "status" .= webhookDeliveryStatus
            , "attempts" .= webhookDeliveryAttempts
            , "next_attempt_at" .= webhookDeliveryNextAttemptAt
            , "response_status" .= webhookDeliveryResponseStatus
            , "response_body" .= webhookDeliveryResponseBody
            , "last_error" .= webhookDeliveryLastError
            , "created_at" .= webhookDeliveryCreatedAt
            , "updated_at" .= webhookDeliveryUpdatedAt
            ]

instance FromJSON WebhookDeliveryResponse where
    parseJSON = Aeson.withObject "WebhookDeliveryResponse" \o ->
        WebhookDeliveryResponse
            <$> o Aeson..: "id"
            <*> o Aeson..: "subscription_id"
            <*> o Aeson..: "event_type"
            <*> o Aeson..: "payload"
            <*> o Aeson..: "status"
            <*> o Aeson..: "attempts"
            <*> o Aeson..: "next_attempt_at"
            <*> o Aeson..:? "response_status"
            <*> o Aeson..:? "response_body"
            <*> o Aeson..:? "last_error"
            <*> o Aeson..: "created_at"
            <*> o Aeson..: "updated_at"

data ListWebhookDeliveriesResponse = ListWebhookDeliveriesResponse
    { listDeliveries :: [WebhookDeliveryResponse]
    , listDeliveriesNextPage :: Maybe Int
    }
    deriving stock (Eq, Show)

instance ToJSON ListWebhookDeliveriesResponse where
    toJSON ListWebhookDeliveriesResponse{listDeliveries, listDeliveriesNextPage} =
        object
            [ "deliveries" .= listDeliveries
            , "next_page" .= listDeliveriesNextPage
            ]

instance FromJSON ListWebhookDeliveriesResponse where
    parseJSON = Aeson.withObject "ListWebhookDeliveriesResponse" \o ->
        ListWebhookDeliveriesResponse
            <$> o Aeson..: "deliveries"
            <*> o Aeson..:? "next_page"

-- | Legacy response type kept for the existing AdminWebhookAPI stubs.
newtype WebhookDeliveriesResponse = WebhookDeliveriesResponse
    { webhookDeliveries :: [WebhookDeliveryResponse]
    }
    deriving stock (Eq, Show)

instance ToJSON WebhookDeliveriesResponse where
    toJSON WebhookDeliveriesResponse{webhookDeliveries} =
        object ["deliveries" .= webhookDeliveries]

instance FromJSON WebhookDeliveriesResponse where
    parseJSON = Aeson.withObject "WebhookDeliveriesResponse" \o ->
        WebhookDeliveriesResponse <$> o Aeson..: "deliveries"

newtype WebhookSubscriptionId = WebhookSubscriptionId {unWebhookSubscriptionId :: Text}
    deriving stock (Eq, Generic, Ord, Show)
    deriving newtype (FromHttpApiData, FromJSON, ToHttpApiData, ToJSON)

data WebhookSubscriptionResponse = WebhookSubscriptionResponse
    { webhookSubId :: UUID
    , webhookSubUrl :: Text
    , webhookSubEvents :: [Text]
    , webhookSubSecret :: Text
    , webhookSubDisabledAt :: Maybe UTCTime
    , webhookSubCreatedAt :: UTCTime
    , webhookSubUpdatedAt :: UTCTime
    }
    deriving stock (Eq, Show)

instance ToJSON WebhookSubscriptionResponse where
    toJSON WebhookSubscriptionResponse{..} =
        object
            [ "id" .= webhookSubId
            , "url" .= webhookSubUrl
            , "events" .= webhookSubEvents
            , "secret" .= webhookSubSecret
            , "disabled_at" .= webhookSubDisabledAt
            , "created_at" .= webhookSubCreatedAt
            , "updated_at" .= webhookSubUpdatedAt
            ]

instance FromJSON WebhookSubscriptionResponse where
    parseJSON = Aeson.withObject "WebhookSubscriptionResponse" \o ->
        WebhookSubscriptionResponse
            <$> o Aeson..: "id"
            <*> o Aeson..: "url"
            <*> o Aeson..: "events"
            <*> o Aeson..: "secret"
            <*> o Aeson..:? "disabled_at"
            <*> o Aeson..: "created_at"
            <*> o Aeson..: "updated_at"

newtype ListWebhookSubscriptionsResponse = ListWebhookSubscriptionsResponse
    { listWebhookSubscriptions :: [WebhookSubscriptionResponse]
    }
    deriving stock (Eq, Show)

instance ToJSON ListWebhookSubscriptionsResponse where
    toJSON ListWebhookSubscriptionsResponse{listWebhookSubscriptions} =
        object ["webhooks" .= listWebhookSubscriptions]

instance FromJSON ListWebhookSubscriptionsResponse where
    parseJSON = Aeson.withObject "ListWebhookSubscriptionsResponse" \o ->
        ListWebhookSubscriptionsResponse <$> o Aeson..: "webhooks"

data CreateWebhookSubscriptionRequest = CreateWebhookSubscriptionRequest
    { createWebhookSubUrl :: Text
    , createWebhookSubEvents :: Maybe [Text]
    , createWebhookSubSecret :: Maybe Text
    }
    deriving stock (Eq, Show)

instance FromJSON CreateWebhookSubscriptionRequest where
    parseJSON = Aeson.withObject "CreateWebhookSubscriptionRequest" \o ->
        CreateWebhookSubscriptionRequest
            <$> o Aeson..: "url"
            <*> o Aeson..:? "events"
            <*> o Aeson..:? "secret"

instance ToJSON CreateWebhookSubscriptionRequest where
    toJSON CreateWebhookSubscriptionRequest{..} =
        object
            [ "url" .= createWebhookSubUrl
            , "events" .= createWebhookSubEvents
            , "secret" .= createWebhookSubSecret
            ]

data UpdateWebhookSubscriptionRequest = UpdateWebhookSubscriptionRequest
    { updateWebhookSubUrl :: Maybe Text
    , updateWebhookSubEvents :: Maybe [Text]
    , updateWebhookSubSecret :: Maybe Text
    , updateWebhookSubDisabledAt :: Maybe (Maybe UTCTime)
    }
    deriving stock (Eq, Show)

instance FromJSON UpdateWebhookSubscriptionRequest where
    parseJSON = Aeson.withObject "UpdateWebhookSubscriptionRequest" \o ->
        UpdateWebhookSubscriptionRequest
            <$> o Aeson..:? "url"
            <*> o Aeson..:? "events"
            <*> o Aeson..:? "secret"
            <*> (fmap Just <$> o Aeson..:? "disabled_at")

instance ToJSON UpdateWebhookSubscriptionRequest where
    toJSON UpdateWebhookSubscriptionRequest{..} =
        object
            [ "url" .= updateWebhookSubUrl
            , "events" .= updateWebhookSubEvents
            , "secret" .= updateWebhookSubSecret
            , "disabled_at" .= updateWebhookSubDisabledAt
            ]

-- ---------------------------------------------------------------------------
-- Sync hooks wire types
-- ---------------------------------------------------------------------------

data HookRow = HookRow
    { hookRowId :: UUID
    , hookRowPoint :: HookPoint
    , hookRowUrl :: Text
    , hookRowSecret :: Text
    , hookRowTimeoutMs :: Int
    , hookRowFailOpen :: Bool
    , hookRowEnabled :: Bool
    }
    deriving stock (Eq, Show)

instance ToJSON HookRow where
    toJSON HookRow{..} =
        object
            [ "id" .= UUID.toText hookRowId
            , "hook_point" .= hookPointName hookRowPoint
            , "url" .= hookRowUrl
            , "secret" .= hookRowSecret
            , "timeout_ms" .= hookRowTimeoutMs
            , "fail_open" .= hookRowFailOpen
            , "enabled" .= hookRowEnabled
            ]

instance FromJSON HookRow where
    parseJSON = withObject "HookRow" \o -> do
        idText <- o Aeson..: "id"
        hpText <- o Aeson..: "hook_point"
        hp <- case parseHookPoint hpText of
            Nothing -> fail ("unknown hook_point: " <> T.unpack hpText)
            Just p -> pure p
        HookRow
            <$> (case UUID.fromText idText of Nothing -> fail "bad uuid"; Just u -> pure u)
            <*> pure hp
            <*> o Aeson..: "url"
            <*> o Aeson..: "secret"
            <*> o Aeson..: "timeout_ms"
            <*> o Aeson..: "fail_open"
            <*> o Aeson..: "enabled"

data CreateHookRequest = CreateHookRequest
    { createHookPoint :: Text
    , createHookUrl :: Text
    , createHookSecret :: Maybe Text
    , createHookTimeoutMs :: Maybe Int
    , createHookFailOpen :: Maybe Bool
    , createHookEnabled :: Maybe Bool
    }
    deriving stock (Eq, Show)

instance FromJSON CreateHookRequest where
    parseJSON = withObject "CreateHookRequest" \o ->
        CreateHookRequest
            <$> o Aeson..: "hook_point"
            <*> o Aeson..: "url"
            <*> o Aeson..:? "secret"
            <*> o Aeson..:? "timeout_ms"
            <*> o Aeson..:? "fail_open"
            <*> o Aeson..:? "enabled"

data UpdateHookRequest = UpdateHookRequest
    { updateHookUrl :: Maybe Text
    , updateHookSecret :: Maybe Text
    , updateHookTimeoutMs :: Maybe Int
    , updateHookFailOpen :: Maybe Bool
    , updateHookEnabled :: Maybe Bool
    }
    deriving stock (Eq, Show)

instance FromJSON UpdateHookRequest where
    parseJSON = withObject "UpdateHookRequest" \o ->
        UpdateHookRequest
            <$> o Aeson..:? "url"
            <*> o Aeson..:? "secret"
            <*> o Aeson..:? "timeout_ms"
            <*> o Aeson..:? "fail_open"
            <*> o Aeson..:? "enabled"

newtype ListHooksResponse = ListHooksResponse {listHookRows :: [HookRow]}
    deriving stock (Eq, Show)

instance ToJSON ListHooksResponse where
    toJSON ListHooksResponse{listHookRows} =
        object ["hooks" .= listHookRows]
