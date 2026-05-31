module Hauth.API (
    AdminAPI,
    AdminConfigAPI,
    AdminUsersAPI,
    AdminWebhookAPI,
    HauthAPI,
    MfaAPI,
    OperatorAPI,
    PublicAuthAPI,
    SessionAPI,
    hauthAPI,
) where

import Data.Proxy (Proxy (Proxy))
import Data.Text (Text)
import Hauth.API.Auth (AuthRequirement (Anonymous, ServiceRole, ValidSession), RequireAuth)
import Hauth.API.Types
import Servant.API (
    Capture,
    Delete,
    Get,
    JSON,
    NoContent,
    Post,
    PostNoContent,
    Put,
    QueryParam,
    QueryParam',
    ReqBody,
    Required,
    Strict,
    type (:<|>),
    type (:>),
 )

type HauthAPI =
    OperatorAPI
        :<|> PublicAuthAPI
        :<|> SessionAPI
        :<|> MfaAPI
        :<|> AdminAPI

type OperatorAPI =
    RequireAuth 'Anonymous :> "healthz" :> Get '[JSON] HealthResponse
        :<|> RequireAuth 'Anonymous :> "healthz" :> "deep" :> Get '[JSON] DeepHealthResponse

type PublicAuthAPI =
    RequireAuth 'Anonymous :> "settings" :> Get '[JSON] SettingsResponse
        :<|> RequireAuth 'Anonymous :> "signup" :> ReqBody '[JSON] SignupRequest :> Post '[JSON] SignupResponse
        :<|> RequireAuth 'Anonymous :> "token" :> QueryParam' '[Required, Strict] "grant_type" Text :> ReqBody '[JSON] TokenRequest :> Post '[JSON] TokenResponse
        :<|> RequireAuth 'Anonymous :> "recover" :> ReqBody '[JSON] RecoverRequest :> Post '[JSON] MessageResponse
        :<|> RequireAuth 'Anonymous :> "verify" :> ReqBody '[JSON] VerifyRequest :> Post '[JSON] SessionResponse
        :<|> RequireAuth 'Anonymous :> "resend" :> ReqBody '[JSON] ResendRequest :> Post '[JSON] MessageResponse
        :<|> RequireAuth 'Anonymous :> "authorize" :> QueryParam "provider" Text :> QueryParam "redirect_to" Text :> Get '[JSON] OAuthAuthorizeResponse
        :<|> RequireAuth 'Anonymous :> "callback" :> QueryParam "code" Text :> QueryParam "state" Text :> Get '[JSON] SessionResponse

type SessionAPI =
    RequireAuth 'ValidSession :> "user" :> Get '[JSON] UserResponse
        :<|> RequireAuth 'ValidSession :> "user" :> ReqBody '[JSON] UpdateUserRequest :> Put '[JSON] UserResponse
        :<|> RequireAuth 'ValidSession :> "logout" :> QueryParam "scope" Text :> PostNoContent

type MfaAPI =
    RequireAuth 'ValidSession :> "factors" :> Get '[JSON] ListFactorsResponse
        :<|> RequireAuth 'ValidSession :> "factors" :> ReqBody '[JSON] EnrollFactorRequest :> Post '[JSON] FactorResponse
        :<|> RequireAuth 'ValidSession :> "factors" :> Capture "factor_id" FactorId :> "challenge" :> ReqBody '[JSON] ChallengeFactorRequest :> Post '[JSON] ChallengeFactorResponse
        :<|> RequireAuth 'ValidSession :> "factors" :> Capture "factor_id" FactorId :> "verify" :> ReqBody '[JSON] VerifyFactorRequest :> Post '[JSON] VerifyFactorResponse
        :<|> RequireAuth 'ValidSession :> "factors" :> Capture "factor_id" FactorId :> Delete '[JSON] MessageResponse

type AdminAPI =
    "admin"
        :> ( AdminUsersAPI
                :<|> AdminConfigAPI
                :<|> AdminWebhookAPI
           )

type AdminUsersAPI =
    RequireAuth 'ServiceRole :> "users" :> QueryParam "page" Int :> QueryParam "per_page" Int :> Get '[JSON] ListUsersResponse
        :<|> RequireAuth 'ServiceRole :> "users" :> ReqBody '[JSON] AdminCreateUserRequest :> Post '[JSON] UserResponse
        :<|> RequireAuth 'ServiceRole :> "users" :> Capture "user_id" UserId :> Get '[JSON] UserResponse
        :<|> RequireAuth 'ServiceRole :> "users" :> Capture "user_id" UserId :> ReqBody '[JSON] AdminUpdateUserRequest :> Put '[JSON] UserResponse
        :<|> RequireAuth 'ServiceRole :> "users" :> Capture "user_id" UserId :> Delete '[JSON] DeletedUserResponse
        :<|> RequireAuth 'ServiceRole :> "users" :> Capture "user_id" UserId :> "identities" :> Get '[JSON] ListIdentitiesResponse
        :<|> RequireAuth 'ServiceRole :> "users" :> Capture "user_id" UserId :> "identities" :> Capture "identity_id" IdentityId :> Delete '[JSON] MessageResponse
        :<|> RequireAuth 'ServiceRole :> "generate_link" :> ReqBody '[JSON] GenerateLinkRequest :> Post '[JSON] GenerateLinkResponse
        :<|> RequireAuth 'ServiceRole :> "invite" :> ReqBody '[JSON] InviteUserRequest :> Post '[JSON] MessageResponse

type AdminConfigAPI =
    RequireAuth 'ServiceRole :> "providers" :> Get '[JSON] ProvidersResponse
        :<|> RequireAuth 'ServiceRole :> "providers" :> ReqBody '[JSON] UpdateProvidersRequest :> Put '[JSON] ProvidersResponse
        :<|> RequireAuth 'ServiceRole :> "email_templates" :> Get '[JSON] EmailTemplatesResponse
        :<|> RequireAuth 'ServiceRole :> "email_templates" :> ReqBody '[JSON] UpdateEmailTemplatesRequest :> Put '[JSON] EmailTemplatesResponse

type AdminWebhookAPI =
    RequireAuth 'ServiceRole :> "webhook_deliveries" :> QueryParam "status" Text :> Get '[JSON] WebhookDeliveriesResponse
        :<|> RequireAuth 'ServiceRole :> "webhook_deliveries" :> Capture "delivery_id" WebhookDeliveryId :> Get '[JSON] WebhookDeliveryResponse
        :<|> RequireAuth 'ServiceRole :> "webhook_deliveries" :> Capture "delivery_id" WebhookDeliveryId :> "retry" :> Post '[JSON] WebhookDeliveryResponse

hauthAPI :: Proxy HauthAPI
hauthAPI = Proxy
