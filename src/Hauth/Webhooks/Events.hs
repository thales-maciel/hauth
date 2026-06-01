module Hauth.Webhooks.Events (
    WebhookEvent (..),
    UserPayload (..),
    SessionPayload (..),
    MfaPayload (..),
    eventName,
    eventPayload,
) where

import Data.Aeson (Value)
import qualified Data.Aeson as Aeson
import Data.Text (Text)
import Data.Time (UTCTime)
import Data.UUID (UUID)

-- | All event types that hauth can emit to webhook subscribers.
data WebhookEvent
    = UserSignedUp UserPayload
    | UserEmailConfirmed UserPayload
    | UserRecovered UserPayload
    | UserDeleted UserPayload
    | UserAdminCreated UserPayload
    | UserAdminUpdated UserPayload
    | PasswordChanged UserPayload
    | SessionRevoked SessionPayload
    | MfaEnrolled MfaPayload
    | MfaVerified MfaPayload
    deriving stock (Eq, Show)

-- | Payload fields available for user-scoped events.
data UserPayload = UserPayload
    { upUserId :: UUID
    , upEmail :: Maybe Text
    , upCreatedAt :: UTCTime
    }
    deriving stock (Eq, Show)

-- | Payload fields available for session-scoped events.
data SessionPayload = SessionPayload
    { spSessionId :: UUID
    , spUserId :: UUID
    }
    deriving stock (Eq, Show)

-- | Payload fields available for MFA-scoped events.
data MfaPayload = MfaPayload
    { mpFactorId :: UUID
    , mpUserId :: UUID
    }
    deriving stock (Eq, Show)

-- | Stable wire name for a 'WebhookEvent', stored as @event_type@ in deliveries.
eventName :: WebhookEvent -> Text
eventName (UserSignedUp _) = "user.signed_up"
eventName (UserEmailConfirmed _) = "user.email_confirmed"
eventName (UserRecovered _) = "user.recovered"
eventName (UserDeleted _) = "user.deleted"
eventName (UserAdminCreated _) = "user.admin_created"
eventName (UserAdminUpdated _) = "user.admin_updated"
eventName (PasswordChanged _) = "user.password_changed"
eventName (SessionRevoked _) = "session.revoked"
eventName (MfaEnrolled _) = "mfa.enrolled"
eventName (MfaVerified _) = "mfa.verified"

-- | JSON body POSTed to the webhook URL for each event.
eventPayload :: WebhookEvent -> Value
eventPayload (UserSignedUp p) = userPayloadValue p
eventPayload (UserEmailConfirmed p) = userPayloadValue p
eventPayload (UserRecovered p) = userPayloadValue p
eventPayload (UserDeleted p) = userPayloadValue p
eventPayload (UserAdminCreated p) = userPayloadValue p
eventPayload (UserAdminUpdated p) = userPayloadValue p
eventPayload (PasswordChanged p) = userPayloadValue p
eventPayload (SessionRevoked SessionPayload{..}) =
    Aeson.object
        [ "session_id" Aeson..= spSessionId
        , "user_id" Aeson..= spUserId
        ]
eventPayload (MfaEnrolled MfaPayload{..}) =
    Aeson.object
        [ "factor_id" Aeson..= mpFactorId
        , "user_id" Aeson..= mpUserId
        ]
eventPayload (MfaVerified MfaPayload{..}) =
    Aeson.object
        [ "factor_id" Aeson..= mpFactorId
        , "user_id" Aeson..= mpUserId
        ]

userPayloadValue :: UserPayload -> Value
userPayloadValue UserPayload{..} =
    Aeson.object
        [ "user_id" Aeson..= upUserId
        , "email" Aeson..= upEmail
        , "created_at" Aeson..= upCreatedAt
        ]
