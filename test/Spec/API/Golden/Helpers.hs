{-# LANGUAGE NumericUnderscores #-}

{- | Shared helpers and canonical values reused across the per-surface
golden-encoding test modules under "Spec.API.Golden.*".
-}
module Spec.API.Golden.Helpers (
    -- * Shape-equality helpers
    shapeEq,
    roundTrip,
    encodeShape,
    decodeShape,

    -- * Canonical fixtures
    uuid0,
    t0,
    canonicalUserResponse,
    userResponseJson,
    canonicalSessionResponse,
    sessionResponseJson,
    canonicalFactorResponse,
    factorResponseJson,
    canonicalIdentityResponse,
    identityResponseJson,
    canonicalEmailTemplateRow,
    emailTemplateRowJson,
    canonicalWebhookSubResponse,
    webhookSubJson,
    canonicalWebhookSubCreateResponse,
    webhookSubCreateJson,
    canonicalWebhookDeliveryResponse,
    webhookDeliveryJson,
    canonicalHookRow,
    hookRowJson,
    canonicalHookCreateResponse,
    hookCreateResponseJson,
) where

import Data.Aeson (FromJSON, ToJSON, Value)
import qualified Data.Aeson as Aeson
import qualified Data.ByteString.Lazy as BSL
import Data.Time.Calendar (fromGregorian)
import Data.Time.Clock (UTCTime (..), secondsToDiffTime)
import qualified Data.UUID as UUID
import Hauth.API.Types
import Hauth.Hooks.Types (HookPoint (..))
import Test.Hspec (expectationFailure, shouldBe)

-- ---------------------------------------------------------------------------
-- Helpers
-- ---------------------------------------------------------------------------

{- | Shape-equality comparison via 'Aeson.Value'. Tolerates key reordering and
whitespace differences in the expected literal; catches wrong field names,
missing fields, wrong types.
-}
shapeEq :: BSL.ByteString -> BSL.ByteString -> Either String ()
shapeEq actual expected = do
    a <- Aeson.eitherDecode actual :: Either String Value
    e <- Aeson.eitherDecode expected :: Either String Value
    if a == e
        then Right ()
        else Left ("\n  actual:   " <> show a <> "\n  expected: " <> show e)

{- | For types with both 'FromJSON' and 'ToJSON': encode, compare shape to
expected, then decode expected and compare to the original.
-}
roundTrip :: (Eq a, Show a, FromJSON a, ToJSON a) => String -> a -> BSL.ByteString -> IO ()
roundTrip label value expected = do
    case shapeEq (Aeson.encode value) expected of
        Right () -> pure ()
        Left diff -> expectationFailure (label <> " encode shape mismatch:" <> diff)
    case Aeson.eitherDecode expected of
        Left e -> expectationFailure (label <> " decode failed: " <> e)
        Right decoded -> decoded `shouldBe` value

-- | For response-only types: just check the encoded shape.
encodeShape :: (ToJSON a) => String -> a -> BSL.ByteString -> IO ()
encodeShape label value expected =
    case shapeEq (Aeson.encode value) expected of
        Right () -> pure ()
        Left diff -> expectationFailure (label <> " encode shape mismatch:" <> diff)

-- | For request-only types: decode the input and compare to expected value.
decodeShape :: (Eq a, Show a, FromJSON a) => String -> BSL.ByteString -> a -> IO ()
decodeShape label input expected =
    case Aeson.eitherDecode input of
        Left e -> expectationFailure (label <> " decode failed: " <> e)
        Right decoded -> decoded `shouldBe` expected

-- ---------------------------------------------------------------------------
-- Canonical values reused across multiple tests
-- ---------------------------------------------------------------------------

uuid0 :: UUID.UUID
uuid0 = UUID.nil

-- 2026-01-02T03:04:05Z
t0 :: UTCTime
t0 = UTCTime (fromGregorian 2026 1 2) (secondsToDiffTime 11_045)

canonicalUserResponse :: UserResponse
canonicalUserResponse =
    UserResponse
        { userResponseId = uuid0
        , userResponseAud = "authenticated"
        , userResponseRole = "authenticated"
        , userResponseEmail = Just "alice@example.com"
        , userResponseEmailConfirmedAt = Just t0
        , userResponseCreatedAt = t0
        , userResponseUpdatedAt = t0
        , userResponseAppMetadata = Aeson.object []
        , userResponseUserMetadata = Aeson.object []
        }

userResponseJson :: BSL.ByteString
userResponseJson =
    "{\"id\":\"00000000-0000-0000-0000-000000000000\"\
    \,\"aud\":\"authenticated\",\"role\":\"authenticated\"\
    \,\"email\":\"alice@example.com\"\
    \,\"email_confirmed_at\":\"2026-01-02T03:04:05Z\"\
    \,\"created_at\":\"2026-01-02T03:04:05Z\"\
    \,\"updated_at\":\"2026-01-02T03:04:05Z\"\
    \,\"app_metadata\":{},\"user_metadata\":{}}"

canonicalSessionResponse :: SessionResponse
canonicalSessionResponse =
    SessionResponse
        { sessionAccessToken = "at"
        , sessionRefreshToken = "rt"
        , sessionExpiresIn = 3600
        , sessionUser = canonicalUserResponse
        }

sessionResponseJson :: BSL.ByteString
sessionResponseJson =
    "{\"access_token\":\"at\",\"token_type\":\"bearer\"\
    \,\"expires_in\":3600,\"refresh_token\":\"rt\"\
    \,\"user\":"
        <> userResponseJson
        <> "}"

canonicalFactorResponse :: FactorResponse
canonicalFactorResponse =
    FactorResponse
        { factorResponseId = FactorId "00000000-0000-0000-0000-000000000000"
        , factorResponseType = "totp"
        , factorResponseFriendlyName = Just "phone"
        , factorResponseStatus = "verified"
        , factorResponseTotp =
            Just
                FactorTotpData
                    { factorTotpQrCode = "otpauth://..."
                    , factorTotpSecret = "BASE32SECRET"
                    , factorTotpUri = "otpauth://..."
                    }
        }

factorResponseJson :: BSL.ByteString
factorResponseJson =
    "{\"id\":\"00000000-0000-0000-0000-000000000000\",\"type\":\"totp\"\
    \,\"friendly_name\":\"phone\",\"status\":\"verified\"\
    \,\"totp\":{\"qr_code\":\"otpauth://...\",\"secret\":\"BASE32SECRET\",\"uri\":\"otpauth://...\"}}"

canonicalIdentityResponse :: IdentityResponse
canonicalIdentityResponse =
    IdentityResponse
        { identityResponseId = "ident-1"
        , identityResponseUserId = uuid0
        , identityResponseProvider = "google"
        , identityResponseProviderId = "google-sub-1"
        , identityResponseIdentityData = Aeson.object []
        , identityResponseEmail = Just "alice@example.com"
        , identityResponseCreatedAt = t0
        , identityResponseUpdatedAt = t0
        , identityResponseLastSignInAt = Just t0
        }

identityResponseJson :: BSL.ByteString
identityResponseJson =
    "{\"id\":\"ident-1\",\"user_id\":\"00000000-0000-0000-0000-000000000000\"\
    \,\"provider\":\"google\",\"provider_id\":\"google-sub-1\"\
    \,\"identity_data\":{},\"email\":\"alice@example.com\"\
    \,\"created_at\":\"2026-01-02T03:04:05Z\"\
    \,\"updated_at\":\"2026-01-02T03:04:05Z\"\
    \,\"last_sign_in_at\":\"2026-01-02T03:04:05Z\"}"

canonicalEmailTemplateRow :: EmailTemplateRow
canonicalEmailTemplateRow =
    EmailTemplateRow
        { emailTemplateRowName = "confirmation"
        , emailTemplateRowSubject = "Confirm"
        , emailTemplateRowBodyText = "txt"
        , emailTemplateRowBodyHtml = "<p>html</p>"
        , emailTemplateRowUpdatedAt = t0
        }

emailTemplateRowJson :: BSL.ByteString
emailTemplateRowJson =
    "{\"name\":\"confirmation\",\"subject\":\"Confirm\"\
    \,\"body_text\":\"txt\",\"body_html\":\"<p>html</p>\"\
    \,\"updated_at\":\"2026-01-02T03:04:05Z\"}"

canonicalWebhookSubResponse :: WebhookSubscriptionResponse
canonicalWebhookSubResponse =
    WebhookSubscriptionResponse
        { webhookSubId = uuid0
        , webhookSubUrl = "https://example.com/wh"
        , webhookSubEvents = ["user.signed_up"]
        , webhookSubSecret = "shh"
        , webhookSubDisabledAt = Nothing
        , webhookSubCreatedAt = t0
        , webhookSubUpdatedAt = t0
        }

-- The secret field is always redacted on read/list responses.
webhookSubJson :: BSL.ByteString
webhookSubJson =
    "{\"id\":\"00000000-0000-0000-0000-000000000000\"\
    \,\"url\":\"https://example.com/wh\"\
    \,\"events\":[\"user.signed_up\"],\"secret\":\"***redacted***\"\
    \,\"disabled_at\":null\
    \,\"created_at\":\"2026-01-02T03:04:05Z\"\
    \,\"updated_at\":\"2026-01-02T03:04:05Z\"}"

canonicalWebhookSubCreateResponse :: WebhookSubscriptionCreateResponse
canonicalWebhookSubCreateResponse =
    WebhookSubscriptionCreateResponse
        { webhookCreateSubId = uuid0
        , webhookCreateSubUrl = "https://example.com/wh"
        , webhookCreateSubEvents = ["user.signed_up"]
        , webhookCreateSubSecret = "shh"
        , webhookCreateSubDisabledAt = Nothing
        , webhookCreateSubCreatedAt = t0
        , webhookCreateSubUpdatedAt = t0
        }

webhookSubCreateJson :: BSL.ByteString
webhookSubCreateJson =
    "{\"id\":\"00000000-0000-0000-0000-000000000000\"\
    \,\"url\":\"https://example.com/wh\"\
    \,\"events\":[\"user.signed_up\"],\"secret\":\"shh\"\
    \,\"disabled_at\":null\
    \,\"created_at\":\"2026-01-02T03:04:05Z\"\
    \,\"updated_at\":\"2026-01-02T03:04:05Z\"}"

canonicalWebhookDeliveryResponse :: WebhookDeliveryResponse
canonicalWebhookDeliveryResponse =
    WebhookDeliveryResponse
        { webhookDeliveryId = uuid0
        , webhookDeliverySubscriptionId = uuid0
        , webhookDeliveryEventType = "user.signed_up"
        , webhookDeliveryPayload = Aeson.object []
        , webhookDeliveryStatus = "pending"
        , webhookDeliveryAttempts = 0
        , webhookDeliveryNextAttemptAt = t0
        , webhookDeliveryResponseStatus = Nothing
        , webhookDeliveryResponseBody = Nothing
        , webhookDeliveryLastError = Nothing
        , webhookDeliveryCreatedAt = t0
        , webhookDeliveryUpdatedAt = t0
        }

webhookDeliveryJson :: BSL.ByteString
webhookDeliveryJson =
    "{\"id\":\"00000000-0000-0000-0000-000000000000\"\
    \,\"subscription_id\":\"00000000-0000-0000-0000-000000000000\"\
    \,\"event_type\":\"user.signed_up\",\"payload\":{}\
    \,\"status\":\"pending\",\"attempts\":0\
    \,\"next_attempt_at\":\"2026-01-02T03:04:05Z\"\
    \,\"response_status\":null,\"response_body\":null,\"last_error\":null\
    \,\"created_at\":\"2026-01-02T03:04:05Z\"\
    \,\"updated_at\":\"2026-01-02T03:04:05Z\"}"

canonicalHookRow :: HookRow
canonicalHookRow =
    HookRow
        { hookRowId = uuid0
        , hookRowPoint = HookBeforeUserCreated
        , hookRowUrl = "https://example.com/hook"
        , hookRowSecret = "shh"
        , hookRowTimeoutMs = 1000
        , hookRowFailOpen = True
        , hookRowEnabled = True
        }

-- The secret field is always redacted on read/list responses.
hookRowJson :: BSL.ByteString
hookRowJson =
    "{\"id\":\"00000000-0000-0000-0000-000000000000\"\
    \,\"hook_point\":\"before-user-created\"\
    \,\"url\":\"https://example.com/hook\",\"secret\":\"***redacted***\"\
    \,\"timeout_ms\":1000,\"fail_open\":true,\"enabled\":true}"

canonicalHookCreateResponse :: HookCreateResponse
canonicalHookCreateResponse =
    HookCreateResponse
        { hookCreateId = uuid0
        , hookCreatePoint = HookBeforeUserCreated
        , hookCreateUrl = "https://example.com/hook"
        , hookCreateSecret = "shh"
        , hookCreateTimeoutMs = 1000
        , hookCreateFailOpen = True
        , hookCreateEnabled = True
        }

hookCreateResponseJson :: BSL.ByteString
hookCreateResponseJson =
    "{\"id\":\"00000000-0000-0000-0000-000000000000\"\
    \,\"hook_point\":\"before-user-created\"\
    \,\"url\":\"https://example.com/hook\",\"secret\":\"shh\"\
    \,\"timeout_ms\":1000,\"fail_open\":true,\"enabled\":true}"
