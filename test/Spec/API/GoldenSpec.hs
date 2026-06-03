{-# LANGUAGE NumericUnderscores #-}

{- | Wire-shape coverage for every request and response type referenced by
'Hauth.API.HauthAPI'.

Each test pins a canonical Haskell value against the JSON it must encode to
(and, where the type has both 'FromJSON' and 'ToJSON', round-trips it). The
shape comparison is structural — keys are compared via 'Aeson.Value' equality,
not byte-for-byte — so the tests don't accidentally lock us to a specific key
ordering, only to the field-name contract.

The point of this module is to make Generic-derived drift impossible. If
anyone reaches for @deriving anyclass (FromJSON, ToJSON)@ on a wire type
again (banned in AGENTS.md), the encode-shape assertion fails because the
Haskell record field name leaks into the JSON.
-}
module Spec.API.GoldenSpec (runSpec) where

import Data.Aeson (FromJSON, ToJSON, Value)
import qualified Data.Aeson as Aeson
import qualified Data.ByteString.Lazy as BSL
import qualified Data.Map.Strict as Map
import Data.Text (Text)
import Data.Time.Calendar (fromGregorian)
import Data.Time.Clock (UTCTime (..), secondsToDiffTime)
import qualified Data.UUID as UUID
import Hauth.API.Types
import Hauth.Hooks.Types (HookPoint (..))
import Spec.TestUtils (assertEqual)

runSpec :: IO ()
runSpec = do
    encodeShape
        "HealthResponse"
        HealthResponse{healthStatus = "ok"}
        "{\"status\":\"ok\"}"
    encodeShape
        "DeepHealthResponse"
        DeepHealthResponse
            { deepHealthStatus = "ok"
            , deepHealthChecks =
                [ DeepHealthCheck
                    { deepHealthCheckName = "process"
                    , deepHealthCheckOutcome = CheckOk
                    , deepHealthCheckLatencyMs = Nothing
                    }
                , DeepHealthCheck
                    { deepHealthCheckName = "postgres"
                    , deepHealthCheckOutcome = CheckFailed "boom"
                    , deepHealthCheckLatencyMs = Just 42
                    }
                ]
            }
        "{\"status\":\"ok\",\"checks\":\
        \[{\"name\":\"process\",\"status\":\"ok\",\"latency_ms\":null}\
        \,{\"name\":\"postgres\",\"status\":\"failed\",\"reason\":\"boom\",\"latency_ms\":42}]}"
    encodeShape
        "SettingsResponse"
        SettingsResponse
            { settingsExternal = Map.fromList [("email" :: Text, True), ("phone", False)]
            , settingsExternalEmailEnabled = True
            , settingsExternalPhoneEnabled = False
            , settingsDisableSignup = False
            , settingsMailerAutoconfirm = False
            , settingsPhoneAutoconfirm = False
            , settingsSmsProvider = ""
            }
        "{\"external\":{\"email\":true,\"phone\":false}\
        \,\"external_email_enabled\":true,\"external_phone_enabled\":false\
        \,\"disable_signup\":false,\"mailer_autoconfirm\":false\
        \,\"phone_autoconfirm\":false,\"sms_provider\":\"\"}"

    -- Auth: signup, token, recover, verify, resend, update-user
    roundTrip
        "SignupRequest"
        SignupRequest
            { signupEmail = Email "alice@example.com"
            , signupPassword = Password "correct horse"
            , signupData = Just (Aeson.object ["foo" Aeson..= ("bar" :: Text)])
            }
        "{\"email\":\"alice@example.com\",\"password\":\"correct horse\",\"data\":{\"foo\":\"bar\"}}"
    encodeShape
        "SignupResponse"
        SignupResponse
            { signupResponseId = uuid0
            , signupResponseAud = "authenticated"
            , signupResponseRole = "authenticated"
            , signupResponseEmail = Just "alice@example.com"
            , signupResponseConfirmationSentAt = Just t0
            , signupResponseCreatedAt = t0
            , signupResponseUpdatedAt = t0
            , signupResponseAppMetadata = Aeson.object []
            , signupResponseUserMetadata = Aeson.object []
            }
        "{\"id\":\"00000000-0000-0000-0000-000000000000\"\
        \,\"aud\":\"authenticated\",\"role\":\"authenticated\"\
        \,\"email\":\"alice@example.com\"\
        \,\"confirmation_sent_at\":\"2026-01-02T03:04:05Z\"\
        \,\"created_at\":\"2026-01-02T03:04:05Z\"\
        \,\"updated_at\":\"2026-01-02T03:04:05Z\"\
        \,\"app_metadata\":{},\"user_metadata\":{}}"
    decodeShape
        "TokenRequest (refresh_token)"
        "{\"refresh_token\":\"rt-1\"}"
        TokenRequest{tokenRequestRefreshToken = Just "rt-1", tokenRequestEmail = Nothing, tokenRequestPassword = Nothing}
    decodeShape
        "TokenRequest (password)"
        "{\"email\":\"alice@example.com\",\"password\":\"pw\"}"
        TokenRequest
            { tokenRequestRefreshToken = Nothing
            , tokenRequestEmail = Just (Email "alice@example.com")
            , tokenRequestPassword = Just (Password "pw")
            }
    encodeShape
        "TokenResponse"
        TokenResponse
            { tokenResponseAccessToken = "at"
            , tokenResponseTokenType = "bearer"
            , tokenResponseExpiresIn = 3600
            , tokenResponseRefreshToken = "rt"
            , tokenResponseUser = Aeson.object ["id" Aeson..= UUID.toText uuid0]
            }
        "{\"access_token\":\"at\",\"token_type\":\"bearer\"\
        \,\"expires_in\":3600,\"refresh_token\":\"rt\"\
        \,\"user\":{\"id\":\"00000000-0000-0000-0000-000000000000\"}}"
    roundTrip
        "RecoverRequest"
        (RecoverRequest (Email "alice@example.com"))
        "{\"email\":\"alice@example.com\"}"
    roundTrip
        "VerifyRequest"
        VerifyRequest
            { verifyToken = "tok"
            , verifyType = "signup"
            , verifyEmail = Just "alice@example.com"
            , verifyPassword = Nothing
            }
        "{\"token\":\"tok\",\"type\":\"signup\",\"email\":\"alice@example.com\",\"password\":null}"
    roundTrip
        "ResendRequest"
        ResendRequest
            { resendEmail = Email "alice@example.com"
            , resendType = "signup"
            }
        "{\"email\":\"alice@example.com\",\"type\":\"signup\"}"
    roundTrip
        "UpdateUserRequest"
        UpdateUserRequest
            { updateUserEmail = Just (Email "bob@example.com")
            , updateUserPassword = Just (Password "pw")
            , updateUserData = Just (Aeson.object [])
            }
        "{\"email\":\"bob@example.com\",\"password\":\"pw\",\"data\":{}}"
    roundTrip
        "SessionResponse"
        canonicalSessionResponse
        sessionResponseJson
    roundTrip
        "UserResponse"
        canonicalUserResponse
        userResponseJson
    roundTrip
        "MessageResponse"
        MessageResponse{message = "ok"}
        "{\"message\":\"ok\"}"
    roundTrip
        "OAuthAuthorizeResponse"
        OAuthAuthorizeResponse
            { oauthAuthorizeUrl = "https://accounts.google.com/o/oauth2/v2/auth?...."
            , oauthAuthorizeState = "state-abc"
            }
        "{\"url\":\"https://accounts.google.com/o/oauth2/v2/auth?....\",\"state\":\"state-abc\"}"

    -- MFA
    roundTrip
        "ListFactorsResponse"
        ListFactorsResponse
            { listFactorsAll = [canonicalFactorResponse]
            , listFactorsTotp = [canonicalFactorResponse]
            , listFactorsPhone = []
            }
        ("{\"factors\":[" <> factorResponseJson <> "],\"totp\":[" <> factorResponseJson <> "],\"phone\":[]}")
    roundTrip
        "EnrollFactorRequest"
        EnrollFactorRequest
            { enrollFactorType = "totp"
            , enrollFactorFriendlyName = Just "phone"
            , enrollFactorIssuer = Just "Hauth"
            }
        "{\"factor_type\":\"totp\",\"friendly_name\":\"phone\",\"issuer\":\"Hauth\"}"
    roundTrip
        "FactorResponse"
        canonicalFactorResponse
        factorResponseJson
    roundTrip
        "ChallengeFactorRequest"
        ChallengeFactorRequest{challengeFactorChannel = Just "sms"}
        "{\"channel\":\"sms\"}"
    -- ChallengeFactorResponse's ToJSON adds "type":"totp"; FromJSON ignores it.
    -- A strict round-trip would re-add "type" on re-encode, so we just verify
    -- the encoded shape.
    encodeShape
        "ChallengeFactorResponse"
        ChallengeFactorResponse
            { challengeFactorId = "00000000-0000-0000-0000-000000000000"
            , challengeExpiresAt = t0
            }
        "{\"id\":\"00000000-0000-0000-0000-000000000000\",\"type\":\"totp\",\"expires_at\":\"2026-01-02T03:04:05Z\"}"
    roundTrip
        "VerifyFactorRequest"
        VerifyFactorRequest{verifyFactorChallengeId = "00000000-0000-0000-0000-000000000000", verifyFactorCode = "123456"}
        "{\"challenge_id\":\"00000000-0000-0000-0000-000000000000\",\"code\":\"123456\"}"
    roundTrip
        "VerifyFactorResponse"
        (VerifyFactorResponse canonicalSessionResponse)
        sessionResponseJson

    -- Admin: users, identities, generate_link, invite, providers, email_templates
    roundTrip
        "ListUsersResponse"
        ListUsersResponse
            { listUsers = [canonicalUserResponse]
            , listUsersAud = "authenticated"
            , listUsersNextPage = Just 2
            }
        ("{\"users\":[" <> userResponseJson <> "],\"aud\":\"authenticated\",\"next_page\":2}")
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
    roundTrip
        "DeletedUserResponse"
        (DeletedUserResponse canonicalUserResponse)
        ("{\"user\":" <> userResponseJson <> "}")
    roundTrip
        "ListIdentitiesResponse"
        ListIdentitiesResponse{listIdentities = [canonicalIdentityResponse]}
        ("{\"identities\":[" <> identityResponseJson <> "]}")
    roundTrip
        "GenerateLinkRequest"
        GenerateLinkRequest
            { generateLinkEmail = Email "alice@example.com"
            , generateLinkType = "signup"
            }
        "{\"email\":\"alice@example.com\",\"type\":\"signup\"}"
    roundTrip
        "GenerateLinkResponse"
        GenerateLinkResponse{generateLinkActionLink = "https://auth.example.com/verify?token=...&type=signup"}
        "{\"action_link\":\"https://auth.example.com/verify?token=...&type=signup\"}"
    roundTrip
        "InviteUserRequest"
        InviteUserRequest
            { inviteUserEmail = Email "alice@example.com"
            , inviteUserData = Just (Aeson.object [])
            }
        "{\"email\":\"alice@example.com\",\"data\":{}}"
    roundTrip
        "ProvidersResponse"
        ProvidersResponse{providers = ["google", "github"]}
        "{\"providers\":[\"google\",\"github\"]}"
    roundTrip
        "UpdateProvidersRequest"
        UpdateProvidersRequest{updateProviders = ["google", "github"]}
        "{\"providers\":[\"google\",\"github\"]}"
    roundTrip
        "EmailTemplatesResponse"
        EmailTemplatesResponse{emailTemplates = ["confirmation", "recovery"]}
        "{\"templates\":[\"confirmation\",\"recovery\"]}"
    roundTrip
        "UpdateEmailTemplatesRequest"
        UpdateEmailTemplatesRequest{updateEmailTemplates = ["confirmation", "recovery"]}
        "{\"templates\":[\"confirmation\",\"recovery\"]}"
    roundTrip
        "EmailTemplateCrudRequest"
        EmailTemplateCrudRequest
            { emailTemplateCrudSubject = "Confirm"
            , emailTemplateCrudBodyText = "txt"
            , emailTemplateCrudBodyHtml = "<p>html</p>"
            }
        "{\"subject\":\"Confirm\",\"body_text\":\"txt\",\"body_html\":\"<p>html</p>\"}"
    roundTrip
        "EmailTemplateRow"
        canonicalEmailTemplateRow
        emailTemplateRowJson
    roundTrip
        "EmailTemplatesListResponse"
        EmailTemplatesListResponse{emailTemplatesList = [canonicalEmailTemplateRow]}
        ("{\"templates\":[" <> emailTemplateRowJson <> "]}")

    -- Webhook subscriptions
    roundTrip
        "WebhookSubscriptionResponse"
        canonicalWebhookSubResponse
        webhookSubJson
    roundTrip
        "ListWebhookSubscriptionsResponse"
        ListWebhookSubscriptionsResponse{listWebhookSubscriptions = [canonicalWebhookSubResponse]}
        ("{\"webhooks\":[" <> webhookSubJson <> "]}")
    roundTrip
        "CreateWebhookSubscriptionRequest"
        CreateWebhookSubscriptionRequest
            { createWebhookSubUrl = "https://example.com/wh"
            , createWebhookSubEvents = Just ["user.signed_up"]
            , createWebhookSubSecret = Just "shh"
            }
        "{\"url\":\"https://example.com/wh\",\"events\":[\"user.signed_up\"],\"secret\":\"shh\"}"
    roundTrip
        "UpdateWebhookSubscriptionRequest"
        UpdateWebhookSubscriptionRequest
            { updateWebhookSubUrl = Just "https://example.com/wh2"
            , updateWebhookSubEvents = Just ["user.signed_up"]
            , updateWebhookSubSecret = Just "shh"
            , updateWebhookSubDisabledAt = Just (Just t0)
            }
        "{\"url\":\"https://example.com/wh2\",\"events\":[\"user.signed_up\"]\
        \,\"secret\":\"shh\",\"disabled_at\":\"2026-01-02T03:04:05Z\"}"

    -- Webhook deliveries
    roundTrip
        "WebhookDeliveryResponse"
        canonicalWebhookDeliveryResponse
        webhookDeliveryJson
    roundTrip
        "ListWebhookDeliveriesResponse"
        ListWebhookDeliveriesResponse
            { listDeliveries = [canonicalWebhookDeliveryResponse]
            , listDeliveriesNextPage = Nothing
            }
        ("{\"deliveries\":[" <> webhookDeliveryJson <> "],\"next_page\":null}")
    roundTrip
        "WebhookDeliveriesResponse"
        WebhookDeliveriesResponse{webhookDeliveries = [canonicalWebhookDeliveryResponse]}
        ("{\"deliveries\":[" <> webhookDeliveryJson <> "]}")

    -- Sync hooks
    roundTrip
        "HookRow"
        canonicalHookRow
        hookRowJson
    decodeShape
        "CreateHookRequest"
        "{\"hook_point\":\"before-user-created\",\"url\":\"https://example.com/hook\"\
        \,\"secret\":\"shh\",\"timeout_ms\":1000,\"fail_open\":true,\"enabled\":true}"
        CreateHookRequest
            { createHookPoint = "before-user-created"
            , createHookUrl = "https://example.com/hook"
            , createHookSecret = Just "shh"
            , createHookTimeoutMs = Just 1000
            , createHookFailOpen = Just True
            , createHookEnabled = Just True
            }
    decodeShape
        "UpdateHookRequest"
        "{\"url\":\"https://example.com/hook2\",\"enabled\":false}"
        UpdateHookRequest
            { updateHookUrl = Just "https://example.com/hook2"
            , updateHookSecret = Nothing
            , updateHookTimeoutMs = Nothing
            , updateHookFailOpen = Nothing
            , updateHookEnabled = Just False
            }
    encodeShape
        "ListHooksResponse"
        ListHooksResponse{listHookRows = [canonicalHookRow]}
        ("{\"hooks\":[" <> hookRowJson <> "]}")

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
        Left diff -> fail (label <> " encode shape mismatch:" <> diff)
    case Aeson.eitherDecode expected of
        Left e -> fail (label <> " decode failed: " <> e)
        Right decoded -> assertEqual (label <> " decode roundtrip") value decoded

-- | For response-only types: just check the encoded shape.
encodeShape :: (ToJSON a) => String -> a -> BSL.ByteString -> IO ()
encodeShape label value expected =
    case shapeEq (Aeson.encode value) expected of
        Right () -> pure ()
        Left diff -> fail (label <> " encode shape mismatch:" <> diff)

-- | For request-only types: decode the input and compare to expected value.
decodeShape :: (Eq a, Show a, FromJSON a) => String -> BSL.ByteString -> a -> IO ()
decodeShape label input expected =
    case Aeson.eitherDecode input of
        Left e -> fail (label <> " decode failed: " <> e)
        Right decoded -> assertEqual (label <> " decode") expected decoded

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

webhookSubJson :: BSL.ByteString
webhookSubJson =
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

hookRowJson :: BSL.ByteString
hookRowJson =
    "{\"id\":\"00000000-0000-0000-0000-000000000000\"\
    \,\"hook_point\":\"before-user-created\"\
    \,\"url\":\"https://example.com/hook\",\"secret\":\"shh\"\
    \,\"timeout_ms\":1000,\"fail_open\":true,\"enabled\":true}"
