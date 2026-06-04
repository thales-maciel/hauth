{- | Wire-shape coverage for the public auth surface: signup, token, recover,
verify, resend, update-user, session, OAuth authorize.
-}
module Spec.API.Golden.AuthSpec (spec) where

import qualified Data.Aeson as Aeson
import Data.Text (Text)
import qualified Data.UUID as UUID
import Hauth.API.Types
import Spec.API.Golden.Helpers (
    canonicalSessionResponse,
    canonicalUserResponse,
    decodeShape,
    encodeShape,
    roundTrip,
    sessionResponseJson,
    t0,
    userResponseJson,
    uuid0,
 )
import Test.Hspec (Spec, describe, it)

spec :: Spec
spec = describe "Auth" $ do
    it "SignupRequest" $
        roundTrip
            "SignupRequest"
            SignupRequest
                { signupEmail = Email "alice@example.com"
                , signupPassword = Password "correct horse"
                , signupData = Just (Aeson.object ["foo" Aeson..= ("bar" :: Text)])
                }
            "{\"email\":\"alice@example.com\",\"password\":\"correct horse\",\"data\":{\"foo\":\"bar\"}}"

    it "SignupResponse" $
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

    it "TokenRequest (refresh_token)" $
        decodeShape
            "TokenRequest (refresh_token)"
            "{\"refresh_token\":\"rt-1\"}"
            TokenRequest{tokenRequestRefreshToken = Just "rt-1", tokenRequestEmail = Nothing, tokenRequestPassword = Nothing}

    it "TokenRequest (password)" $
        decodeShape
            "TokenRequest (password)"
            "{\"email\":\"alice@example.com\",\"password\":\"pw\"}"
            TokenRequest
                { tokenRequestRefreshToken = Nothing
                , tokenRequestEmail = Just (Email "alice@example.com")
                , tokenRequestPassword = Just (Password "pw")
                }

    it "TokenResponse" $
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

    it "RecoverRequest" $
        roundTrip
            "RecoverRequest"
            (RecoverRequest (Email "alice@example.com"))
            "{\"email\":\"alice@example.com\"}"

    it "VerifyRequest" $
        roundTrip
            "VerifyRequest"
            VerifyRequest
                { verifyToken = "tok"
                , verifyType = "signup"
                , verifyEmail = Just "alice@example.com"
                , verifyPassword = Nothing
                }
            "{\"token\":\"tok\",\"type\":\"signup\",\"email\":\"alice@example.com\",\"password\":null}"

    it "ResendRequest" $
        roundTrip
            "ResendRequest"
            ResendRequest
                { resendEmail = Email "alice@example.com"
                , resendType = "signup"
                }
            "{\"email\":\"alice@example.com\",\"type\":\"signup\"}"

    it "UpdateUserRequest" $
        roundTrip
            "UpdateUserRequest"
            UpdateUserRequest
                { updateUserEmail = Just (Email "bob@example.com")
                , updateUserPassword = Just (Password "pw")
                , updateUserData = Just (Aeson.object [])
                }
            "{\"email\":\"bob@example.com\",\"password\":\"pw\",\"data\":{}}"

    it "SessionResponse" $
        roundTrip
            "SessionResponse"
            canonicalSessionResponse
            sessionResponseJson

    it "UserResponse" $
        roundTrip
            "UserResponse"
            canonicalUserResponse
            userResponseJson

    it "MessageResponse" $
        roundTrip
            "MessageResponse"
            MessageResponse{message = "ok"}
            "{\"message\":\"ok\"}"

    it "OAuthAuthorizeResponse" $
        roundTrip
            "OAuthAuthorizeResponse"
            OAuthAuthorizeResponse
                { oauthAuthorizeUrl = "https://accounts.google.com/o/oauth2/v2/auth?...."
                , oauthAuthorizeState = "state-abc"
                }
            "{\"url\":\"https://accounts.google.com/o/oauth2/v2/auth?....\",\"state\":\"state-abc\"}"
