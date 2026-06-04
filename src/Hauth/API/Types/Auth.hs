{- | Wire types for the public auth surface: signup, token (refresh and
password grants), recover, verify, resend, settings, and update-user.
-}
module Hauth.API.Types.Auth (
    SignupRequest (..),
    SignupResponse (..),
    TokenRequest (..),
    GrantType (..),
    parseGrantType,
    RefreshTokenError (..),
    ValidRefreshToken (..),
    classifyRefreshTokenLookup,
    TokenResponse (..),
    RecoverRequest (..),
    VerifyRequest (..),
    ResendRequest (..),
    UpdateUserRequest (..),
    SessionResponse (..),
    buildSessionResponse,
    buildSignupResponse,
) where

import Data.Aeson (FromJSON (..), ToJSON (toJSON), Value, object, withObject, (.:?), (.=))
import qualified Data.Aeson as Aeson
import Data.Text (Text)
import Data.Time (UTCTime)
import Data.UUID (UUID)
import GHC.Generics (Generic)
import Hauth.API.Types.Common (Email, Password, UserResponse)
import Hauth.Session (RefreshToken (..))
import qualified Hauth.User as User

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
