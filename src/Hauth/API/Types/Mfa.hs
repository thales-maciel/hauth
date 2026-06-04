-- | Wire types for the MFA endpoints: enroll, list, challenge, verify.
module Hauth.API.Types.Mfa (
    FactorId (..),
    ListFactorsResponse (..),
    EnrollFactorRequest (..),
    FactorTotpData (..),
    FactorResponse (..),
    EnrollError (..),
    validateEnrollRequest,
    buildFactorResponse,
    ChallengeFactorRequest (..),
    ChallengeFactorResponse (..),
    VerifyFactorRequest (..),
    VerifyFactorResponse (..),
) where

import Data.Aeson (FromJSON (..), ToJSON (toJSON), Value, object, withObject, (.=))
import qualified Data.Aeson as Aeson
import Data.Text (Text)
import Data.Time (UTCTime)
import Data.UUID (UUID)
import qualified Data.UUID as UUID
import GHC.Generics (Generic)
import Hauth.API.Types.Auth (SessionResponse)
import Web.HttpApiData (FromHttpApiData, ToHttpApiData)

newtype FactorId = FactorId {unFactorId :: Text}
    deriving stock (Eq, Generic, Ord, Show)
    deriving newtype (FromHttpApiData, FromJSON, ToHttpApiData, ToJSON)

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
