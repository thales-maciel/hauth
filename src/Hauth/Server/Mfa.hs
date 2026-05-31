module Hauth.Server.Mfa (
    challengeFactorHandler,
    enrollFactorHandler,
    factorStatusText,
    listFactorsHandler,
    parseSessionUuid,
    verifyFactorHandler,
) where

import Control.Monad (when)
import Control.Monad.Except (throwError)
import Control.Monad.IO.Class (liftIO)
import Control.Monad.Reader (ReaderT, ask)
import qualified Data.Aeson as Aeson
import Data.Maybe (fromMaybe)
import Data.Text (Text)
import qualified Data.Text as T
import Data.Time.Clock (addUTCTime, getCurrentTime)
import Data.Time.Clock.POSIX (getPOSIXTime)
import Data.UUID (UUID)
import qualified Data.UUID as UUID
import qualified Data.UUID.V4 as UUID4

import Hauth.API.Auth (SessionPrincipal (..))
import Hauth.API.Types
import Hauth.Auth.AalAmr (SessionAuthState (..), buildAmrEntries, deriveSessionAuthState)
import Hauth.Auth.Jwt (AccessTokenClaims (..), signAccessToken)
import Hauth.Config (Config (..), JwtConfig (..))
import Hauth.Env (AppEnv (..), withDatabaseConnection)
import Hauth.Mfa.Totp (TotpSecret (..), decodeBase32, encodeBase32, generateTotpSecret, otpAuthUri, unTotpSecret)
import Hauth.Mfa.TotpVerify (TotpVerificationResult (..), verifyTotpCode)
import qualified Hauth.MfaFactor as MfaFactor
import Hauth.Session (
    SessionId (..),
    getActiveRefreshTokenForSession,
    refreshTokenToken,
    unSessionId,
    updateSessionAalFactor,
 )
import qualified Hauth.User as User
import Servant.Server (
    Handler,
    ServerError (errBody),
    err400,
    err401,
    err403,
    err404,
    err500,
 )

type AppHandler = ReaderT AppEnv Handler

-- ---------------------------------------------------------------------------
-- List factors
-- ---------------------------------------------------------------------------

listFactorsHandler :: SessionPrincipal -> AppHandler ListFactorsResponse
listFactorsHandler principal = do
    env <- ask
    uid <- parseSessionUuid principal
    factors <- liftIO (withDatabaseConnection env (`MfaFactor.listFactorsForUser` uid))
    let toFactorResp f =
            FactorResponse
                { factorResponseId = FactorId (UUID.toText (MfaFactor.unMfaFactorId (MfaFactor.mfaFactorId f)))
                , factorResponseType = "totp"
                , factorResponseFriendlyName = MfaFactor.mfaFactorFriendlyName f
                , factorResponseStatus = factorStatusText (MfaFactor.mfaFactorStatus f)
                , factorResponseTotp = Nothing
                }
        allFactors = fmap toFactorResp factors
        verifiedTotp =
            filter
                ( \f ->
                    factorResponseStatus f == "verified"
                        && factorResponseType f == "totp"
                )
                allFactors
    pure
        ListFactorsResponse
            { listFactorsAll = allFactors
            , listFactorsTotp = verifiedTotp
            , listFactorsPhone = []
            }

-- ---------------------------------------------------------------------------
-- Enroll factor
-- ---------------------------------------------------------------------------

enrollFactorHandler :: SessionPrincipal -> EnrollFactorRequest -> AppHandler FactorResponse
enrollFactorHandler principal req@EnrollFactorRequest{enrollFactorFriendlyName, enrollFactorIssuer} = do
    case validateEnrollRequest req of
        Left (EnrollUnsupportedFactorType ft) ->
            throwError
                err400
                    { errBody =
                        Aeson.encode $
                            Aeson.object
                                [ "error" Aeson..= ("unsupported_factor_type" :: Text)
                                , "error_description" Aeson..= ("Unsupported factor type: " <> ft)
                                ]
                    }
        Right () -> pure ()
    env <- ask
    let AppEnv{appConfig} = env
        Config{configJwt = JwtConfig{jwtIssuer}} = appConfig
        issuer = fromMaybe jwtIssuer enrollFactorIssuer
    uid <- parseSessionUuid principal
    mUser <- liftIO (withDatabaseConnection env (`User.getUserById` User.UserId uid))
    let label = case mUser >>= User.userEmail of
            Just email -> email
            Nothing -> UUID.toText uid
    secret <- liftIO generateTotpSecret
    let secretB32 = encodeBase32 (unTotpSecret secret)
        uri = otpAuthUri issuer label secret
    let newFactor =
            MfaFactor.NewMfaFactor
                { MfaFactor.newMfaFactorUserId = uid
                , MfaFactor.newMfaFactorFriendlyName = enrollFactorFriendlyName
                , MfaFactor.newMfaFactorType = MfaFactor.FactorTypeTotp
                , MfaFactor.newMfaFactorSecret = secretB32
                }
    factor <- liftIO (withDatabaseConnection env (`MfaFactor.createFactor` newFactor))
    pure
        FactorResponse
            { factorResponseId = FactorId (UUID.toText (MfaFactor.unMfaFactorId (MfaFactor.mfaFactorId factor)))
            , factorResponseType = "totp"
            , factorResponseFriendlyName = MfaFactor.mfaFactorFriendlyName factor
            , factorResponseStatus = factorStatusText (MfaFactor.mfaFactorStatus factor)
            , factorResponseTotp =
                Just
                    FactorTotpData
                        { factorTotpQrCode = uri
                        , factorTotpSecret = secretB32
                        , factorTotpUri = uri
                        }
            }

-- ---------------------------------------------------------------------------
-- Challenge factor
-- ---------------------------------------------------------------------------

{- | Challenge a TOTP factor.

For TOTP, no server-side state is needed — codes are time-based.
This endpoint validates the factor exists and belongs to the requesting user,
then returns a challenge id (fresh UUID) and an expiry 300 seconds from now.
-}
challengeFactorHandler ::
    SessionPrincipal ->
    FactorId ->
    ChallengeFactorRequest ->
    AppHandler ChallengeFactorResponse
challengeFactorHandler principal (FactorId factorIdText) _req = do
    env <- ask
    uid <- parseSessionUuid principal
    _factor <- lookupFactorOrError env factorIdText uid
    now <- liftIO getCurrentTime
    challengeId <- liftIO UUID4.nextRandom
    let expiresAt = addUTCTime 300 now
    pure
        ChallengeFactorResponse
            { challengeFactorId = UUID.toText challengeId
            , challengeExpiresAt = expiresAt
            }

-- ---------------------------------------------------------------------------
-- Verify factor
-- ---------------------------------------------------------------------------

{- | Verify a TOTP code against the factor secret.

Steps:
1. Parse the existing session id from the bearer JWT.
2. Look up the factor; 404 if not found, 403 if foreign.
3. Decode the BASE32 secret; 500 if the DB row is corrupt.
4. Verify the candidate code; 401 if invalid.
5. On success: update factor status to verified (if unverified), elevate the
   existing session to aal2 via 'updateSessionAalFactor', derive AAL\/AMR
   from the updated session, sign a new access token, and return it together
   with the existing (unchanged) refresh token.
-}
verifyFactorHandler ::
    SessionPrincipal ->
    FactorId ->
    VerifyFactorRequest ->
    AppHandler VerifyFactorResponse
verifyFactorHandler principal (FactorId factorIdText) VerifyFactorRequest{verifyFactorCode} = do
    env <- ask
    let AppEnv{appConfig} = env
        Config{configJwt} = appConfig
        JwtConfig{jwtAccessTokenTtlSeconds} = configJwt
    uid <- parseSessionUuid principal
    -- Parse the session id carried in the bearer JWT.
    existingSid <- case UUID.fromText (sessionAccessTokenId principal) of
        Nothing ->
            throwError
                err401
                    { errBody =
                        Aeson.encode $
                            Aeson.object
                                [ "error" Aeson..= ("invalid_session_id" :: Text)
                                , "msg" Aeson..= ("malformed session id in token" :: Text)
                                ]
                    }
        Just u -> pure (SessionId u)
    factor <- lookupFactorOrError env factorIdText uid
    let secretB32 = MfaFactor.mfaFactorSecret factor
    rawSecret <- case decodeBase32 secretB32 of
        Nothing ->
            throwError
                err500
                    { errBody =
                        Aeson.encode $
                            Aeson.object
                                [ "error" Aeson..= ("corrupt_factor" :: Text)
                                , "msg" Aeson..= ("factor secret is corrupt" :: Text)
                                ]
                    }
        Just bs -> pure bs
    let totpSecret = TotpSecret rawSecret
    now <- liftIO getPOSIXTime
    case verifyTotpCode totpSecret verifyFactorCode now of
        TotpInvalid ->
            throwError
                err401
                    { errBody =
                        Aeson.encode $
                            Aeson.object
                                [ "error" Aeson..= ("invalid_code" :: Text)
                                , "msg" Aeson..= ("TOTP code is invalid or expired" :: Text)
                                ]
                    }
        TotpVerified -> do
            let factorUuid = MfaFactor.unMfaFactorId (MfaFactor.mfaFactorId factor)
            -- Mark the factor verified if it was previously unverified.
            when (MfaFactor.mfaFactorStatus factor == MfaFactor.FactorUnverified) $
                liftIO $
                    withDatabaseConnection env \conn ->
                        MfaFactor.updateFactorStatus conn (MfaFactor.mfaFactorId factor) MfaFactor.FactorVerified
            -- Elevate the existing session to aal2.
            mUpdatedSess <- liftIO $
                withDatabaseConnection env \conn ->
                    updateSessionAalFactor conn existingSid "aal2" (Just factorUuid)
            updatedSess <- case mUpdatedSess of
                Nothing ->
                    throwError
                        err401
                            { errBody =
                                Aeson.encode $
                                    Aeson.object
                                        [ "error" Aeson..= ("invalid_session" :: Text)
                                        , "msg" Aeson..= ("session not found" :: Text)
                                        ]
                            }
                Just s -> pure s
            -- Look up the existing refresh token for this session.
            mRefreshTok <-
                liftIO $
                    withDatabaseConnection env (`getActiveRefreshTokenForSession` existingSid)
            refreshTok <- case mRefreshTok of
                Nothing ->
                    throwError
                        err401
                            { errBody =
                                Aeson.encode $
                                    Aeson.object
                                        [ "error" Aeson..= ("invalid_session" :: Text)
                                        , "msg" Aeson..= ("no active refresh token for session" :: Text)
                                        ]
                            }
                Just rt -> pure rt
            nowUtc <- liftIO getCurrentTime
            let sas = deriveSessionAuthState Nothing updatedSess
                ttl = fromIntegral jwtAccessTokenTtlSeconds
                expiryUtc = addUTCTime ttl nowUtc
                claims =
                    AccessTokenClaims
                        { claimSub = UUID.toText uid
                        , claimRole = "authenticated"
                        , claimEmail = Nothing
                        , claimPhone = Nothing
                        , claimAppMetadata = Aeson.object []
                        , claimUserMetadata = Aeson.object []
                        , claimAal = sasAal sas
                        , claimAmr = buildAmrEntries (sasMethods sas) now
                        , claimSessionId = UUID.toText (unSessionId existingSid)
                        , claimIssuedAt = nowUtc
                        , claimExpiresAt = expiryUtc
                        }
            signResult <- liftIO (signAccessToken configJwt claims)
            accessToken <- case signResult of
                Left err ->
                    throwError
                        err500
                            { errBody =
                                Aeson.encode $
                                    Aeson.object
                                        [ "error" Aeson..= ("server_error" :: Text)
                                        , "error_description" Aeson..= T.pack (show err)
                                        ]
                            }
                Right t -> pure t
            mUser <- liftIO (withDatabaseConnection env (`User.getUserById` User.UserId uid))
            userResp <- case mUser of
                Nothing ->
                    throwError
                        err500
                            { errBody =
                                Aeson.encode $
                                    Aeson.object
                                        [ "error" Aeson..= ("user_not_found" :: Text)
                                        , "msg" Aeson..= ("user referenced by session no longer exists" :: Text)
                                        ]
                            }
                Just u -> pure (buildUserResponse u)
            let sessionResp =
                    SessionResponse
                        { sessionAccessToken = accessToken
                        , sessionRefreshToken = refreshTokenToken refreshTok
                        , sessionExpiresIn = jwtAccessTokenTtlSeconds
                        , sessionUser = userResp
                        }
            pure (VerifyFactorResponse sessionResp)

-- ---------------------------------------------------------------------------
-- Shared helpers
-- ---------------------------------------------------------------------------

parseSessionUuid :: SessionPrincipal -> AppHandler UUID
parseSessionUuid principal =
    case UUID.fromText (sessionUserId principal) of
        Nothing ->
            throwError
                err401
                    { errBody =
                        Aeson.encode $
                            Aeson.object
                                [ "code" Aeson..= ("invalid_user_id" :: Text)
                                , "msg" Aeson..= ("malformed user id in token" :: Text)
                                ]
                    }
        Just u -> pure u

factorStatusText :: MfaFactor.FactorStatus -> Text
factorStatusText MfaFactor.FactorUnverified = "unverified"
factorStatusText MfaFactor.FactorVerified = "verified"

{- | Look up a factor by text UUID, checking ownership.

Returns 404 if the factor does not exist.
Returns 403 if the factor belongs to a different user.
-}
lookupFactorOrError :: AppEnv -> Text -> UUID -> AppHandler MfaFactor.MfaFactor
lookupFactorOrError env factorIdText uid = do
    factorUuid <- case UUID.fromText factorIdText of
        Nothing ->
            throwError
                err404
                    { errBody =
                        Aeson.encode $
                            Aeson.object
                                [ "error" Aeson..= ("factor_not_found" :: Text)
                                , "msg" Aeson..= ("factor not found" :: Text)
                                ]
                    }
        Just fid -> pure fid
    mFactor <- liftIO (withDatabaseConnection env (`MfaFactor.getFactor` MfaFactor.MfaFactorId factorUuid))
    factor <- case mFactor of
        Nothing ->
            throwError
                err404
                    { errBody =
                        Aeson.encode $
                            Aeson.object
                                [ "error" Aeson..= ("factor_not_found" :: Text)
                                , "msg" Aeson..= ("factor not found" :: Text)
                                ]
                    }
        Just f -> pure f
    if MfaFactor.mfaFactorUserId factor == uid
        then pure factor
        else
            throwError
                err403
                    { errBody =
                        Aeson.encode $
                            Aeson.object
                                [ "error" Aeson..= ("forbidden" :: Text)
                                , "msg" Aeson..= ("factor does not belong to this user" :: Text)
                                ]
                    }
