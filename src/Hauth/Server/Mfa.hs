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
import Data.Time.Clock.POSIX (getPOSIXTime, utcTimeToPOSIXSeconds)
import Data.UUID (UUID)
import qualified Data.UUID as UUID
import qualified Data.UUID.V4 as UUID4

import Hauth.API.Auth (SessionPrincipal (..))
import Hauth.API.Types
import Hauth.Auth.Jwt (AccessTokenClaims (..), AmrEntry (..), signAccessToken)
import Hauth.Config (Config (..), JwtConfig (..))
import Hauth.Env (AppEnv (..), withDatabaseConnection)
import Hauth.Mfa.Totp (TotpSecret (..), decodeBase32, encodeBase32, generateTotpSecret, otpAuthUri, unTotpSecret)
import Hauth.Mfa.TotpVerify (TotpVerificationResult (..), verifyTotpCode)
import qualified Hauth.MfaFactor as MfaFactor
import Hauth.Session (
    NewSession (..),
    SessionId (..),
    createRefreshToken,
    createSession,
    refreshTokenToken,
    sessionId,
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
1. Look up the factor; 404 if not found, 403 if foreign.
2. Decode the BASE32 secret; 500 if the DB row is corrupt.
3. Verify the candidate code; 401 if invalid.
4. On success: update status to verified (if unverified), create an aal2
   session, sign a JWT with aal=aal2 and amr=[totp], and return the session.
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
            when (MfaFactor.mfaFactorStatus factor == MfaFactor.FactorUnverified) $
                liftIO $
                    withDatabaseConnection env \conn ->
                        MfaFactor.updateFactorStatus conn (MfaFactor.mfaFactorId factor) MfaFactor.FactorVerified
            let newSess =
                    NewSession
                        { newSessionUserId = uid
                        , newSessionAal = "aal2"
                        , newSessionFactorId = Just factorUuid
                        , newSessionUserAgent = Nothing
                        , newSessionIp = Nothing
                        , newSessionNotAfter = Nothing
                        }
            (sess, refreshTok) <- liftIO $
                withDatabaseConnection env \conn -> do
                    s <- createSession conn newSess
                    rt <- createRefreshToken conn (sessionId s) Nothing
                    pure (s, rt)
            nowUtc <- liftIO getCurrentTime
            let sid = sessionId sess
                ttl = fromIntegral jwtAccessTokenTtlSeconds
                expiryUtc = addUTCTime ttl nowUtc
                iatSecs = floor (utcTimeToPOSIXSeconds nowUtc) :: Integer
                claims =
                    AccessTokenClaims
                        { claimSub = UUID.toText uid
                        , claimRole = "authenticated"
                        , claimEmail = Nothing
                        , claimPhone = Nothing
                        , claimAppMetadata = Aeson.object []
                        , claimUserMetadata = Aeson.object []
                        , claimAal = "aal2"
                        , claimAmr =
                            [ AmrEntry
                                { amrMethod = "totp"
                                , amrTimestamp = iatSecs
                                }
                            ]
                        , claimSessionId = UUID.toText (unSessionId sid)
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
