module Spec.Auth.LoginSpec (runSpec) where

import qualified Data.Aeson as Aeson
import Data.Time.Clock (getCurrentTime)
import qualified Data.UUID as UUID
import Hauth.API.Types (
    Email (..),
    Password (..),
    TokenRequest (..),
 )
import Hauth.Auth.Jwt (
    AccessTokenClaims (..),
    AmrEntry (..),
    signAccessToken,
    validateAccessToken,
 )
import Hauth.Auth.Login (
    LoginError (..),
    authorizeLogin,
    buildLoginClaims,
    extractCredentials,
 )
import Hauth.Config (JwtConfig (..))
import Hauth.Session (SessionId (..))
import Hauth.User (
    User (..),
    UserId (..),
 )
import Spec.TestUtils (assertEqual)

runSpec :: IO ()
runSpec = do
    let noEmailReq =
            TokenRequest
                { tokenRequestRefreshToken = Nothing
                , tokenRequestEmail = Nothing
                , tokenRequestPassword = Just (Password "secret")
                }
    assertEqual
        "extractCredentials missing email"
        (Left LoginMissingFields)
        (extractCredentials noEmailReq)
    let blankEmailReq =
            TokenRequest
                { tokenRequestRefreshToken = Nothing
                , tokenRequestEmail = Just (Email "")
                , tokenRequestPassword = Just (Password "secret")
                }
    assertEqual
        "extractCredentials blank email"
        (Left LoginMissingFields)
        (extractCredentials blankEmailReq)
    let noPasswordReq =
            TokenRequest
                { tokenRequestRefreshToken = Nothing
                , tokenRequestEmail = Just (Email "user@example.com")
                , tokenRequestPassword = Nothing
                }
    assertEqual
        "extractCredentials missing password"
        (Left LoginMissingFields)
        (extractCredentials noPasswordReq)
    let blankPasswordReq =
            TokenRequest
                { tokenRequestRefreshToken = Nothing
                , tokenRequestEmail = Just (Email "user@example.com")
                , tokenRequestPassword = Just (Password "")
                }
    assertEqual
        "extractCredentials blank password"
        (Left LoginMissingFields)
        (extractCredentials blankPasswordReq)
    let fullCredsReq =
            TokenRequest
                { tokenRequestRefreshToken = Nothing
                , tokenRequestEmail = Just (Email "user@example.com")
                , tokenRequestPassword = Just (Password "mysecret")
                }
    assertEqual
        "extractCredentials both present"
        (Right ("user@example.com", "mysecret"))
        (extractCredentials fullCredsReq)
    now4 <- getCurrentTime
    assertEqual
        "authorizeLogin wrong password + confirmed"
        (Left LoginInvalidGrant)
        (authorizeLogin False (Just now4))
    assertEqual
        "authorizeLogin wrong password + unconfirmed"
        (Left LoginInvalidGrant)
        (authorizeLogin False Nothing)
    assertEqual
        "authorizeLogin correct password + unconfirmed"
        (Left LoginEmailNotConfirmed)
        (authorizeLogin True Nothing)
    assertEqual
        "authorizeLogin correct password + confirmed"
        (Right ())
        (authorizeLogin True (Just now4))
    now5 <- getCurrentTime
    let loginSid = SessionId UUID.nil
        loginUser =
            User
                { userId = UserId UUID.nil
                , userEmail = Just "login@example.com"
                , userEncryptedPassword = Just "$argon2id$v=19$..."
                , userEmailConfirmedAt = Just now5
                , userConfirmationToken = Nothing
                , userConfirmationSentAt = Nothing
                , userRawAppMetaData = Aeson.object []
                , userRawUserMetaData = Aeson.object []
                , userRole = "authenticated"
                , userAud = "authenticated"
                , userCreatedAt = now5
                , userUpdatedAt = now5
                }
        loginCfg =
            JwtConfig
                { jwtSecret = "0123456789abcdef0123456789abcdef"
                , jwtIssuer = "https://auth.example.com"
                , jwtAudience = "authenticated"
                , jwtAccessTokenTtlSeconds = 3600
                , jwtRefreshTokenTtlSeconds = 2592000
                }
        loginClaims = buildLoginClaims loginCfg loginUser loginSid now5
    assertEqual
        "buildLoginClaims sub = userId"
        (UUID.toText UUID.nil)
        (claimSub loginClaims)
    assertEqual
        "buildLoginClaims email"
        (Just "login@example.com")
        (claimEmail loginClaims)
    assertEqual
        "buildLoginClaims aal"
        "aal1"
        (claimAal loginClaims)
    assertEqual
        "buildLoginClaims amr length 1"
        1
        (length (claimAmr loginClaims))
    assertEqual
        "buildLoginClaims amr method password"
        "password"
        (amrMethod (head (claimAmr loginClaims)))
    assertEqual
        "buildLoginClaims session_id"
        (UUID.toText UUID.nil)
        (claimSessionId loginClaims)
    loginSignResult <- signAccessToken loginCfg loginClaims
    case loginSignResult of
        Left err ->
            fail ("login claims round-trip sign failed: " <> show err)
        Right loginToken -> do
            loginValidateResult <- validateAccessToken loginCfg loginToken
            case loginValidateResult of
                Left err ->
                    fail ("login claims round-trip validate failed: " <> show err)
                Right loginClaims' -> do
                    assertEqual
                        "login round-trip sub"
                        (claimSub loginClaims)
                        (claimSub loginClaims')
                    assertEqual
                        "login round-trip email"
                        (claimEmail loginClaims)
                        (claimEmail loginClaims')
                    assertEqual
                        "login round-trip aal"
                        (claimAal loginClaims)
                        (claimAal loginClaims')
                    assertEqual
                        "login round-trip amr length"
                        (length (claimAmr loginClaims))
                        (length (claimAmr loginClaims'))
                    assertEqual
                        "login round-trip amr method"
                        (amrMethod (head (claimAmr loginClaims)))
                        (amrMethod (head (claimAmr loginClaims')))
                    assertEqual
                        "login round-trip session_id"
                        (claimSessionId loginClaims)
                        (claimSessionId loginClaims')
