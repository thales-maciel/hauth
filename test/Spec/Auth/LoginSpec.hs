module Spec.Auth.LoginSpec (spec) where

import qualified Data.Aeson as Aeson
import Data.Time.Clock (UTCTime, getCurrentTime)
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
import Test.Hspec (Spec, describe, expectationFailure, it, shouldBe)

loginCfg :: JwtConfig
loginCfg =
    JwtConfig
        { jwtSecret = "0123456789abcdef0123456789abcdef"
        , jwtIssuer = "https://auth.example.com"
        , jwtAudience = "authenticated"
        , jwtAccessTokenTtlSeconds = 3600
        , jwtRefreshTokenTtlSeconds = 2592000
        }

mkLoginUser :: UTCTime -> User
mkLoginUser now =
    User
        { userId = UserId UUID.nil
        , userEmail = Just "login@example.com"
        , userEncryptedPassword = Just "$argon2id$v=19$..."
        , userEmailConfirmedAt = Just now
        , userConfirmationToken = Nothing
        , userConfirmationSentAt = Nothing
        , userRawAppMetaData = Aeson.object []
        , userRawUserMetaData = Aeson.object []
        , userRole = "authenticated"
        , userAud = "authenticated"
        , userCreatedAt = now
        , userUpdatedAt = now
        }

spec :: Spec
spec = do
    describe "extractCredentials" $ do
        it "missing email" $
            let noEmailReq =
                    TokenRequest
                        { tokenRequestRefreshToken = Nothing
                        , tokenRequestEmail = Nothing
                        , tokenRequestPassword = Just (Password "secret")
                        }
             in extractCredentials noEmailReq `shouldBe` Left LoginMissingFields
        it "blank email" $
            let blankEmailReq =
                    TokenRequest
                        { tokenRequestRefreshToken = Nothing
                        , tokenRequestEmail = Just (Email "")
                        , tokenRequestPassword = Just (Password "secret")
                        }
             in extractCredentials blankEmailReq `shouldBe` Left LoginMissingFields
        it "missing password" $
            let noPasswordReq =
                    TokenRequest
                        { tokenRequestRefreshToken = Nothing
                        , tokenRequestEmail = Just (Email "user@example.com")
                        , tokenRequestPassword = Nothing
                        }
             in extractCredentials noPasswordReq `shouldBe` Left LoginMissingFields
        it "blank password" $
            let blankPasswordReq =
                    TokenRequest
                        { tokenRequestRefreshToken = Nothing
                        , tokenRequestEmail = Just (Email "user@example.com")
                        , tokenRequestPassword = Just (Password "")
                        }
             in extractCredentials blankPasswordReq `shouldBe` Left LoginMissingFields
        it "both present" $
            let fullCredsReq =
                    TokenRequest
                        { tokenRequestRefreshToken = Nothing
                        , tokenRequestEmail = Just (Email "user@example.com")
                        , tokenRequestPassword = Just (Password "mysecret")
                        }
             in extractCredentials fullCredsReq `shouldBe` Right ("user@example.com", "mysecret")

    describe "authorizeLogin" $ do
        it "wrong password + confirmed" $ do
            now4 <- getCurrentTime
            authorizeLogin False (Just now4) `shouldBe` Left LoginInvalidGrant
        it "wrong password + unconfirmed" $
            authorizeLogin False Nothing `shouldBe` Left LoginInvalidGrant
        it "correct password + unconfirmed" $
            authorizeLogin True Nothing `shouldBe` Left LoginEmailNotConfirmed
        it "correct password + confirmed" $ do
            now4 <- getCurrentTime
            authorizeLogin True (Just now4) `shouldBe` Right ()

    describe "buildLoginClaims" $ do
        it "sub = userId" $ do
            now5 <- getCurrentTime
            let claims = buildLoginClaims loginCfg (mkLoginUser now5) (SessionId UUID.nil) now5
            claimSub claims `shouldBe` UUID.toText UUID.nil
        it "email" $ do
            now5 <- getCurrentTime
            let claims = buildLoginClaims loginCfg (mkLoginUser now5) (SessionId UUID.nil) now5
            claimEmail claims `shouldBe` Just "login@example.com"
        it "aal" $ do
            now5 <- getCurrentTime
            let claims = buildLoginClaims loginCfg (mkLoginUser now5) (SessionId UUID.nil) now5
            claimAal claims `shouldBe` "aal1"
        it "amr length 1" $ do
            now5 <- getCurrentTime
            let claims = buildLoginClaims loginCfg (mkLoginUser now5) (SessionId UUID.nil) now5
            length (claimAmr claims) `shouldBe` 1
        it "amr method password" $ do
            now5 <- getCurrentTime
            let claims = buildLoginClaims loginCfg (mkLoginUser now5) (SessionId UUID.nil) now5
            amrMethod (head (claimAmr claims)) `shouldBe` "password"
        it "session_id" $ do
            now5 <- getCurrentTime
            let claims = buildLoginClaims loginCfg (mkLoginUser now5) (SessionId UUID.nil) now5
            claimSessionId claims `shouldBe` UUID.toText UUID.nil

    describe "login claims round-trip" $
        it "sign + validate preserves all login claim fields" $ do
            now5 <- getCurrentTime
            let loginClaims = buildLoginClaims loginCfg (mkLoginUser now5) (SessionId UUID.nil) now5
            loginSignResult <- signAccessToken loginCfg loginClaims
            case loginSignResult of
                Left err ->
                    expectationFailure ("login claims round-trip sign failed: " <> show err)
                Right loginToken -> do
                    loginValidateResult <- validateAccessToken loginCfg loginToken
                    case loginValidateResult of
                        Left err ->
                            expectationFailure ("login claims round-trip validate failed: " <> show err)
                        Right loginClaims' -> do
                            claimSub loginClaims' `shouldBe` claimSub loginClaims
                            claimEmail loginClaims' `shouldBe` claimEmail loginClaims
                            claimAal loginClaims' `shouldBe` claimAal loginClaims
                            length (claimAmr loginClaims') `shouldBe` length (claimAmr loginClaims)
                            amrMethod (head (claimAmr loginClaims'))
                                `shouldBe` amrMethod (head (claimAmr loginClaims))
                            claimSessionId loginClaims' `shouldBe` claimSessionId loginClaims
