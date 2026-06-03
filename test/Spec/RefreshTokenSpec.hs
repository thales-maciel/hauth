module Spec.RefreshTokenSpec (spec) where

import Data.Aeson (Object, Value (..))
import qualified Data.Aeson as Aeson
import qualified Data.Aeson.KeyMap as KeyMap
import qualified Data.Text as T
import Data.Time.Clock (getCurrentTime)
import qualified Data.UUID as UUID
import Hauth.API.Types (
    Email (..),
    GrantType (..),
    Password (..),
    RefreshTokenError (..),
    TokenRequest (..),
    TokenResponse (..),
    ValidRefreshToken (..),
    classifyRefreshTokenLookup,
    parseGrantType,
 )
import Hauth.Session (
    RefreshToken (..),
    RefreshTokenId (..),
    SessionId (..),
 )
import Test.Hspec (Spec, describe, expectationFailure, it, shouldBe)

spec :: Spec
spec = do
    describe "classifyRefreshTokenLookup" $ do
        it "Nothing yields InvalidGrant" $
            classifyRefreshTokenLookup Nothing `shouldBe` Left InvalidGrant

        it "revoked token yields RefreshTokenReuseDetected" $ do
            now <- getCurrentTime
            let revokedRt =
                    RefreshToken
                        { refreshTokenId = RefreshTokenId 1
                        , refreshTokenToken = "revoked-token"
                        , refreshTokenSessionId = SessionId UUID.nil
                        , refreshTokenUserId = UUID.nil
                        , refreshTokenParent = Nothing
                        , refreshTokenRevoked = True
                        , refreshTokenCreatedAt = now
                        , refreshTokenUpdatedAt = now
                        }
            classifyRefreshTokenLookup (Just revokedRt) `shouldBe` Left RefreshTokenReuseDetected

        it "valid token yields ValidRefreshToken with correct token value" $ do
            now <- getCurrentTime
            let baseRt =
                    RefreshToken
                        { refreshTokenId = RefreshTokenId 1
                        , refreshTokenToken = "revoked-token"
                        , refreshTokenSessionId = SessionId UUID.nil
                        , refreshTokenUserId = UUID.nil
                        , refreshTokenParent = Nothing
                        , refreshTokenRevoked = True
                        , refreshTokenCreatedAt = now
                        , refreshTokenUpdatedAt = now
                        }
                validRt = baseRt{refreshTokenRevoked = False, refreshTokenToken = "valid-token"}
            case classifyRefreshTokenLookup (Just validRt) of
                Left e ->
                    expectationFailure ("expected Right, got Left: " <> show e)
                Right (ValidRefreshToken rt) ->
                    refreshTokenToken rt `shouldBe` "valid-token"

    describe "TokenResponse JSON" $
        it "encodes required keys and values" $ do
            let testTokenResp =
                    TokenResponse
                        { tokenResponseAccessToken = "access.token.here"
                        , tokenResponseTokenType = "bearer"
                        , tokenResponseExpiresIn = 3600
                        , tokenResponseRefreshToken = "opaque-refresh"
                        , tokenResponseUser = Aeson.object ["id" Aeson..= ("uid" :: T.Text)]
                        }
            case Aeson.decode (Aeson.encode testTokenResp) of
                Nothing ->
                    expectationFailure "JSON decode failed"
                Just (obj :: Object) -> do
                    let tokenRespKeys = ["access_token", "token_type", "expires_in", "refresh_token", "user"]
                    mapM_
                        ( \k ->
                            if KeyMap.member k obj
                                then pure ()
                                else expectationFailure ("missing key: " <> show k)
                        )
                        tokenRespKeys
                    KeyMap.lookup "token_type" obj `shouldBe` Just (String "bearer")
                    KeyMap.lookup "expires_in" obj `shouldBe` Just (Number 3600)

    describe "TokenRequest JSON parsing" $ do
        it "parses {refresh_token}" $
            case Aeson.decode "{\"refresh_token\": \"abc\"}" of
                Nothing -> expectationFailure "parse failed"
                Just tr ->
                    tokenRequestRefreshToken tr `shouldBe` Just "abc"

        it "parses {} as all-Nothing" $
            case Aeson.decode "{}" of
                Nothing -> expectationFailure "parse failed"
                Just (tr :: TokenRequest) -> do
                    tokenRequestRefreshToken tr `shouldBe` Nothing
                    tokenRequestEmail tr `shouldBe` Nothing
                    tokenRequestPassword tr `shouldBe` Nothing

        it "parses {email, password}" $
            case Aeson.decode "{\"email\": \"a@b.c\", \"password\": \"x\"}" of
                Nothing -> expectationFailure "parse failed"
                Just tr -> do
                    tokenRequestEmail tr `shouldBe` Just (Email "a@b.c")
                    tokenRequestPassword tr `shouldBe` Just (Password "x")

    describe "parseGrantType" $ do
        it "password" $
            parseGrantType (Just "password") `shouldBe` GrantPassword
        it "refresh_token" $
            parseGrantType (Just "refresh_token") `shouldBe` GrantRefreshToken
        it "client_credentials is unsupported" $
            parseGrantType (Just "client_credentials")
                `shouldBe` GrantUnsupported "client_credentials"
        it "Nothing is unsupported with empty label" $
            parseGrantType Nothing `shouldBe` GrantUnsupported ""
