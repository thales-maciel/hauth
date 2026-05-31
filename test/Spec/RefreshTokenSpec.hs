module Spec.RefreshTokenSpec (runSpec) where

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
import Spec.TestUtils (assertEqual)

runSpec :: IO ()
runSpec = do
    now <- getCurrentTime
    assertEqual
        "classify Nothing → InvalidGrant"
        (Left InvalidGrant)
        (classifyRefreshTokenLookup Nothing)
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
    assertEqual
        "classify revoked → RefreshTokenReuseDetected"
        (Left RefreshTokenReuseDetected)
        (classifyRefreshTokenLookup (Just revokedRt))
    let validRt = revokedRt{refreshTokenRevoked = False, refreshTokenToken = "valid-token"}
    case classifyRefreshTokenLookup (Just validRt) of
        Left e ->
            fail ("classify valid → expected Right, got Left: " <> show e)
        Right (ValidRefreshToken rt) ->
            assertEqual "classify valid → token value" "valid-token" (refreshTokenToken rt)
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
            fail "TokenResponse: JSON decode failed"
        Just (obj :: Object) -> do
            let tokenRespKeys = ["access_token", "token_type", "expires_in", "refresh_token", "user"]
            mapM_
                ( \k ->
                    if KeyMap.member k obj
                        then pure ()
                        else fail ("TokenResponse JSON: missing key: " <> show k)
                )
                tokenRespKeys
            assertEqual
                "TokenResponse token_type"
                (Just (String "bearer"))
                (KeyMap.lookup "token_type" obj)
            assertEqual
                "TokenResponse expires_in"
                (Just (Number 3600))
                (KeyMap.lookup "expires_in" obj)
    case Aeson.decode "{\"refresh_token\": \"abc\"}" of
        Nothing -> fail "TokenRequest: parse {refresh_token} failed"
        Just tr ->
            assertEqual
                "TokenRequest refresh_token"
                (Just "abc")
                (tokenRequestRefreshToken tr)
    case Aeson.decode "{}" of
        Nothing -> fail "TokenRequest: parse {} failed"
        Just (tr :: TokenRequest) -> do
            assertEqual "TokenRequest empty refresh" Nothing (tokenRequestRefreshToken tr)
            assertEqual "TokenRequest empty email" Nothing (tokenRequestEmail tr)
            assertEqual "TokenRequest empty password" Nothing (tokenRequestPassword tr)
    case Aeson.decode "{\"email\": \"a@b.c\", \"password\": \"x\"}" of
        Nothing -> fail "TokenRequest: parse email+password failed"
        Just tr -> do
            assertEqual
                "TokenRequest email"
                (Just (Email "a@b.c"))
                (tokenRequestEmail tr)
            assertEqual
                "TokenRequest password"
                (Just (Password "x"))
                (tokenRequestPassword tr)
    assertEqual "parseGrantType password" GrantPassword (parseGrantType (Just "password"))
    assertEqual "parseGrantType refresh_token" GrantRefreshToken (parseGrantType (Just "refresh_token"))
    assertEqual
        "parseGrantType client_credentials"
        (GrantUnsupported "client_credentials")
        (parseGrantType (Just "client_credentials"))
    assertEqual "parseGrantType Nothing" (GrantUnsupported "") (parseGrantType Nothing)
