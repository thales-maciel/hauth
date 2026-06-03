module Spec.UserSpec (spec) where

import Data.Aeson (Object)
import qualified Data.Aeson as Aeson
import qualified Data.Aeson.KeyMap as KeyMap
import qualified Data.Text as T
import Data.Time.Clock (getCurrentTime)
import qualified Data.UUID as UUID
import Hauth.API.Types (buildSignupResponse)
import Hauth.Crypto.Password (
    Argon2Settings (..),
    defaultArgon2Settings,
    hashPassword,
 )
import qualified Hauth.Crypto.Password as Password
import Hauth.User (
    SignupError (..),
    User (..),
    UserId (..),
    generateConfirmationToken,
    validateSignupEmail,
    validateSignupPassword,
 )
import Test.Hspec (Spec, describe, expectationFailure, it, shouldBe)

spec :: Spec
spec = do
    describe "generateConfirmationToken" $ do
        it "produces a non-empty 43-char token" $ do
            ctok <- generateConfirmationToken
            T.null ctok `shouldBe` False
            T.length ctok `shouldBe` 43

        it "two calls produce different tokens" $ do
            ctok1 <- generateConfirmationToken
            ctok2 <- generateConfirmationToken
            (ctok1 /= ctok2) `shouldBe` True

    describe "User record" $
        it "round-trips field values" $ do
            ctok <- generateConfirmationToken
            now <- getCurrentTime
            let testUserId = UserId UUID.nil
                testUser =
                    User
                        { userId = testUserId
                        , userEmail = Just "test@example.com"
                        , userEncryptedPassword = Just "$argon2id$v=19$..."
                        , userEmailConfirmedAt = Nothing
                        , userConfirmationToken = Just ctok
                        , userConfirmationSentAt = Just now
                        , userRawAppMetaData = Aeson.object []
                        , userRawUserMetaData = Aeson.object []
                        , userRole = "authenticated"
                        , userAud = "authenticated"
                        , userCreatedAt = now
                        , userUpdatedAt = now
                        }
            userId testUser `shouldBe` testUserId
            userEmail testUser `shouldBe` Just "test@example.com"
            userRole testUser `shouldBe` "authenticated"
            userAud testUser `shouldBe` "authenticated"
            userEmailConfirmedAt testUser `shouldBe` Nothing
            userConfirmationToken testUser `shouldBe` Just ctok

    describe "buildSignupResponse" $
        it "encodes the required JSON keys" $ do
            now <- getCurrentTime
            ctok <- generateConfirmationToken
            let testUser =
                    User
                        { userId = UserId UUID.nil
                        , userEmail = Just "test@example.com"
                        , userEncryptedPassword = Just "$argon2id$v=19$..."
                        , userEmailConfirmedAt = Nothing
                        , userConfirmationToken = Just ctok
                        , userConfirmationSentAt = Just now
                        , userRawAppMetaData = Aeson.object []
                        , userRawUserMetaData = Aeson.object []
                        , userRole = "authenticated"
                        , userAud = "authenticated"
                        , userCreatedAt = now
                        , userUpdatedAt = now
                        }
                signupResp = buildSignupResponse testUser
                signupJson = Aeson.encode signupResp
            case Aeson.decode signupJson of
                Nothing -> expectationFailure "JSON decode failed"
                Just (obj :: Object) -> do
                    let requiredSignupKeys =
                            [ "id"
                            , "aud"
                            , "role"
                            , "email"
                            , "confirmation_sent_at"
                            , "created_at"
                            , "updated_at"
                            , "app_metadata"
                            , "user_metadata"
                            ]
                    mapM_
                        ( \k ->
                            if KeyMap.member k obj
                                then pure ()
                                else expectationFailure ("missing key: " <> show k)
                        )
                        requiredSignupKeys

    describe "validateSignupEmail" $ do
        it "rejects empty" $
            validateSignupEmail "" `shouldBe` Left (SignupEmailInvalid "")
        it "rejects no-at" $
            validateSignupEmail "no-at" `shouldBe` Left (SignupEmailInvalid "no-at")
        it "rejects @no-local" $
            validateSignupEmail "@no-local" `shouldBe` Left (SignupEmailInvalid "@no-local")
        it "accepts a@b.co" $
            validateSignupEmail "a@b.co" `shouldBe` Right "a@b.co"

    describe "validateSignupPassword" $ do
        it "rejects empty as too short" $
            case validateSignupPassword "" of
                Left (SignupPasswordTooShort _ _) -> pure ()
                other -> expectationFailure ("expected SignupPasswordTooShort, got " <> show other)

        it "rejects short as too short" $
            case validateSignupPassword "short" of
                Left (SignupPasswordTooShort _ _) -> pure ()
                other -> expectationFailure ("expected SignupPasswordTooShort, got " <> show other)

        it "accepts 8+ chars" $
            validateSignupPassword "abcdefgh" `shouldBe` Right "abcdefgh"

    describe "signup password hashing" $
        it "hash + verify round-trip succeeds" $ do
            let cheapSettings =
                    defaultArgon2Settings
                        { argon2Iterations = 1
                        , argon2Memory = 8
                        , argon2Parallelism = 1
                        }
            hash <- hashPassword cheapSettings "correct horse"
            Password.verifyPassword hash "correct horse" `shouldBe` True
