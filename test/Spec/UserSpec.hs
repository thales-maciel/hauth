module Spec.UserSpec (runSpec) where

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
import Spec.TestUtils (assertEqual)

runSpec :: IO ()
runSpec = do
    ctok1 <- generateConfirmationToken
    assertEqual "generateConfirmationToken non-empty" True (not (T.null ctok1))
    assertEqual "generateConfirmationToken length 43" 43 (T.length ctok1)
    ctok2 <- generateConfirmationToken
    assertEqual "generateConfirmationToken two calls differ" True (ctok1 /= ctok2)
    now3 <- getCurrentTime
    let testUserId = UserId UUID.nil
        testUser =
            User
                { userId = testUserId
                , userEmail = Just "test@example.com"
                , userEncryptedPassword = Just "$argon2id$v=19$..."
                , userEmailConfirmedAt = Nothing
                , userConfirmationToken = Just ctok1
                , userConfirmationSentAt = Just now3
                , userRawAppMetaData = Aeson.object []
                , userRawUserMetaData = Aeson.object []
                , userRole = "authenticated"
                , userAud = "authenticated"
                , userCreatedAt = now3
                , userUpdatedAt = now3
                }
    assertEqual "user userId" testUserId (userId testUser)
    assertEqual "user email" (Just "test@example.com") (userEmail testUser)
    assertEqual "user role" "authenticated" (userRole testUser)
    assertEqual "user aud" "authenticated" (userAud testUser)
    assertEqual "user emailConfirmedAt" Nothing (userEmailConfirmedAt testUser)
    assertEqual "user confirmationToken" (Just ctok1) (userConfirmationToken testUser)
    let signupResp = buildSignupResponse testUser
        signupJson = Aeson.encode signupResp
    case Aeson.decode signupJson of
        Nothing -> fail "buildSignupResponse: JSON decode failed"
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
                        else fail ("buildSignupResponse: missing key: " <> show k)
                )
                requiredSignupKeys
    assertEqual
        "validateSignupEmail rejects empty"
        (Left (SignupEmailInvalid ""))
        (validateSignupEmail "")
    assertEqual
        "validateSignupEmail rejects no-at"
        (Left (SignupEmailInvalid "no-at"))
        (validateSignupEmail "no-at")
    assertEqual
        "validateSignupEmail rejects @no-local"
        (Left (SignupEmailInvalid "@no-local"))
        (validateSignupEmail "@no-local")
    assertEqual
        "validateSignupEmail accepts a@b.co"
        (Right "a@b.co")
        (validateSignupEmail "a@b.co")
    case validateSignupPassword "" of
        Left (SignupPasswordTooShort _ _) -> pure ()
        other -> fail ("validateSignupPassword empty: expected SignupPasswordTooShort, got " <> show other)
    case validateSignupPassword "short" of
        Left (SignupPasswordTooShort _ _) -> pure ()
        other -> fail ("validateSignupPassword short: expected SignupPasswordTooShort, got " <> show other)
    assertEqual
        "validateSignupPassword accepts 8+"
        (Right "abcdefgh")
        (validateSignupPassword "abcdefgh")
    let cheapSettings2 =
            defaultArgon2Settings
                { argon2Iterations = 1
                , argon2Memory = 8
                , argon2Parallelism = 1
                }
    hash3 <- hashPassword cheapSettings2 "correct horse"
    assertEqual "signup hash+verify roundtrip" True (Password.verifyPassword hash3 "correct horse")
