module Spec.Crypto.PasswordSpec (spec) where

import Hauth.Crypto.Password (
    Argon2Settings (..),
    PasswordPolicyError (..),
    checkPasswordPolicy,
    defaultArgon2Settings,
    defaultPasswordPolicy,
    hashPassword,
 )
import qualified Hauth.Crypto.Password as Password
import Test.Hspec (Spec, describe, it, shouldBe)

-- Password hashing tests use cheap settings to keep CI fast.
cheapSettings :: Argon2Settings
cheapSettings =
    defaultArgon2Settings
        { argon2Iterations = 1
        , argon2Memory = 8
        , argon2Parallelism = 1
        }

spec :: Spec
spec = do
    describe "hashPassword / verifyPassword" $ do
        it "verifies a correct password" $ do
            h <- hashPassword cheapSettings "correct horse"
            Password.verifyPassword h "correct horse" `shouldBe` True
        it "rejects a wrong password" $ do
            h <- hashPassword cheapSettings "correct horse"
            Password.verifyPassword h "wrong" `shouldBe` False
        it "produces different hashes for the same input (different salts)" $ do
            hash1 <- hashPassword cheapSettings "correct horse"
            hash2 <- hashPassword cheapSettings "correct horse"
            (hash1 /= hash2) `shouldBe` True
        it "rejects a non-PHC string as a stored hash" $
            Password.verifyPassword "not a phc string" "anything" `shouldBe` False

    describe "checkPasswordPolicy" $ do
        it "rejects an empty password" $
            checkPasswordPolicy defaultPasswordPolicy ""
                `shouldBe` Left (PasswordTooShort 8 0)
        it "accepts a minimum-length password" $
            checkPasswordPolicy defaultPasswordPolicy "abcdefgh"
                `shouldBe` Right ()
