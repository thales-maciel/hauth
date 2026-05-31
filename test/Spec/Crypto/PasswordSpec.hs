module Spec.Crypto.PasswordSpec (runSpec) where

import Hauth.Crypto.Password (
    Argon2Settings (..),
    PasswordPolicyError (..),
    checkPasswordPolicy,
    defaultArgon2Settings,
    defaultPasswordPolicy,
    hashPassword,
 )
import qualified Hauth.Crypto.Password as Password
import Spec.TestUtils (assertEqual)

runSpec :: IO ()
runSpec = do
    -- Password hashing tests use cheap settings to keep CI fast.
    let cheapSettings =
            defaultArgon2Settings
                { argon2Iterations = 1
                , argon2Memory = 8
                , argon2Parallelism = 1
                }
    hash1 <- hashPassword cheapSettings "correct horse"
    assertEqual "verify correct password" True (Password.verifyPassword hash1 "correct horse")
    assertEqual "verify wrong password" False (Password.verifyPassword hash1 "wrong")
    hash2 <- hashPassword cheapSettings "correct horse"
    assertEqual "different salts produce different hashes" True (hash1 /= hash2)
    assertEqual "bad phc string" False (Password.verifyPassword "not a phc string" "anything")
    assertEqual
        "policy rejects empty password"
        (Left (PasswordTooShort 8 0))
        (checkPasswordPolicy defaultPasswordPolicy "")
    assertEqual
        "policy accepts min-length password"
        (Right ())
        (checkPasswordPolicy defaultPasswordPolicy "abcdefgh")
