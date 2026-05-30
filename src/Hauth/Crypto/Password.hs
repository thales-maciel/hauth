module Hauth.Crypto.Password (
    Argon2Settings (..),
    defaultArgon2Settings,
    PasswordPolicy (..),
    defaultPasswordPolicy,
    PasswordPolicyError (..),
    hashPassword,
    verifyPassword,
    checkPasswordPolicy,
) where

import Crypto.Error (CryptoFailable (..))
import qualified Crypto.KDF.Argon2 as Argon2
import Crypto.Random (getRandomBytes)
import Data.ByteArray (constEq)
import Data.ByteArray.Encoding (Base (..), convertFromBase, convertToBase)
import qualified Data.ByteString as BS
import Data.Text (Text)
import qualified Data.Text as T
import qualified Data.Text.Encoding as TE
import Data.Word (Word32)

-- | Settings for Argon2id hashing.
data Argon2Settings = Argon2Settings
    { argon2Iterations :: Word32
    -- ^ Number of iterations (time cost).
    , argon2Memory :: Word32
    -- ^ Memory usage in KiB.
    , argon2Parallelism :: Word32
    -- ^ Degree of parallelism.
    , argon2HashLength :: Word32
    -- ^ Length of the output hash in bytes.
    }
    deriving stock (Show, Eq)

-- | Recommended defaults: t=3, m=65536 (64 MiB), p=4, hashLength=32.
defaultArgon2Settings :: Argon2Settings
defaultArgon2Settings =
    Argon2Settings
        { argon2Iterations = 3
        , argon2Memory = 65536
        , argon2Parallelism = 4
        , argon2HashLength = 32
        }

-- | Policy governing acceptable passwords.
newtype PasswordPolicy = PasswordPolicy
    { policyMinLength :: Int
    -- ^ Minimum number of characters required.
    }
    deriving stock (Show, Eq)

-- | Default policy: minimum 8 characters.
defaultPasswordPolicy :: PasswordPolicy
defaultPasswordPolicy = PasswordPolicy{policyMinLength = 8}

-- | Errors returned by 'checkPasswordPolicy'.
data PasswordPolicyError
    = -- | Password is too short. Fields: expected minimum, actual length.
      PasswordTooShort Int Int
    deriving stock (Show, Eq)

-- | Check that a plaintext password satisfies the given policy.
checkPasswordPolicy :: PasswordPolicy -> Text -> Either PasswordPolicyError ()
checkPasswordPolicy policy pw
    | actual < minLen = Left (PasswordTooShort minLen actual)
    | otherwise = Right ()
  where
    minLen = policyMinLength policy
    actual = T.length pw

{- | Hash a plaintext password using Argon2id with the given settings.
Generates a fresh random salt on each call and returns a PHC-format string.
-}
hashPassword :: Argon2Settings -> Text -> IO Text
hashPassword settings pw = do
    salt <- getRandomBytes saltLength :: IO BS.ByteString
    let opts =
            Argon2.Options
                { Argon2.iterations = argon2Iterations settings
                , Argon2.memory = argon2Memory settings
                , Argon2.parallelism = argon2Parallelism settings
                , Argon2.variant = Argon2.Argon2id
                , Argon2.version = Argon2.Version13
                }
        pwBytes = TE.encodeUtf8 pw
        outLen = fromIntegral (argon2HashLength settings)
    case Argon2.hash opts pwBytes salt outLen of
        CryptoFailed err -> fail ("hashPassword: " <> show err)
        CryptoPassed (hashBytes :: BS.ByteString) ->
            pure (encodePHC settings salt hashBytes)
  where
    saltLength :: Int
    saltLength = 16

{- | Encode a PHC string from settings, salt, and raw hash bytes.
Format: @$argon2id$v=19$m=\<mem\>,t=\<iter\>,p=\<par\>$\<salt-b64\>$\<hash-b64\>@
-}
encodePHC :: Argon2Settings -> BS.ByteString -> BS.ByteString -> Text
encodePHC settings salt hashBytes =
    T.intercalate
        "$"
        [ ""
        , "argon2id"
        , "v=19"
        , "m=" <> tshow (argon2Memory settings) <> ",t=" <> tshow (argon2Iterations settings) <> ",p=" <> tshow (argon2Parallelism settings)
        , b64Unpadded salt
        , b64Unpadded hashBytes
        ]
  where
    tshow :: (Show a) => a -> Text
    tshow = T.pack . show

{- | Verify a candidate password against a stored PHC string.
Returns 'False' on any parse error, never throws.
-}
verifyPassword :: Text -> Text -> Bool
verifyPassword phcText candidate =
    case parsePHC phcText of
        Nothing -> False
        Just (opts, salt, storedHash) ->
            let pwBytes = TE.encodeUtf8 candidate
                outLen = BS.length storedHash
             in case Argon2.hash opts pwBytes salt outLen of
                    CryptoFailed _ -> False
                    CryptoPassed (computed :: BS.ByteString) ->
                        constEq computed storedHash

-- | Parse a PHC string into Argon2 options, salt bytes, and hash bytes.
parsePHC :: Text -> Maybe (Argon2.Options, BS.ByteString, BS.ByteString)
parsePHC phcText = do
    -- Expected: ["", "argon2id", "v=19", "m=65536,t=3,p=4", "<salt-b64>", "<hash-b64>"]
    parts <- case T.splitOn "$" phcText of
        ["", "argon2id", versionPart, paramsPart, saltB64, hashB64] ->
            Just (versionPart, paramsPart, saltB64, hashB64)
        _ -> Nothing
    let (versionPart, paramsPart, saltB64, hashB64) = parts
    ver <- parseVersion versionPart
    (m, t, p) <- parseParams paramsPart
    salt <- decodeB64 saltB64
    hashBytes <- decodeB64 hashB64
    let opts =
            Argon2.Options
                { Argon2.iterations = t
                , Argon2.memory = m
                , Argon2.parallelism = p
                , Argon2.variant = Argon2.Argon2id
                , Argon2.version = ver
                }
    pure (opts, salt, hashBytes)

parseVersion :: Text -> Maybe Argon2.Version
parseVersion "v=19" = Just Argon2.Version13
parseVersion "v=16" = Just Argon2.Version10
parseVersion _ = Nothing

parseParams :: Text -> Maybe (Word32, Word32, Word32)
parseParams paramsPart = do
    kvPairs <- mapM parseKV (T.splitOn "," paramsPart)
    m <- lookup "m" kvPairs
    t <- lookup "t" kvPairs
    p <- lookup "p" kvPairs
    pure (m, t, p)
  where
    parseKV :: Text -> Maybe (Text, Word32)
    parseKV kv = case T.splitOn "=" kv of
        [k, v] -> case reads (T.unpack v) of
            [(n, "")] -> Just (k, n)
            _ -> Nothing
        _ -> Nothing

-- | Encode bytes as unpadded standard base64.
b64Unpadded :: BS.ByteString -> Text
b64Unpadded bs =
    T.dropWhileEnd (== '=') $
        TE.decodeUtf8 $
            convertToBase Base64 bs

-- | Decode unpadded standard base64, re-adding padding if needed.
decodeB64 :: Text -> Maybe BS.ByteString
decodeB64 t =
    let padded = TE.encodeUtf8 (addPadding t)
     in case convertFromBase Base64 padded of
            Left _ -> Nothing
            Right bs -> Just bs

-- | Add '=' padding to make length a multiple of 4.
addPadding :: Text -> Text
addPadding t =
    let r = T.length t `mod` 4
     in if r == 0 then t else t <> T.replicate (4 - r) "="
