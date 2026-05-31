module Hauth.Mfa.Totp (
    TotpSecret (..),
    generateTotpSecret,
    otpAuthUri,
    Base32Bytes (..),
    encodeBase32,
    decodeBase32,
) where

import qualified Crypto.Random as CR
import Data.Bits (shiftL, shiftR, (.&.), (.|.))
import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import Data.Char (isAlphaNum, isAsciiUpper, toUpper)
import Data.Text (Text)
import qualified Data.Text as T
import Data.Word (Word8)

-- | The raw 20-byte (160-bit) TOTP secret.
newtype TotpSecret = TotpSecret {unTotpSecret :: ByteString}
    deriving stock (Eq, Show)

-- | Opaque wrapper; exposed so callers can work with base32 bytes directly.
newtype Base32Bytes = Base32Bytes {unBase32Bytes :: ByteString}
    deriving stock (Eq, Show)

-- | Generate a fresh 20-byte TOTP secret via cryptographically secure RNG.
generateTotpSecret :: IO TotpSecret
generateTotpSecret =
    TotpSecret <$> CR.getRandomBytes 20

-- ---------------------------------------------------------------------------
-- Base32 (RFC 4648)
-- ---------------------------------------------------------------------------

base32Alphabet :: [Char]
base32Alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"

-- | Pure RFC 4648 base32 encoding, no padding.
encodeBase32 :: ByteString -> Text
encodeBase32 bs
    | BS.null bs = T.empty
    | otherwise = T.pack (go (BS.unpack bs) 0 0 [])
  where
    -- State: remaining input bytes, bits held in accumulator, accumulator value, output chars (reversed).
    go :: [Word8] -> Int -> Int -> [Char] -> [Char]
    go [] bitsLeft acc result
        | bitsLeft == 0 = reverse result
        | otherwise =
            -- Flush remaining bits by left-justifying into a 5-bit group.
            let idx = (acc `shiftL` (5 - bitsLeft)) .&. 0x1F
                c = base32Alphabet !! idx
             in reverse (c : result)
    go (b : rest) bitsLeft acc result =
        let newAcc = (acc `shiftL` 8) .|. fromIntegral b
            newBits = bitsLeft + 8
         in emitBits rest newBits newAcc result

    emitBits :: [Word8] -> Int -> Int -> [Char] -> [Char]
    emitBits bytes bitsLeft acc result
        | bitsLeft >= 5 =
            let idx = (acc `shiftR` (bitsLeft - 5)) .&. 0x1F
                c = base32Alphabet !! idx
             in emitBits bytes (bitsLeft - 5) acc (c : result)
        | otherwise = go bytes bitsLeft acc result

{- | Decode RFC 4648 base32 text.  Tolerant of padding (@=@) and lowercase.
Returns 'Nothing' on any invalid character.
-}
decodeBase32 :: Text -> Maybe ByteString
decodeBase32 t
    | T.null stripped = Just BS.empty
    | otherwise = fmap (BS.pack . reverse) (go (T.unpack stripped) 0 0 [])
  where
    stripped = T.dropWhileEnd (== '=') t

    charValue :: Char -> Maybe Int
    charValue c =
        case toUpper c of
            u | isAsciiUpper u -> Just (fromEnum u - fromEnum 'A')
            '2' -> Just 26
            '3' -> Just 27
            '4' -> Just 28
            '5' -> Just 29
            '6' -> Just 30
            '7' -> Just 31
            _ -> Nothing

    go :: [Char] -> Int -> Int -> [Word8] -> Maybe [Word8]
    go [] _ _ acc = Just acc
    go (c : rest) bitsLeft buf acc =
        case charValue c of
            Nothing -> Nothing
            Just v ->
                let newBuf = (buf `shiftL` 5) .|. v
                    newBits = bitsLeft + 5
                 in if newBits >= 8
                        then
                            let out = fromIntegral ((newBuf `shiftR` (newBits - 8)) .&. 0xFF) :: Word8
                             in go rest (newBits - 8) newBuf (out : acc)
                        else go rest newBits newBuf acc

{- | Construct an @otpauth://totp/@ URI.

Issuer and label are URL-encoded so that special characters (such as @\@@)
are percent-escaped per RFC 3986.
-}
otpAuthUri ::
    -- | Issuer
    Text ->
    -- | Account label (email or user identifier)
    Text ->
    TotpSecret ->
    Text
otpAuthUri issuer label secret =
    "otpauth://totp/"
        <> urlEncode issuer
        <> ":"
        <> urlEncode label
        <> "?secret="
        <> encodeBase32 (unTotpSecret secret)
        <> "&issuer="
        <> urlEncode issuer
        <> "&algorithm=SHA1&digits=6&period=30"

{- | Minimal percent-encoding: encode any character that is not unreserved
(letters, digits, @-@, @_@, @.@, @~@).
-}
urlEncode :: Text -> Text
urlEncode = T.concatMap encodeChar
  where
    encodeChar c
        | isAlphaNum c || c `elem` ("-_.~" :: String) = T.singleton c
        | otherwise =
            let b = fromEnum c
             in "%" <> T.pack [hexDigit (b `div` 16), hexDigit (b `mod` 16)]
    hexDigit n
        | n < 10 = toEnum (fromEnum '0' + n)
        | otherwise = toEnum (fromEnum 'A' + n - 10)
