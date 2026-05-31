module Hauth.Mfa.TotpVerify (
    TotpVerificationResult (..),
    verifyTotpCode,
    totpCodeAtStep,
    currentTimeStep,
) where

import Data.Bits (shiftL, shiftR, (.&.), (.|.))
import qualified Data.ByteArray as BA
import qualified Data.ByteString as BS
import Data.Int (Int64)
import Data.Text (Text)
import qualified Data.Text as T
import Data.Text.Encoding (encodeUtf8)
import Data.Time.Clock.POSIX (POSIXTime)

import Crypto.Hash (SHA1)
import Crypto.MAC.HMAC (HMAC, hmac, hmacGetDigest)
import Data.ByteArray (convert)

import Hauth.Mfa.Totp (TotpSecret (..))

-- | Result of verifying a TOTP code against a secret.
data TotpVerificationResult
    = TotpVerified
    | TotpInvalid
    deriving stock (Eq, Show)

{- | Compute the TOTP time step from a POSIX timestamp.
@currentTimeStep t = floor(t / 30)@
-}
currentTimeStep :: POSIXTime -> Int64
currentTimeStep t = floor (t / 30)

{- | Compute the 6-digit TOTP code for a given secret and time step.

Implements RFC 6238 / RFC 4226 (HOTP):
1. Pack the step as an 8-byte big-endian integer.
2. Compute HMAC-SHA1(secret, counter).
3. Extract the dynamic binary code via offset truncation.
4. Return as zero-padded 6-digit text.
-}
totpCodeAtStep :: TotpSecret -> Int64 -> Text
totpCodeAtStep (TotpSecret secret) step =
    let counter = packInt64BE step
        mac = hmac secret counter :: HMAC SHA1
        digest = convert (hmacGetDigest mac) :: BS.ByteString
        lastByte = fromIntegral (BS.last digest) :: Int
        offset = lastByte .&. 0x0F
        b0 = fromIntegral (BS.index digest offset) :: Int
        b1 = fromIntegral (BS.index digest (offset + 1)) :: Int
        b2 = fromIntegral (BS.index digest (offset + 2)) :: Int
        b3 = fromIntegral (BS.index digest (offset + 3)) :: Int
        truncated = ((b0 .&. 0x7F) `shiftL` 24) .|. (b1 `shiftL` 16) .|. (b2 `shiftL` 8) .|. b3
        code = truncated `mod` 1000000
     in T.justifyRight 6 '0' (T.pack (show code))

{- | Verify a TOTP code against a secret with a ±1-step clock-skew window.

Uses constant-time comparison via 'BA.constEq' to avoid timing side-channels.
Returns 'TotpVerified' if the candidate code matches any of the three steps:
@currentTimeStep now - 1@, @currentTimeStep now@, or @currentTimeStep now + 1@.
Returns 'TotpInvalid' otherwise (including when the code is not 6 characters).
-}
verifyTotpCode :: TotpSecret -> Text -> POSIXTime -> TotpVerificationResult
verifyTotpCode secret candidate now
    | T.length candidate /= 6 = TotpInvalid
    | otherwise =
        let step = currentTimeStep now
            candidateBS = encodeUtf8 candidate
            check s =
                let expected = encodeUtf8 (totpCodeAtStep secret s)
                 in BA.constEq candidateBS expected
         in if check (step - 1) || check step || check (step + 1)
                then TotpVerified
                else TotpInvalid

-- ---------------------------------------------------------------------------
-- Internal helpers
-- ---------------------------------------------------------------------------

-- | Pack an 'Int64' as 8 bytes in big-endian order.
packInt64BE :: Int64 -> BS.ByteString
packInt64BE n =
    BS.pack
        [ fromIntegral ((n `shiftR` 56) .&. 0xFF)
        , fromIntegral ((n `shiftR` 48) .&. 0xFF)
        , fromIntegral ((n `shiftR` 40) .&. 0xFF)
        , fromIntegral ((n `shiftR` 32) .&. 0xFF)
        , fromIntegral ((n `shiftR` 24) .&. 0xFF)
        , fromIntegral ((n `shiftR` 16) .&. 0xFF)
        , fromIntegral ((n `shiftR` 8) .&. 0xFF)
        , fromIntegral (n .&. 0xFF)
        ]
