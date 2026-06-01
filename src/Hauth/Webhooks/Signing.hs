{- | HMAC-SHA256 request signing following the Standard Webhooks convention.

Tolerance: 'verifySignature' rejects timestamps more than 5 minutes from the
current system time in either direction.
-}
module Hauth.Webhooks.Signing (
    SignedHeaders (..),
    signRequest,
    verifySignature,
) where

import Crypto.Hash (SHA256)
import Crypto.MAC.HMAC (HMAC, hmac, hmacGetDigest)
import Data.ByteArray (constEq, convert)
import Data.ByteArray.Encoding (Base (..), convertToBase)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Char8 as BSC
import Data.Time.Clock.POSIX (POSIXTime, getPOSIXTime)
import Data.UUID (UUID)
import qualified Data.UUID as UUID
import System.IO.Unsafe (unsafePerformIO)

-- | The three Standard Webhooks signing headers.
data SignedHeaders = SignedHeaders
    { sigWebhookId :: BS.ByteString
    , sigWebhookTimestamp :: BS.ByteString
    , sigWebhookSignature :: BS.ByteString
    }
    deriving stock (Eq, Show)

-- | Sign a webhook request; returns the three headers to attach.
signRequest ::
    -- | Secret (raw bytes).
    BS.ByteString ->
    -- | Delivery ID used as webhook-id.
    UUID ->
    -- | Timestamp at sign time.
    POSIXTime ->
    -- | Request body.
    BS.ByteString ->
    SignedHeaders
signRequest secret deliveryId ts body =
    SignedHeaders
        { sigWebhookId = idBytes
        , sigWebhookTimestamp = tsBytes
        , sigWebhookSignature = "v1," <> sig
        }
  where
    idBytes = BSC.pack (UUID.toString deliveryId)
    tsBytes = BSC.pack (show (floor ts :: Integer))
    signed = idBytes <> "." <> tsBytes <> "." <> body
    digest = hmacGetDigest (hmac secret signed :: HMAC SHA256)
    sig = convertToBase Base64 (convert digest :: BS.ByteString) :: BS.ByteString

{- | Verify a signed request.

Returns False on tamper, wrong secret, or timestamp drift exceeding 5 minutes.
Uses constant-time comparison to prevent timing attacks.
-}
verifySignature ::
    -- | Secret (raw bytes).
    BS.ByteString ->
    -- | webhook-id header value.
    BS.ByteString ->
    -- | webhook-timestamp header value.
    BS.ByteString ->
    -- | webhook-signature header value.
    BS.ByteString ->
    -- | Body.
    BS.ByteString ->
    -- | Constant-time comparison; tolerates timestamp drift up to 5 minutes.
    Bool
verifySignature secret wId wTs wSig body =
    case parseTimestamp wTs of
        Nothing -> False
        Just ts ->
            let now = unsafePerformIO getPOSIXTime
             in if abs (now - ts) > driftTolerance
                    then False
                    else
                        let signed = wId <> "." <> wTs <> "." <> body
                            digest = hmacGetDigest (hmac secret signed :: HMAC SHA256)
                            rawSig = convertToBase Base64 (convert digest :: BS.ByteString) :: BS.ByteString
                            expected = "v1," <> rawSig :: BS.ByteString
                            candidate = BS.takeWhile (/= 0x20) wSig
                         in constEq expected candidate

-- | Maximum allowed timestamp drift (seconds).
driftTolerance :: POSIXTime
driftTolerance = 300

parseTimestamp :: BS.ByteString -> Maybe POSIXTime
parseTimestamp bs =
    case reads (BSC.unpack bs) of
        [(n, "")] -> Just (fromInteger n)
        _ -> Nothing
