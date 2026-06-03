{- | HMAC-SHA256 request signing following the Standard Webhooks convention.

Verification is parameterised over the current time: 'verifySignatureAt'
takes the reference instant explicitly so tests can pin it; 'verifySignature'
is the thin @IO@ wrapper that reads the wall clock.

Tolerance: timestamps more than 5 minutes from the reference time in either
direction are rejected.
-}
module Hauth.Webhooks.Signing (
    SignedHeaders (..),
    signRequest,
    verifySignature,
    verifySignatureAt,
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

{- | Pure verifier. Takes the reference instant explicitly so the function is
total and time-independent — tests can pin a deterministic @now@; production
code calls 'verifySignature' which threads in the wall clock.

Returns False on tamper, wrong secret, or timestamp drift exceeding
'driftTolerance' from the supplied reference. Uses constant-time comparison.
-}
verifySignatureAt ::
    -- | Reference time (treated as \"now\" for the drift check).
    POSIXTime ->
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
    Bool
verifySignatureAt now secret wId wTs wSig body =
    case parseTimestamp wTs of
        Nothing -> False
        Just ts ->
            abs (now - ts) <= driftTolerance
                && let signed = wId <> "." <> wTs <> "." <> body
                       digest = hmacGetDigest (hmac secret signed :: HMAC SHA256)
                       rawSig = convertToBase Base64 (convert digest :: BS.ByteString) :: BS.ByteString
                       expected = "v1," <> rawSig :: BS.ByteString
                       candidate = BS.takeWhile (/= 0x20) wSig
                    in constEq expected candidate

{- | Wall-clock wrapper over 'verifySignatureAt'. Use this in handlers; pin a
fixed instant via 'verifySignatureAt' in tests.
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
    IO Bool
verifySignature secret wId wTs wSig body = do
    now <- getPOSIXTime
    pure (verifySignatureAt now secret wId wTs wSig body)

-- | Maximum allowed timestamp drift (seconds).
driftTolerance :: POSIXTime
driftTolerance = 300

parseTimestamp :: BS.ByteString -> Maybe POSIXTime
parseTimestamp bs =
    case reads (BSC.unpack bs) of
        [(n, "")] -> Just (fromInteger n)
        _ -> Nothing
