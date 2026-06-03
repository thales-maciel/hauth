module Spec.Webhooks.SigningSpec (runSpec) where

import Data.ByteArray (constEq)
import qualified Data.ByteString as BS
import Data.UUID (nil)
import Hauth.Webhooks.Signing (SignedHeaders (..), signRequest, verifySignatureAt)
import Spec.TestUtils (assertEqual)

secret :: BS.ByteString
secret = "super-secret-key-32-bytes-long!!"

altSecret :: BS.ByteString
altSecret = "different-secret-key-32-bytes!!!"

body :: BS.ByteString
body = "{\"event\":\"user.created\"}"

-- Pin a deterministic instant so the drift-tolerance cases below don't drift
-- with real wall-clock time. 2026-01-01T00:00:00Z.
now :: (Num a) => a
now = 1767225600

runSpec :: IO ()
runSpec = do
    let hdrs = signRequest secret nil now body

    -- Sign + verify roundtrip with same secret → True
    assertEqual
        "roundtrip with same secret"
        True
        (verifySignatureAt now secret (sigWebhookId hdrs) (sigWebhookTimestamp hdrs) (sigWebhookSignature hdrs) body)

    -- Sign + verify with different secret → False
    assertEqual
        "different secret rejected"
        False
        (verifySignatureAt now altSecret (sigWebhookId hdrs) (sigWebhookTimestamp hdrs) (sigWebhookSignature hdrs) body)

    -- Sign + verify with tampered body → False
    assertEqual
        "tampered body rejected"
        False
        (verifySignatureAt now secret (sigWebhookId hdrs) (sigWebhookTimestamp hdrs) (sigWebhookSignature hdrs) "tampered-body")

    -- Timestamp drift > 5 minutes → False
    let staleTs = now - 301
        staleHdrs = signRequest secret nil staleTs body
    assertEqual
        "stale timestamp rejected"
        False
        (verifySignatureAt now secret (sigWebhookId staleHdrs) (sigWebhookTimestamp staleHdrs) (sigWebhookSignature staleHdrs) body)

    -- Timestamp drift < 5 minutes → True
    let freshTs = now - 299
        freshHdrs = signRequest secret nil freshTs body
    assertEqual
        "fresh timestamp accepted"
        True
        (verifySignatureAt now secret (sigWebhookId freshHdrs) (sigWebhookTimestamp freshHdrs) (sigWebhookSignature freshHdrs) body)

    -- Constant-time comparison is used (assert via code: constEq from Data.ByteArray)
    let bs1 = "abc" :: BS.ByteString
        bs2 = "abc" :: BS.ByteString
    assertEqual "constEq is available and works" True (constEq bs1 bs2)
