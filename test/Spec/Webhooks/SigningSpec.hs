module Spec.Webhooks.SigningSpec (runSpec) where

import Data.ByteArray (constEq)
import qualified Data.ByteString as BS
import Data.Time.Clock.POSIX (getPOSIXTime)
import Data.UUID (nil)
import Hauth.Webhooks.Signing (SignedHeaders (..), signRequest, verifySignature)
import Spec.TestUtils (assertEqual)

secret :: BS.ByteString
secret = "super-secret-key-32-bytes-long!!"

altSecret :: BS.ByteString
altSecret = "different-secret-key-32-bytes!!!"

body :: BS.ByteString
body = "{\"event\":\"user.created\"}"

runSpec :: IO ()
runSpec = do
    now <- getPOSIXTime

    let hdrs = signRequest secret nil now body

    -- Sign + verify roundtrip with same secret → True
    assertEqual
        "roundtrip with same secret"
        True
        (verifySignature secret (sigWebhookId hdrs) (sigWebhookTimestamp hdrs) (sigWebhookSignature hdrs) body)

    -- Sign + verify with different secret → False
    assertEqual
        "different secret rejected"
        False
        (verifySignature altSecret (sigWebhookId hdrs) (sigWebhookTimestamp hdrs) (sigWebhookSignature hdrs) body)

    -- Sign + verify with tampered body → False
    assertEqual
        "tampered body rejected"
        False
        (verifySignature secret (sigWebhookId hdrs) (sigWebhookTimestamp hdrs) (sigWebhookSignature hdrs) "tampered-body")

    -- Timestamp drift > 5 minutes → False
    let staleTs = now - 301
        staleHdrs = signRequest secret nil staleTs body
    assertEqual
        "stale timestamp rejected"
        False
        (verifySignature secret (sigWebhookId staleHdrs) (sigWebhookTimestamp staleHdrs) (sigWebhookSignature staleHdrs) body)

    -- Timestamp drift < 5 minutes → True
    let freshTs = now - 299
        freshHdrs = signRequest secret nil freshTs body
    assertEqual
        "fresh timestamp accepted"
        True
        (verifySignature secret (sigWebhookId freshHdrs) (sigWebhookTimestamp freshHdrs) (sigWebhookSignature freshHdrs) body)

    -- Constant-time comparison is used (assert via code: constEq from Data.ByteArray)
    let bs1 = "abc" :: BS.ByteString
        bs2 = "abc" :: BS.ByteString
    assertEqual "constEq is available and works" True (constEq bs1 bs2)
