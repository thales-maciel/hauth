module Spec.Webhooks.SigningSpec (spec) where

import Data.ByteArray (constEq)
import qualified Data.ByteString as BS
import Data.UUID (nil)
import Hauth.Webhooks.Signing (SignedHeaders (..), signRequest, verifySignatureAt)
import Test.Hspec (Spec, describe, it, shouldBe)

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

spec :: Spec
spec = do
    describe "signRequest / verifySignatureAt" $ do
        let hdrs = signRequest secret nil now body

        it "verifies a roundtrip with the same secret" $
            verifySignatureAt now secret (sigWebhookId hdrs) (sigWebhookTimestamp hdrs) (sigWebhookSignature hdrs) body
                `shouldBe` True

        it "rejects a signature produced with a different secret" $
            verifySignatureAt now altSecret (sigWebhookId hdrs) (sigWebhookTimestamp hdrs) (sigWebhookSignature hdrs) body
                `shouldBe` False

        it "rejects a tampered body" $
            verifySignatureAt now secret (sigWebhookId hdrs) (sigWebhookTimestamp hdrs) (sigWebhookSignature hdrs) "tampered-body"
                `shouldBe` False

        it "rejects a timestamp older than the 5-minute window" $ do
            let staleTs = now - 301
                staleHdrs = signRequest secret nil staleTs body
            verifySignatureAt now secret (sigWebhookId staleHdrs) (sigWebhookTimestamp staleHdrs) (sigWebhookSignature staleHdrs) body
                `shouldBe` False

        it "accepts a timestamp within the 5-minute window" $ do
            let freshTs = now - 299
                freshHdrs = signRequest secret nil freshTs body
            verifySignatureAt now secret (sigWebhookId freshHdrs) (sigWebhookTimestamp freshHdrs) (sigWebhookSignature freshHdrs) body
                `shouldBe` True

    describe "constant-time comparison" $
        it "constEq from Data.ByteArray is available and works" $ do
            let bs1 = "abc" :: BS.ByteString
                bs2 = "abc" :: BS.ByteString
            constEq bs1 bs2 `shouldBe` True
