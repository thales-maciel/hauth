-- | HTTP runner for synchronous hook invocations.
module Hauth.Hooks.Runner (
    HookDecision (..),
    SignedHeaders (..),
    runHook,
    -- Signing seam — swap for Hauth.Webhooks.Signing imports when #82 lands.
    signHookRequest,
    verifyHookSignature,
) where

import Control.Exception (SomeException, try)
import Crypto.Hash (SHA256)
import Crypto.MAC.HMAC (HMAC, hmac, hmacGetDigest)
import Data.Aeson (Value)
import qualified Data.Aeson as Aeson
import qualified Data.Aeson.KeyMap as KeyMap
import Data.ByteArray (convert)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Base64 as B64
import qualified Data.ByteString.Char8 as BSC
import qualified Data.ByteString.Lazy as BSL
import Data.Text (Text)
import qualified Data.Text as T
import Data.Time.Clock.POSIX (POSIXTime, getPOSIXTime)
import Data.UUID (UUID)
import qualified Data.UUID as UUID
import Hauth.Hooks.Types (HookConfig (..), hookPointName)
import Network.HTTP.Client (
    Manager,
    RequestBody (..),
    httpLbs,
    method,
    parseRequest,
    requestBody,
    requestHeaders,
    responseBody,
    responseStatus,
    responseTimeout,
    responseTimeoutMicro,
 )
import Network.HTTP.Types (statusIsSuccessful)

-- ---------------------------------------------------------------------------
-- Decision type
-- ---------------------------------------------------------------------------

-- | Outcome returned by the hook endpoint.
data HookDecision
    = -- | Proceed unchanged.
      HookAllow
    | -- | Proceed; overlay contains hook-specific extra data (e.g. JWT claims).
      HookAllowWith Value
    | -- | Reject with an operator-facing reason.
      HookReject Text
    deriving stock (Eq, Show)

-- ---------------------------------------------------------------------------
-- Public runner
-- ---------------------------------------------------------------------------

{- | POST @payload@ inside the standard envelope to the hook URL and return a
'HookDecision'.

The caller supplies the shared HTTP 'Manager' (typically
@appHookHttpManager@ from 'Hauth.Env.AppEnv'). Allocating a fresh
'Manager' per request defeats connection pooling and is the bug fixed in
issue #160. The per-hook timeout is applied to the 'Request' via
'responseTimeout' so a shared manager remains correct.
-}
runHook :: Manager -> HookConfig -> Value -> IO HookDecision
runHook mgr cfg payload = do
    now <- getPOSIXTime
    let envelope = buildEnvelope cfg payload now
        strictBody = BSL.toStrict envelope
        signedHdrs = signHookRequest (hookConfigSecret cfg) (hookConfigId cfg) now strictBody
    result <- try (executeRequest mgr cfg strictBody signedHdrs) :: IO (Either SomeException (Maybe HookDecision))
    case result of
        Left _ -> respFailOpen cfg "hook network error"
        Right Nothing -> respFailOpen cfg "hook timed out"
        Right (Just d) -> pure d

-- ---------------------------------------------------------------------------
-- Internal
-- ---------------------------------------------------------------------------

buildEnvelope :: HookConfig -> Value -> POSIXTime -> BSL.ByteString
buildEnvelope cfg payload ts =
    Aeson.encode $
        Aeson.object
            [ "hook_point" Aeson..= hookPointName (hookConfigPoint cfg)
            , "issued_at" Aeson..= posixToText ts
            , "payload" Aeson..= payload
            ]

posixToText :: POSIXTime -> Text
posixToText ts = T.pack (show (round ts :: Integer)) <> "Z"

executeRequest :: Manager -> HookConfig -> BS.ByteString -> SignedHeaders -> IO (Maybe HookDecision)
executeRequest mgr cfg body hdrs = do
    let timeoutMicros = hookConfigTimeoutMs cfg * 1000
    baseReq <- parseRequest (T.unpack (hookConfigUrl cfg))
    let req =
            baseReq
                { method = "POST"
                , requestBody = RequestBodyBS body
                , requestHeaders =
                    [ ("Content-Type", "application/json")
                    , ("webhook-id", sigWebhookId hdrs)
                    , ("webhook-timestamp", sigWebhookTimestamp hdrs)
                    , ("webhook-signature", sigWebhookSignature hdrs)
                    ]
                , -- Per-hook timeout lives on the request so the shared 'Manager'
                  -- can be reused across hooks with different deadlines.
                  responseTimeout = responseTimeoutMicro timeoutMicros
                }
    resp <- httpLbs req mgr
    let status = responseStatus resp
        rawBody = maxBodyBytesL (responseBody resp)
    if not (statusIsSuccessful status)
        then pure (Just (failOpenDecision cfg "hook returned non-2xx"))
        else case Aeson.eitherDecode rawBody of
            Left _ -> pure (Just (HookReject "invalid hook response"))
            Right v -> pure (Just (parseDecision v))

-- | Cap response body at 64 KB to bound memory.
maxBodyBytesL :: BSL.ByteString -> BSL.ByteString
maxBodyBytesL = BSL.take 65536

parseDecision :: Value -> HookDecision
parseDecision (Aeson.Object o) =
    case KeyMap.lookup "decision" o of
        Just (Aeson.String "allow") -> HookAllow
        Just (Aeson.String "allow_with") ->
            case KeyMap.lookup "overlay" o of
                Just overlay -> HookAllowWith overlay
                Nothing -> HookReject "missing overlay for allow_with"
        Just (Aeson.String "reject") ->
            case KeyMap.lookup "reason" o of
                Just (Aeson.String r) -> HookReject r
                _ -> HookReject "rejected by hook"
        _ -> HookReject "invalid hook response"
parseDecision _ = HookReject "invalid hook response"

respFailOpen :: HookConfig -> Text -> IO HookDecision
respFailOpen cfg reason = pure (failOpenDecision cfg reason)

failOpenDecision :: HookConfig -> Text -> HookDecision
failOpenDecision cfg reason =
    if hookConfigFailOpen cfg then HookAllow else HookReject reason

-- ---------------------------------------------------------------------------
-- Standard Webhooks signing (inline until #82 lands)
-- ---------------------------------------------------------------------------

-- | Headers produced by 'signHookRequest'.
data SignedHeaders = SignedHeaders
    { sigWebhookId :: BS.ByteString
    , sigWebhookTimestamp :: BS.ByteString
    , sigWebhookSignature :: BS.ByteString
    }
    deriving stock (Eq, Show)

-- | Sign @body@ using HMAC-SHA256 per the Standard Webhooks convention.
signHookRequest ::
    -- | Raw secret bytes
    BS.ByteString ->
    -- | Used as webhook-id
    UUID ->
    POSIXTime ->
    -- | Request body
    BS.ByteString ->
    SignedHeaders
signHookRequest secret hookId ts body =
    let wid = BSC.pack (UUID.toString hookId)
        wts = BSC.pack (show (round ts :: Integer))
        digest = computeHmac secret (wid <> "." <> wts <> "." <> body)
        sig = "v1," <> B64.encode digest
     in SignedHeaders
            { sigWebhookId = wid
            , sigWebhookTimestamp = wts
            , sigWebhookSignature = sig
            }

-- | Verify any of the space-separated @v1,<base64>@ signatures in @wsig@.
verifyHookSignature ::
    -- | Raw secret bytes
    BS.ByteString ->
    -- | webhook-id header value
    BS.ByteString ->
    -- | webhook-timestamp header value
    BS.ByteString ->
    -- | webhook-signature header value
    BS.ByteString ->
    -- | Request body
    BS.ByteString ->
    Bool
verifyHookSignature secret wid wts wsig body =
    let signingInput = wid <> "." <> wts <> "." <> body
        expected = "v1," <> B64.encode (computeHmac secret signingInput)
        candidates = map BSC.strip (BSC.split ' ' wsig)
     in elem expected candidates

computeHmac :: BS.ByteString -> BS.ByteString -> BS.ByteString
computeHmac key msg =
    let mac = hmac key msg :: HMAC SHA256
     in convert (hmacGetDigest mac)
