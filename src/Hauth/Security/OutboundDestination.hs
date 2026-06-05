{-# LANGUAGE NumericUnderscores #-}

{- | Outbound destination policy for hooks and webhooks.

This module provides two complementary enforcement layers against SSRF
(Server-Side Request Forgery):

1. __Validation-time__ ('checkDestination'): resolve the hostname via DNS and
   reject if any A/AAAA record falls in a blocked range.  Catches obvious
   misconfiguration before anything is stored.

2. __Delivery-time__ ('newOutboundManager'): a custom @http-client@ 'Manager'
   that re-resolves and re-checks the destination on every outbound HTTP
   request.  This is mandatory because DNS TTLs can be as short as 1 second,
   meaning a hostname could resolve to a public IP at validation time and then
   rebind to @169.254.169.254@ milliseconds later (DNS rebinding attack).

Both layers are required; neither alone is sufficient.

== Blocked ranges (default policy, always on)

* @127.0.0.0\/8@ — loopback IPv4
* @169.254.0.0\/16@ — link-local IPv4 (includes cloud metadata endpoints)
* @10.0.0.0\/8@, @172.16.0.0\/12@, @192.168.0.0\/16@ — RFC 1918 private
* @::1@ — loopback IPv6
* @fc00::\/7@ — unique-local IPv6
* @fe80::\/10@ — link-local IPv6
* IPv4-mapped IPv6 forms of the above (e.g. @::ffff:10.0.0.1@)

The module is intentionally self-contained: CIDR checks are inlined using
'Network.Socket' types so no additional Hackage dependency is required.
-}
module Hauth.Security.OutboundDestination (
    -- * Validation-time check (DNS lookup)
    checkDestination,
    defaultResolver,

    -- * Delivery-time enforcement
    newOutboundManager,
    hardenedManagerSettings,

    -- * IP classification (exported for unit tests)
    isBlockedAddr,
    isBlockedIpv4Tuple,
    isBlockedIpv6Tuple,
) where

import Control.Exception (throwIO)
import Data.Bits (shiftR, (.&.))
import qualified Data.ByteString.Char8 as BSC
import Data.Text (Text)
import Data.Word (Word16, Word8)
import Hauth.Validation.URL (parseHttpUrl)
import Network.HTTP.Client (
    Manager,
    ManagerSettings,
    Request (host),
    managerModifyRequest,
    managerResponseTimeout,
    newManager,
    responseTimeoutMicro,
 )
import Network.HTTP.Client.TLS (tlsManagerSettings)
import Network.Socket (
    AddrInfo (..),
    AddrInfoFlag (..),
    SockAddr (..),
    SocketType (..),
    defaultHints,
    getAddrInfo,
    hostAddress6ToTuple,
    hostAddressToTuple,
 )
import Network.URI (uriAuthority, uriRegName)

-- ---------------------------------------------------------------------------
-- Validation-time check
-- ---------------------------------------------------------------------------

{- | Check that @url@ is a valid absolute HTTP(S) URL whose destination is not
in a blocked IP range.

The @resolver@ argument is the DNS lookup function.  Pass 'defaultResolver'
in production; pass a stub in unit tests to avoid real DNS calls and to test
specific IP addresses.

Returns @'Right' ()@ when the destination is acceptable, @'Left' reason@
otherwise.
-}
checkDestination ::
    -- | DNS resolver: hostname → addresses (injectable for testing)
    (String -> IO [SockAddr]) ->
    -- | Candidate destination URL
    Text ->
    IO (Either String ())
checkDestination resolve url =
    case parseHttpUrl url of
        Left msg ->
            pure (Left msg)
        Right uri ->
            case uriAuthority uri of
                Nothing ->
                    pure (Left "must be an absolute http:// or https:// URL")
                Just auth ->
                    case uriRegName auth of
                        "" ->
                            pure (Left "must be an absolute http:// or https:// URL")
                        hostname -> do
                            addrs <- resolve hostname
                            let blocked = filter isBlockedAddr addrs
                            case blocked of
                                [] ->
                                    pure (Right ())
                                (addr : _) ->
                                    pure
                                        ( Left
                                            ( "destination resolves to a blocked address: "
                                                <> show addr
                                            )
                                        )

{- | Default production DNS resolver.

Calls 'getAddrInfo' requesting results with 'AI_ADDRCONFIG' so only address
families with a configured interface are returned.
-}
defaultResolver :: String -> IO [SockAddr]
defaultResolver hostname = do
    let hints =
            defaultHints
                { addrFlags = [AI_ADDRCONFIG]
                , addrSocketType = Stream
                }
    results <- getAddrInfo (Just hints) (Just hostname) Nothing
    pure (fmap addrAddress results)

-- ---------------------------------------------------------------------------
-- Delivery-time enforcement (Manager)
-- ---------------------------------------------------------------------------

{- | Construct a hardened TLS-capable 'Manager'.

Every outbound request is checked against the blocked-range policy before it
is sent: the hostname is re-resolved via DNS and rejected with an 'IOException'
if any resolved address falls in a blocked range.  This guards against DNS
rebinding attacks where a hostname resolves differently between validation
time and delivery time.

Use this in production code wherever a 'Manager' makes calls to
operator-configured URLs (hooks, webhooks).
-}
newOutboundManager :: IO Manager
newOutboundManager =
    newManager hardenedManagerSettings

{- | 'ManagerSettings' with the SSRF guard layered on top of 'tlsManagerSettings'.

Sets a 10-second default response timeout (matching the previous per-manager
timeout in the webhook worker) and installs 'checkRequestDestination' as the
pre-request guard.

Prefer 'newOutboundManager' unless you need to further customise settings
before constructing the 'Manager'.
-}
hardenedManagerSettings :: ManagerSettings
hardenedManagerSettings =
    tlsManagerSettings
        { managerModifyRequest = checkRequestDestination
        , managerResponseTimeout = responseTimeoutMicro 10_000_000
        }

{- | Per-request guard wired into the Manager via 'managerModifyRequest'.

Re-resolves the request's @Host@ header and throws an 'IOException' if the
destination is in a blocked range.  The exception is caught by the
@try \@SomeException@ wrappers in 'Hauth.Hooks.Runner.runHook' and
'Hauth.Webhooks.Worker.deliverPayload', both of which treat it as a delivery
failure.
-}
checkRequestDestination :: Request -> IO Request
checkRequestDestination req = do
    let hostname = BSC.unpack (host req)
    addrs <- defaultResolver hostname
    let blocked = filter isBlockedAddr addrs
    case blocked of
        [] -> pure req
        (addr : _) ->
            throwIO
                ( userError
                    ( "outbound request blocked: destination resolves to a blocked address: "
                        <> show addr
                    )
                )

-- ---------------------------------------------------------------------------
-- IP range classification
-- ---------------------------------------------------------------------------

-- | True when the 'SockAddr' falls in any blocked range.
isBlockedAddr :: SockAddr -> Bool
isBlockedAddr = \case
    SockAddrInet _ addr4 ->
        isBlockedIpv4Tuple (hostAddressToTuple addr4)
    SockAddrInet6 _ _ addr6 _ ->
        isBlockedIpv6Tuple (hostAddress6ToTuple addr6)
    _ ->
        False

{- | True when the IPv4 address, expressed as a 4-octet tuple @(a, b, c, d)@,
is in a blocked range.

Checked ranges:

* @127.0.0.0\/8@    — loopback
* @169.254.0.0\/16@ — link-local (includes AWS\/GCP metadata @169.254.169.254@)
* @10.0.0.0\/8@    — RFC 1918
* @172.16.0.0\/12@ — RFC 1918
* @192.168.0.0\/16@ — RFC 1918
-}
isBlockedIpv4Tuple :: (Word8, Word8, Word8, Word8) -> Bool
isBlockedIpv4Tuple (a, b, _, _) =
    -- 127.0.0.0/8
    a == 127
        -- 169.254.0.0/16
        || (a == 169 && b == 254)
        -- 10.0.0.0/8
        || a == 10
        -- 172.16.0.0/12
        || (a == 172 && b >= 16 && b <= 31)
        -- 192.168.0.0/16
        || (a == 192 && b == 168)

{- | True when the IPv6 address, expressed as an 8-element 'Word16' tuple,
is in a blocked range.

Checked ranges:

* @::1@            — loopback
* @fc00::\/7@       — unique-local
* @fe80::\/10@      — link-local
* @::ffff:0:0\/96@  — IPv4-mapped; the embedded IPv4 part is re-checked with
  'isBlockedIpv4Tuple'
-}
isBlockedIpv6Tuple :: (Word16, Word16, Word16, Word16, Word16, Word16, Word16, Word16) -> Bool
isBlockedIpv6Tuple tup@(w0, w1, w2, w3, w4, w5, w6, w7) =
    -- ::1 — loopback
    tup == (0, 0, 0, 0, 0, 0, 0, 1)
        -- fc00::/7 — unique-local
        -- Top 7 bits of the first 16-bit word: 0xfc00 with mask 0xfe00
        || ((w0 .&. 0xfe00) == 0xfc00)
        -- fe80::/10 — link-local
        -- Top 10 bits: 0xfe80 with mask 0xffc0
        || ((w0 .&. 0xffc0) == 0xfe80)
        -- ::ffff:0:0/96 — IPv4-mapped IPv6
        -- Format: 0000:0000:0000:0000:0000:ffff:a.b.c.d
        || ( w0 == 0
                && w1 == 0
                && w2 == 0
                && w3 == 0
                && w4 == 0
                && w5 == 0xffff
                && isBlockedIpv4Tuple
                    ( fromIntegral (w6 `shiftR` 8)
                    , fromIntegral (w6 .&. 0xff)
                    , fromIntegral (w7 `shiftR` 8)
                    , fromIntegral (w7 .&. 0xff)
                    )
           )
