module Spec.Security.OutboundDestinationSpec (spec) where

import Control.Exception (throwIO)
import Data.Word (Word16, Word8)
import Hauth.Security.OutboundDestination (
    checkDestination,
    isBlockedAddr,
    isBlockedIpv4Tuple,
    isBlockedIpv6Tuple,
 )
import Network.Socket (
    SockAddr (..),
    tupleToHostAddress,
    tupleToHostAddress6,
 )
import System.IO.Error (userError)
import Test.Hspec (Spec, describe, it, shouldBe, shouldSatisfy)

-- ---------------------------------------------------------------------------
-- Stub resolver helpers
-- ---------------------------------------------------------------------------

{- | A stub resolver that always returns a single IPv4 SockAddr for the given
packed tuple.
-}
resolveAs4 :: (Word8, Word8, Word8, Word8) -> String -> IO [SockAddr]
resolveAs4 tup _ = pure [SockAddrInet 0 (tupleToHostAddress tup)]

-- | A stub resolver that always returns a single IPv6 SockAddr.
resolveAs6 :: (Word16, Word16, Word16, Word16, Word16, Word16, Word16, Word16) -> String -> IO [SockAddr]
resolveAs6 tup _ = pure [SockAddrInet6 0 0 (tupleToHostAddress6 tup) 0]

-- | A stub resolver that always returns an empty list (hostname has no records).
resolveEmpty :: String -> IO [SockAddr]
resolveEmpty _ = pure []

-- | A stub resolver that returns a public IPv4 address.
resolvePublic :: String -> IO [SockAddr]
resolvePublic = resolveAs4 (93, 184, 216, 34) -- example.com

-- | A stub resolver that throws an IOException, mimicking NXDOMAIN / timeout.
resolveFails :: String -> IO [SockAddr]
resolveFails _ = throwIO (userError "simulated DNS failure")

-- ---------------------------------------------------------------------------
-- Spec
-- ---------------------------------------------------------------------------

spec :: Spec
spec = do
    describe "isBlockedIpv4Tuple" $ do
        it "blocks 0.0.0.0 (kernel routes to loopback)" $
            isBlockedIpv4Tuple (0, 0, 0, 0) `shouldBe` True

        it "blocks 0.1.2.3 (0.0.0.0/8)" $
            isBlockedIpv4Tuple (0, 1, 2, 3) `shouldBe` True

        it "blocks 127.0.0.1 (loopback)" $
            isBlockedIpv4Tuple (127, 0, 0, 1) `shouldBe` True

        it "blocks 127.255.255.255 (loopback /8 boundary)" $
            isBlockedIpv4Tuple (127, 255, 255, 255) `shouldBe` True

        it "blocks 169.254.169.254 (AWS metadata)" $
            isBlockedIpv4Tuple (169, 254, 169, 254) `shouldBe` True

        it "blocks 169.254.0.1 (link-local)" $
            isBlockedIpv4Tuple (169, 254, 0, 1) `shouldBe` True

        it "blocks 10.0.0.1 (RFC1918 /8)" $
            isBlockedIpv4Tuple (10, 0, 0, 1) `shouldBe` True

        it "blocks 10.255.255.255 (RFC1918 /8 boundary)" $
            isBlockedIpv4Tuple (10, 255, 255, 255) `shouldBe` True

        it "blocks 172.16.0.1 (RFC1918 /12 lower)" $
            isBlockedIpv4Tuple (172, 16, 0, 1) `shouldBe` True

        it "blocks 172.31.255.255 (RFC1918 /12 upper)" $
            isBlockedIpv4Tuple (172, 31, 255, 255) `shouldBe` True

        it "does NOT block 172.15.255.255 (just below RFC1918 /12)" $
            isBlockedIpv4Tuple (172, 15, 255, 255) `shouldBe` False

        it "does NOT block 172.32.0.0 (just above RFC1918 /12)" $
            isBlockedIpv4Tuple (172, 32, 0, 0) `shouldBe` False

        it "blocks 192.168.0.1 (RFC1918 /16)" $
            isBlockedIpv4Tuple (192, 168, 0, 1) `shouldBe` True

        it "blocks 192.168.255.255 (RFC1918 /16 boundary)" $
            isBlockedIpv4Tuple (192, 168, 255, 255) `shouldBe` True

        it "does NOT block 8.8.8.8 (public)" $
            isBlockedIpv4Tuple (8, 8, 8, 8) `shouldBe` False

        it "does NOT block 93.184.216.34 (example.com)" $
            isBlockedIpv4Tuple (93, 184, 216, 34) `shouldBe` False

    describe "isBlockedIpv6Tuple" $ do
        it "blocks ::1 (loopback)" $
            isBlockedIpv6Tuple (0, 0, 0, 0, 0, 0, 0, 1) `shouldBe` True

        it "does NOT block ::2 (not loopback)" $
            isBlockedIpv6Tuple (0, 0, 0, 0, 0, 0, 0, 2) `shouldBe` False

        it "blocks fc00::1 (unique-local lower)" $
            isBlockedIpv6Tuple (0xfc00, 0, 0, 0, 0, 0, 0, 1) `shouldBe` True

        it "blocks fd00::1 (unique-local)" $
            isBlockedIpv6Tuple (0xfd00, 0, 0, 0, 0, 0, 0, 1) `shouldBe` True

        it "blocks fdff:ffff:ffff:ffff:ffff:ffff:ffff:ffff (unique-local upper)" $
            isBlockedIpv6Tuple (0xfdff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff) `shouldBe` True

        it "does NOT block fe00:: (just above unique-local)" $
            isBlockedIpv6Tuple (0xfe00, 0, 0, 0, 0, 0, 0, 0) `shouldBe` False

        it "blocks fe80::1 (link-local)" $
            isBlockedIpv6Tuple (0xfe80, 0, 0, 0, 0, 0, 0, 1) `shouldBe` True

        it "blocks febf::1 (link-local upper)" $
            isBlockedIpv6Tuple (0xfebf, 0, 0, 0, 0, 0, 0, 1) `shouldBe` True

        it "does NOT block fec0:: (just above link-local)" $
            isBlockedIpv6Tuple (0xfec0, 0, 0, 0, 0, 0, 0, 0) `shouldBe` False

        it "blocks ::ffff:10.0.0.1 (IPv4-mapped, RFC1918)" $
            -- ::ffff:10.0.0.1 = (0,0,0,0,0,0xffff,0x0a00,0x0001)
            isBlockedIpv6Tuple (0, 0, 0, 0, 0, 0xffff, 0x0a00, 0x0001) `shouldBe` True

        it "blocks ::ffff:127.0.0.1 (IPv4-mapped, loopback)" $
            -- ::ffff:127.0.0.1 = (0,0,0,0,0,0xffff,0x7f00,0x0001)
            isBlockedIpv6Tuple (0, 0, 0, 0, 0, 0xffff, 0x7f00, 0x0001) `shouldBe` True

        it "blocks ::ffff:192.168.0.1 (IPv4-mapped, RFC1918)" $
            -- ::ffff:192.168.0.1 = (0,0,0,0,0,0xffff,0xc0a8,0x0001)
            isBlockedIpv6Tuple (0, 0, 0, 0, 0, 0xffff, 0xc0a8, 0x0001) `shouldBe` True

        it "does NOT block ::ffff:8.8.8.8 (IPv4-mapped, public)" $
            -- ::ffff:8.8.8.8 = (0,0,0,0,0,0xffff,0x0808,0x0808)
            isBlockedIpv6Tuple (0, 0, 0, 0, 0, 0xffff, 0x0808, 0x0808) `shouldBe` False

        it "does NOT block 2001:db8::1 (documentation, public)" $
            isBlockedIpv6Tuple (0x2001, 0x0db8, 0, 0, 0, 0, 0, 1) `shouldBe` False

    describe "isBlockedAddr (SockAddr)" $ do
        it "blocks SockAddrInet 127.0.0.1" $
            isBlockedAddr (SockAddrInet 0 (tupleToHostAddress (127, 0, 0, 1))) `shouldBe` True

        it "allows SockAddrInet 8.8.8.8" $
            isBlockedAddr (SockAddrInet 0 (tupleToHostAddress (8, 8, 8, 8))) `shouldBe` False

        it "blocks SockAddrInet6 ::1" $
            isBlockedAddr (SockAddrInet6 0 0 (tupleToHostAddress6 (0, 0, 0, 0, 0, 0, 0, 1)) 0) `shouldBe` True

        it "allows SockAddrInet6 2001:db8::1" $
            isBlockedAddr (SockAddrInet6 0 0 (tupleToHostAddress6 (0x2001, 0x0db8, 0, 0, 0, 0, 0, 1)) 0) `shouldBe` False

    describe "checkDestination (with stub resolver)" $ do
        it "accepts https://example.com/hook when resolver returns public IP" $ do
            result <- checkDestination resolvePublic "https://example.com/hook"
            result `shouldBe` Right ()

        it "rejects ftp:// (wrong scheme)" $ do
            result <- checkDestination resolvePublic "ftp://example.com/hook"
            result `shouldSatisfy` isLeft

        it "rejects file:// (wrong scheme)" $ do
            result <- checkDestination resolvePublic "file:///etc/passwd"
            result `shouldSatisfy` isLeft

        it "rejects malformed URL (no host)" $ do
            result <- checkDestination resolvePublic "not-a-url"
            result `shouldSatisfy` isLeft

        it "rejects http://127.0.0.1 (loopback literal) via resolver" $ do
            result <- checkDestination (resolveAs4 (127, 0, 0, 1)) "http://127.0.0.1/path"
            result `shouldSatisfy` isLeft

        it "rejects http://localhost when resolver returns 127.0.0.1" $ do
            result <- checkDestination (resolveAs4 (127, 0, 0, 1)) "http://localhost/path"
            result `shouldSatisfy` isLeft

        it "rejects http://169.254.169.254 (metadata endpoint)" $ do
            result <- checkDestination (resolveAs4 (169, 254, 169, 254)) "http://169.254.169.254/latest/meta-data/"
            result `shouldSatisfy` isLeft

        it "rejects http://10.0.0.1 (RFC1918)" $ do
            result <- checkDestination (resolveAs4 (10, 0, 0, 1)) "http://internal.example.com/hook"
            result `shouldSatisfy` isLeft

        it "rejects http://172.16.0.1 (RFC1918)" $ do
            result <- checkDestination (resolveAs4 (172, 16, 0, 1)) "http://vpn.example.com/hook"
            result `shouldSatisfy` isLeft

        it "rejects http://192.168.0.1 (RFC1918)" $ do
            result <- checkDestination (resolveAs4 (192, 168, 0, 1)) "http://router.local/hook"
            result `shouldSatisfy` isLeft

        it "rejects http://[::1] (IPv6 loopback literal) via resolver" $ do
            result <- checkDestination (resolveAs6 (0, 0, 0, 0, 0, 0, 0, 1)) "http://[::1]/path"
            result `shouldSatisfy` isLeft

        it "rejects http://[fe80::1] (IPv6 link-local) via resolver" $ do
            result <- checkDestination (resolveAs6 (0xfe80, 0, 0, 0, 0, 0, 0, 1)) "http://[fe80::1]/path"
            result `shouldSatisfy` isLeft

        it "rejects http://[fc00::1] (IPv6 unique-local) via resolver" $ do
            result <- checkDestination (resolveAs6 (0xfc00, 0, 0, 0, 0, 0, 0, 1)) "http://[fc00::1]/path"
            result `shouldSatisfy` isLeft

        it "rejects IPv4-mapped IPv6 ::ffff:10.0.0.1 via resolver" $ do
            result <- checkDestination (resolveAs6 (0, 0, 0, 0, 0, 0xffff, 0x0a00, 0x0001)) "http://internal.example.com/hook"
            result `shouldSatisfy` isLeft

        it "accepts when resolver returns no records (rare but distinct from failure)" $ do
            -- A resolver that returns an empty list (no A/AAAA records) is treated as
            -- accept: we cannot prove the destination is blocked. This is the corner
            -- case of getAddrInfo succeeding with zero results, NOT the failure path.
            result <- checkDestination resolveEmpty "https://example.com/hook"
            result `shouldBe` Right ()

        it "rejects when resolver throws (NXDOMAIN / timeout)" $ do
            -- getAddrInfo throws IOException on real DNS failures. We catch and reject:
            -- an unresolvable host can't be validated, so we don't accept it. The user
            -- can retry once the name resolves. The delivery-time Manager guard
            -- re-resolves on each request, so this doesn't lock a config out forever.
            result <- checkDestination resolveFails "https://transient.example.com/hook"
            result `shouldSatisfy` isLeft

isLeft :: Either a b -> Bool
isLeft (Left _) = True
isLeft _ = False
