-- | Pure unit tests for 'Hauth.Auth.AalAmr'.  No live database required.
module Spec.Auth.AalAmrSpec (spec) where

import Data.Time (UTCTime (..))
import Data.Time.Calendar (fromGregorian)
import Data.UUID (nil)
import Hauth.Auth.AalAmr (
    SessionAuthState (..),
    aalForSession,
    buildAmrEntries,
    deriveSessionAuthState,
 )
import Hauth.Auth.Jwt (AmrEntry (..))
import Hauth.Session (Session (..), SessionId (..))
import Test.Hspec (Spec, describe, it, shouldBe)

-- ---------------------------------------------------------------------------
-- Fixture sessions
-- ---------------------------------------------------------------------------

baseTime :: UTCTime
baseTime = UTCTime (fromGregorian 2024 1 1) 0

-- | A session with no MFA factor — aal1.
sessionWithNoFactor :: Session
sessionWithNoFactor =
    Session
        { sessionId = SessionId nil
        , sessionUserId = nil
        , sessionCreatedAt = baseTime
        , sessionUpdatedAt = baseTime
        , sessionFactorId = Nothing
        , sessionAal = "aal1"
        , sessionNotAfter = Nothing
        , sessionRefreshedAt = Nothing
        , sessionUserAgent = Nothing
        , sessionIp = Nothing
        }

-- | A session elevated by a TOTP factor — aal2.
sessionWithFactor :: Session
sessionWithFactor =
    sessionWithNoFactor
        { sessionFactorId = Just nil
        , sessionAal = "aal2"
        }

-- ---------------------------------------------------------------------------
-- Tests
-- ---------------------------------------------------------------------------

spec :: Spec
spec = do
    describe "aalForSession" $ do
        it "returns aal1 when there is no factor" $
            aalForSession sessionWithNoFactor `shouldBe` "aal1"
        it "returns aal2 when a factor is attached" $
            aalForSession sessionWithFactor `shouldBe` "aal2"

    describe "deriveSessionAuthState (no initiating method override)" $ do
        it "no factor -> aal1 [password]" $
            deriveSessionAuthState Nothing sessionWithNoFactor
                `shouldBe` SessionAuthState "aal1" ["password"]
        it "with factor -> aal2 [password, totp]" $
            deriveSessionAuthState Nothing sessionWithFactor
                `shouldBe` SessionAuthState "aal2" ["password", "totp"]

    describe "deriveSessionAuthState (oauth override)" $ do
        it "no factor -> aal1 [oauth]" $
            deriveSessionAuthState (Just "oauth") sessionWithNoFactor
                `shouldBe` SessionAuthState "aal1" ["oauth"]
        it "with factor -> aal2 [oauth, totp]" $
            deriveSessionAuthState (Just "oauth") sessionWithFactor
                `shouldBe` SessionAuthState "aal2" ["oauth", "totp"]

    describe "buildAmrEntries" $
        it "builds one entry per method, all sharing the timestamp" $ do
            let ts = 1780000000
                entries = buildAmrEntries ["password", "totp"] ts
            length entries `shouldBe` 2
            amrMethod (head entries) `shouldBe` "password"
            amrMethod (entries !! 1) `shouldBe` "totp"
            amrTimestamp (head entries) `shouldBe` (floor ts :: Integer)
            amrTimestamp (entries !! 1) `shouldBe` (floor ts :: Integer)
