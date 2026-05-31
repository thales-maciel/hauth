-- | Pure unit tests for 'Hauth.Auth.AalAmr'.  No live database required.
module Spec.Auth.AalAmrSpec (runSpec) where

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
import Spec.TestUtils (assertEqual)

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

runSpec :: IO ()
runSpec = do
    -- aalForSession
    assertEqual "aalForSession: no factor → aal1" "aal1" (aalForSession sessionWithNoFactor)
    assertEqual "aalForSession: with factor → aal2" "aal2" (aalForSession sessionWithFactor)

    -- deriveSessionAuthState: no initiating method override
    assertEqual
        "deriveSessionAuthState Nothing noFactor -> aal1 [password]"
        (SessionAuthState "aal1" ["password"])
        (deriveSessionAuthState Nothing sessionWithNoFactor)

    assertEqual
        "deriveSessionAuthState Nothing withFactor -> aal2 [password, totp]"
        (SessionAuthState "aal2" ["password", "totp"])
        (deriveSessionAuthState Nothing sessionWithFactor)

    -- deriveSessionAuthState: oauth override
    assertEqual
        "deriveSessionAuthState (Just oauth) noFactor -> aal1 [oauth]"
        (SessionAuthState "aal1" ["oauth"])
        (deriveSessionAuthState (Just "oauth") sessionWithNoFactor)

    assertEqual
        "deriveSessionAuthState (Just oauth) withFactor -> aal2 [oauth, totp]"
        (SessionAuthState "aal2" ["oauth", "totp"])
        (deriveSessionAuthState (Just "oauth") sessionWithFactor)

    -- buildAmrEntries
    let ts = 1780000000
        entries = buildAmrEntries ["password", "totp"] ts
    assertEqual "buildAmrEntries: list length" 2 (length entries)
    assertEqual "buildAmrEntries: method 0" "password" (amrMethod (head entries))
    assertEqual "buildAmrEntries: method 1" "totp" (amrMethod (entries !! 1))
    assertEqual "buildAmrEntries: timestamp 0" (floor ts :: Integer) (amrTimestamp (head entries))
    assertEqual "buildAmrEntries: timestamp 1" (floor ts :: Integer) (amrTimestamp (entries !! 1))
