module Spec.SessionSpec (runSpec) where

import qualified Data.Text as T
import Data.Time.Clock (getCurrentTime)
import qualified Data.UUID as UUID
import Hauth.Session (
    NewSession (..),
    Session (..),
    SessionId (..),
    generateOpaqueToken,
 )
import Spec.TestUtils (assertEqual)

runSpec :: IO ()
runSpec = do
    tok1 <- generateOpaqueToken
    assertEqual "generateOpaqueToken non-empty" True (not (T.null tok1))
    assertEqual "generateOpaqueToken length is 43" 43 (T.length tok1)
    tok2 <- generateOpaqueToken
    assertEqual "two tokens differ" True (tok1 /= tok2)
    let nilUUID = UUID.nil
        sid = SessionId nilUUID
        nsess =
            NewSession
                { newSessionUserId = nilUUID
                , newSessionAal = "aal1"
                , newSessionFactorId = Nothing
                , newSessionUserAgent = Just "test-agent"
                , newSessionIp = Just "127.0.0.1"
                , newSessionNotAfter = Nothing
                }
    assertEqual "newSession userId" nilUUID (newSessionUserId nsess)
    assertEqual "newSession aal" "aal1" (newSessionAal nsess)
    assertEqual "newSession factorId" Nothing (newSessionFactorId nsess)
    assertEqual "newSession userAgent" (Just "test-agent") (newSessionUserAgent nsess)
    assertEqual "newSession ip" (Just "127.0.0.1") (newSessionIp nsess)
    assertEqual "newSession notAfter" Nothing (newSessionNotAfter nsess)
    now2 <- getCurrentTime
    let sess =
            Session
                { sessionId = sid
                , sessionUserId = nilUUID
                , sessionCreatedAt = now2
                , sessionUpdatedAt = now2
                , sessionFactorId = Nothing
                , sessionAal = "aal1"
                , sessionNotAfter = Nothing
                , sessionRefreshedAt = Nothing
                , sessionUserAgent = Just "Mozilla/5.0"
                , sessionIp = Just "192.168.1.1"
                }
    assertEqual "session id" sid (sessionId sess)
    assertEqual "session userId" nilUUID (sessionUserId sess)
    assertEqual "session aal" "aal1" (sessionAal sess)
    assertEqual "session factorId" Nothing (sessionFactorId sess)
    assertEqual "session notAfter" Nothing (sessionNotAfter sess)
    assertEqual "session refreshedAt" Nothing (sessionRefreshedAt sess)
    assertEqual "session userAgent" (Just "Mozilla/5.0") (sessionUserAgent sess)
    assertEqual "session ip" (Just "192.168.1.1") (sessionIp sess)
