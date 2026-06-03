module Spec.SessionSpec (spec) where

import qualified Data.Text as T
import Data.Time.Clock (getCurrentTime)
import qualified Data.UUID as UUID
import Hauth.Session (
    NewSession (..),
    Session (..),
    SessionId (..),
    generateOpaqueToken,
 )
import Test.Hspec (Spec, describe, it, shouldBe, shouldSatisfy)

spec :: Spec
spec = do
    describe "generateOpaqueToken" $ do
        it "produces a non-empty token of length 43" $ do
            tok1 <- generateOpaqueToken
            tok1 `shouldSatisfy` (not . T.null)
            T.length tok1 `shouldBe` 43
        it "produces distinct tokens on successive calls" $ do
            tok1 <- generateOpaqueToken
            tok2 <- generateOpaqueToken
            (tok1 /= tok2) `shouldBe` True

    describe "NewSession record" $
        it "exposes all expected fields" $ do
            let nilUUID = UUID.nil
                nsess =
                    NewSession
                        { newSessionUserId = nilUUID
                        , newSessionAal = "aal1"
                        , newSessionFactorId = Nothing
                        , newSessionUserAgent = Just "test-agent"
                        , newSessionIp = Just "127.0.0.1"
                        , newSessionNotAfter = Nothing
                        }
            newSessionUserId nsess `shouldBe` nilUUID
            newSessionAal nsess `shouldBe` "aal1"
            newSessionFactorId nsess `shouldBe` Nothing
            newSessionUserAgent nsess `shouldBe` Just "test-agent"
            newSessionIp nsess `shouldBe` Just "127.0.0.1"
            newSessionNotAfter nsess `shouldBe` Nothing

    describe "Session record" $
        it "exposes all expected fields" $ do
            let nilUUID = UUID.nil
                sid = SessionId nilUUID
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
            sessionId sess `shouldBe` sid
            sessionUserId sess `shouldBe` nilUUID
            sessionAal sess `shouldBe` "aal1"
            sessionFactorId sess `shouldBe` Nothing
            sessionNotAfter sess `shouldBe` Nothing
            sessionRefreshedAt sess `shouldBe` Nothing
            sessionUserAgent sess `shouldBe` Just "Mozilla/5.0"
            sessionIp sess `shouldBe` Just "192.168.1.1"
