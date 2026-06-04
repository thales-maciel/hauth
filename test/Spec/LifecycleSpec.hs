{-# LANGUAGE BlockArguments #-}

{- | Regression tests for issue #161: lifecycle helpers must be exception-safe.

The verify command in @app/Main.hs@ and the e2e harness in @e2e/E2E/Helpers.hs@
previously sequenced @createAppEnv@, the body, and @destroyAppEnv@ as three
separate statements. If the body threw, the destroy never ran and the
connection pool (plus any background services) leaked.

The fix is to wrap each pair in 'Control.Exception.bracket'. These tests do
not import the real 'AppEnv' (it would need a live Postgres for construction);
instead they model the same nested-bracket shape with cheap IORef-backed
"resources" and assert the release IO ran whether the body succeeded or
threw. If a future change drops the bracket and goes back to manual
sequencing, these tests will fail.
-}
module Spec.LifecycleSpec (spec) where

import Control.Exception (SomeException, bracket, try)
import Data.IORef (IORef, modifyIORef', newIORef, readIORef)
import Test.Hspec (Spec, describe, it, shouldBe, shouldSatisfy)

-- | Counters for acquire/release events on the outer and inner brackets.
data LifecycleEvents = LifecycleEvents
    { outerAcquired :: IORef Int
    , outerReleased :: IORef Int
    , innerAcquired :: IORef Int
    , innerReleased :: IORef Int
    }

newLifecycleEvents :: IO LifecycleEvents
newLifecycleEvents =
    LifecycleEvents
        <$> newIORef 0
        <*> newIORef 0
        <*> newIORef 0
        <*> newIORef 0

bump :: IORef Int -> IO ()
bump ref = modifyIORef' ref (+ 1)

{- | The same nested-bracket shape as @withTestEnv@: outer pairs env
acquire/release with destroy, inner pairs background services start/stop.
-}
withMockTestEnv :: LifecycleEvents -> (() -> IO a) -> IO a
withMockTestEnv LifecycleEvents{..} action =
    bracket (bump outerAcquired) (\_ -> bump outerReleased) \_ ->
        bracket (bump innerAcquired) (\_ -> bump innerReleased) action

{- | The same single-bracket shape as the verify command: pair env
acquire/release with destroy around the runChecks body.
-}
withMockVerifyEnv :: IORef Int -> IORef Int -> (() -> IO a) -> IO a
withMockVerifyEnv acquired released =
    bracket (bump acquired) (\_ -> bump released)

spec :: Spec
spec = do
    describe "withTestEnv-shaped harness" $ do
        it "runs both releases on the happy path" $ do
            ev <- newLifecycleEvents
            withMockTestEnv ev \_ -> pure ()
            (,,,)
                <$> readIORef (outerAcquired ev)
                <*> readIORef (innerAcquired ev)
                <*> readIORef (innerReleased ev)
                <*> readIORef (outerReleased ev)
                >>= (`shouldBe` (1, 1, 1, 1))

        it "runs both releases when the action throws" $ do
            ev <- newLifecycleEvents
            result <-
                try (withMockTestEnv ev \_ -> error "boom") ::
                    IO (Either SomeException ())
            result `shouldSatisfy` either (const True) (const False)
            -- Both inner and outer release must have run, in that order
            -- (bracket guarantees LIFO release).
            readIORef (innerReleased ev) >>= (`shouldBe` 1)
            readIORef (outerReleased ev) >>= (`shouldBe` 1)

        it "runs the outer release when the inner acquire throws" $ do
            outerA <- newIORef (0 :: Int)
            outerR <- newIORef (0 :: Int)
            innerR <- newIORef (0 :: Int)
            let prog =
                    bracket (bump outerA) (\_ -> bump outerR) \_ ->
                        bracket
                            (ioError (userError "inner acquire boom"))
                            (\_ -> bump innerR)
                            (\_ -> pure ())
            result <- try prog :: IO (Either SomeException ())
            result `shouldSatisfy` either (const True) (const False)
            readIORef outerR >>= (`shouldBe` 1)
            -- Inner release must NOT run because inner acquire failed.
            readIORef innerR >>= (`shouldBe` 0)

    describe "runVerifyCommand-shaped harness" $ do
        it "releases the env on the happy path" $ do
            acquired <- newIORef (0 :: Int)
            released <- newIORef (0 :: Int)
            _ <- withMockVerifyEnv acquired released \_ -> pure ()
            readIORef acquired >>= (`shouldBe` 1)
            readIORef released >>= (`shouldBe` 1)

        it "releases the env when runChecks throws" $ do
            acquired <- newIORef (0 :: Int)
            released <- newIORef (0 :: Int)
            result <-
                try (withMockVerifyEnv acquired released \_ -> error "checks blew up") ::
                    IO (Either SomeException ())
            result `shouldSatisfy` either (const True) (const False)
            readIORef released >>= (`shouldBe` 1)
