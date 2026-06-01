{-# LANGUAGE OverloadedStrings #-}

module E2E.HooksTypesSpec (spec) where

import Control.Exception (bracket_)
import Database.PostgreSQL.Simple (Only (..), execute)
import E2E.Helpers (TestEnv (..))
import Hauth.Env (withDatabaseConnection)
import Hauth.Hooks.Types (
    HookConfig (..),
    HookPoint (..),
    hookPointName,
    loadHookConfig,
 )
import Test.Hspec (SpecWith, describe, it, shouldBe)

spec :: SpecWith TestEnv
spec = do
    describe "loadHookConfig" do
        it "returns Just with the expected fields for an enabled row" \env ->
            withDatabaseConnection (testAppEnv env) \conn ->
                bracket_
                    ( execute
                        conn
                        "INSERT INTO auth.hooks \
                        \    (hook_point, url, secret, timeout_ms, fail_open, enabled) \
                        \VALUES (?, ?, ?, ?, ?, ?)"
                        ( hookPointName HookBeforeUserCreated
                        , "https://example.com/hooks/before-user-created" :: String
                        , "test-secret" :: String
                        , 1500 :: Int
                        , False
                        , True
                        )
                    )
                    ( execute
                        conn
                        "DELETE FROM auth.hooks WHERE hook_point = ?"
                        (Only (hookPointName HookBeforeUserCreated))
                    )
                    do
                        mCfg <- loadHookConfig conn HookBeforeUserCreated
                        case mCfg of
                            Nothing ->
                                expectationFail "expected Just, got Nothing"
                            Just HookConfig{hookConfigPoint, hookConfigUrl, hookConfigTimeoutMs, hookConfigFailOpen} -> do
                                hookConfigPoint `shouldBe` HookBeforeUserCreated
                                hookConfigUrl `shouldBe` "https://example.com/hooks/before-user-created"
                                hookConfigTimeoutMs `shouldBe` 1500
                                hookConfigFailOpen `shouldBe` False

        it "returns Nothing for a disabled row" \env ->
            withDatabaseConnection (testAppEnv env) \conn ->
                bracket_
                    ( execute
                        conn
                        "INSERT INTO auth.hooks \
                        \    (hook_point, url, secret, timeout_ms, fail_open, enabled) \
                        \VALUES (?, ?, ?, ?, ?, ?)"
                        ( hookPointName HookCustomAccessToken
                        , "https://example.com/hooks/custom-access-token" :: String
                        , "test-secret" :: String
                        , 2000 :: Int
                        , False
                        , False
                        )
                    )
                    ( execute
                        conn
                        "DELETE FROM auth.hooks WHERE hook_point = ?"
                        (Only (hookPointName HookCustomAccessToken))
                    )
                    do
                        mCfg <- loadHookConfig conn HookCustomAccessToken
                        mCfg `shouldBe` Nothing
  where
    expectationFail msg = error ("hooks types e2e: " <> msg)
