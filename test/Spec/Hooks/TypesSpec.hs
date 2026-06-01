module Spec.Hooks.TypesSpec (runSpec) where

import Control.Exception (bracket_)
import Data.Maybe (fromMaybe)
import qualified Data.Text as T
import qualified Data.Text.Encoding as TE
import Database.PostgreSQL.Simple (
    Connection,
    Only (..),
    close,
    connectPostgreSQL,
    execute,
 )
import Hauth.Hooks.Types (
    HookConfig (..),
    HookPoint (..),
    hookPointName,
    loadHookConfig,
    parseHookPoint,
 )
import Spec.TestUtils (assertEqual)
import System.Environment (lookupEnv)

-- ---------------------------------------------------------------------------
-- Helpers
-- ---------------------------------------------------------------------------

withTestConn :: (Connection -> IO a) -> IO a
withTestConn action = do
    dbUrl <-
        fromMaybe "postgresql://hauth:hauth@localhost:5432/hauth"
            <$> lookupEnv "HAUTH_TEST_DATABASE_URL"
    conn <- connectPostgreSQL (TE.encodeUtf8 (T.pack dbUrl))
    result <- action conn
    close conn
    pure result

-- | Insert an auth.hooks row, run action, then unconditionally delete the row.
withHookRow ::
    Connection ->
    HookPoint ->
    T.Text {- url -} ->
    T.Text {- secret -} ->
    Int {- timeout_ms -} ->
    Bool {- fail_open -} ->
    Bool {- enabled -} ->
    IO a ->
    IO a
withHookRow conn hp url secret timeoutMs failOpen enabled =
    bracket_
        ( do
            _ <-
                execute
                    conn
                    "INSERT INTO auth.hooks \
                    \    (hook_point, url, secret, timeout_ms, fail_open, enabled) \
                    \VALUES (?, ?, ?, ?, ?, ?)"
                    ( hookPointName hp
                    , url
                    , secret
                    , timeoutMs
                    , failOpen
                    , enabled
                    )
            pure ()
        )
        ( do
            _ <-
                execute
                    conn
                    "DELETE FROM auth.hooks WHERE hook_point = ?"
                    (Only (hookPointName hp))
            pure ()
        )

-- ---------------------------------------------------------------------------
-- Spec
-- ---------------------------------------------------------------------------

runSpec :: IO ()
runSpec = do
    -- -----------------------------------------------------------------
    -- parseHookPoint / hookPointName round-trip (pure, no DB required)
    -- -----------------------------------------------------------------
    let allPoints = [minBound .. maxBound] :: [HookPoint]
    mapM_
        ( \hp ->
            assertEqual
                ("parseHookPoint (hookPointName " <> show hp <> ")")
                (Just hp)
                (parseHookPoint (hookPointName hp))
        )
        allPoints

    assertEqual
        "parseHookPoint unknown returns Nothing"
        Nothing
        (parseHookPoint "unknown-hook")

    -- -----------------------------------------------------------------
    -- loadHookConfig — DB-backed tests
    -- -----------------------------------------------------------------
    withTestConn $ \conn -> do
        -- Enabled row: loadHookConfig should return Just with the expected fields.
        withHookRow
            conn
            HookBeforeUserCreated
            "https://example.com/hooks/before-user-created"
            "test-secret"
            1500
            False
            True
            do
                mCfg <- loadHookConfig conn HookBeforeUserCreated
                case mCfg of
                    Nothing ->
                        fail "loadHookConfig enabled row: expected Just, got Nothing"
                    Just HookConfig{hookConfigPoint, hookConfigUrl, hookConfigTimeoutMs, hookConfigFailOpen} -> do
                        assertEqual
                            "loadHookConfig enabled: hookConfigPoint"
                            HookBeforeUserCreated
                            hookConfigPoint
                        assertEqual
                            "loadHookConfig enabled: hookConfigUrl"
                            "https://example.com/hooks/before-user-created"
                            hookConfigUrl
                        assertEqual
                            "loadHookConfig enabled: hookConfigTimeoutMs"
                            1500
                            hookConfigTimeoutMs
                        assertEqual
                            "loadHookConfig enabled: hookConfigFailOpen"
                            False
                            hookConfigFailOpen

        -- Disabled row: loadHookConfig should return Nothing.
        withHookRow
            conn
            HookCustomAccessToken
            "https://example.com/hooks/custom-access-token"
            "test-secret"
            2000
            False
            False
            do
                mCfg <- loadHookConfig conn HookCustomAccessToken
                assertEqual
                    "loadHookConfig disabled row: expected Nothing"
                    Nothing
                    mCfg
