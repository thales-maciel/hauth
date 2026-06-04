-- | Wire-shape coverage for the admin sync-hooks surface.
module Spec.API.Golden.HooksSpec (spec) where

import Hauth.API.Types
import Spec.API.Golden.Helpers (
    canonicalHookRow,
    decodeShape,
    encodeShape,
    hookRowJson,
    roundTrip,
 )
import Test.Hspec (Spec, describe, it)

spec :: Spec
spec = describe "Sync hooks" $ do
    it "HookRow" $
        roundTrip
            "HookRow"
            canonicalHookRow
            hookRowJson

    it "CreateHookRequest" $
        decodeShape
            "CreateHookRequest"
            "{\"hook_point\":\"before-user-created\",\"url\":\"https://example.com/hook\"\
            \,\"secret\":\"shh\",\"timeout_ms\":1000,\"fail_open\":true,\"enabled\":true}"
            CreateHookRequest
                { createHookPoint = "before-user-created"
                , createHookUrl = "https://example.com/hook"
                , createHookSecret = Just "shh"
                , createHookTimeoutMs = Just 1000
                , createHookFailOpen = Just True
                , createHookEnabled = Just True
                }

    it "UpdateHookRequest" $
        decodeShape
            "UpdateHookRequest"
            "{\"url\":\"https://example.com/hook2\",\"enabled\":false}"
            UpdateHookRequest
                { updateHookUrl = Just "https://example.com/hook2"
                , updateHookSecret = Nothing
                , updateHookTimeoutMs = Nothing
                , updateHookFailOpen = Nothing
                , updateHookEnabled = Just False
                }

    it "ListHooksResponse" $
        encodeShape
            "ListHooksResponse"
            ListHooksResponse{listHookRows = [canonicalHookRow]}
            ("{\"hooks\":[" <> hookRowJson <> "]}")
