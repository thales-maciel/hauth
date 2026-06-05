-- | Wire-shape coverage for the admin sync-hooks surface.
module Spec.API.Golden.HooksSpec (spec) where

import Hauth.API.Types
import Spec.API.Golden.Helpers (
    canonicalHookCreateResponse,
    canonicalHookRow,
    decodeShape,
    encodeShape,
    hookCreateResponseJson,
    hookRowJson,
    roundTrip,
 )
import Test.Hspec (Spec, describe, it)

spec :: Spec
spec = describe "Sync hooks" $ do
    -- HookRow: secret is always redacted on read/list.
    -- ToJSON emits "***redacted***"; FromJSON reads whatever is in the field.
    -- We test encoding separately since decode(encode(row)) != row for the
    -- secret field (encode redacts; decode would read "***redacted***").
    it "HookRow encodes with redacted secret" $
        encodeShape
            "HookRow"
            canonicalHookRow
            hookRowJson

    -- HookCreateResponse: reveals the real secret exactly once on create.
    it "HookCreateResponse round-trips" $
        roundTrip
            "HookCreateResponse"
            canonicalHookCreateResponse
            hookCreateResponseJson

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

    -- UpdateHookRequest no longer has a secret field.
    it "UpdateHookRequest" $
        decodeShape
            "UpdateHookRequest"
            "{\"url\":\"https://example.com/hook2\",\"enabled\":false}"
            UpdateHookRequest
                { updateHookUrl = Just "https://example.com/hook2"
                , updateHookTimeoutMs = Nothing
                , updateHookFailOpen = Nothing
                , updateHookEnabled = Just False
                }

    it "ListHooksResponse encodes with redacted secret" $
        encodeShape
            "ListHooksResponse"
            ListHooksResponse{listHookRows = [canonicalHookRow]}
            ("{\"hooks\":[" <> hookRowJson <> "]}")

    it "RotateHookSecretRequest decodes with explicit secret" $
        decodeShape
            "RotateHookSecretRequest"
            "{\"secret\":\"newsecret\"}"
            RotateHookSecretRequest{rotateHookSecret = Just "newsecret"}

    it "RotateHookSecretRequest decodes with absent secret" $
        decodeShape
            "RotateHookSecretRequest"
            "{}"
            RotateHookSecretRequest{rotateHookSecret = Nothing}

    it "RotateHookSecretResponse" $
        roundTrip
            "RotateHookSecretResponse"
            RotateHookSecretResponse{rotateHookNewSecret = "fresh-secret"}
            "{\"secret\":\"fresh-secret\"}"
