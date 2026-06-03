module Spec.Hooks.TypesSpec (spec) where

import Hauth.Hooks.Types (HookPoint, hookPointName, parseHookPoint)
import Test.Hspec (Spec, describe, it, shouldBe)

spec :: Spec
spec = describe "Hauth.Hooks.Types" $ do
    it "parseHookPoint . hookPointName round-trips for every HookPoint" $ do
        let allPoints = [minBound .. maxBound] :: [HookPoint]
            roundTrip hp = (hp, parseHookPoint (hookPointName hp))
            expected = fmap (\hp -> (hp, Just hp)) allPoints
        fmap roundTrip allPoints `shouldBe` expected
    it "parseHookPoint returns Nothing for an unknown name" $
        parseHookPoint "unknown-hook" `shouldBe` Nothing
