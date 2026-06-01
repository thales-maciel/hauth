module Spec.Hooks.TypesSpec (runSpec) where

import Hauth.Hooks.Types (HookPoint, hookPointName, parseHookPoint)
import Spec.TestUtils (assertEqual)

runSpec :: IO ()
runSpec = do
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
