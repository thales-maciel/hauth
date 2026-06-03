module Spec.APISpec (spec) where

import Hauth.API (hauthAPI)
import Hauth.Server (server)
import Test.Hspec (Spec, describe, it, shouldBe)

spec :: Spec
spec =
    describe "API surface" $
        it "forces hauthAPI and server without bottoms" $
            (hauthAPI `seq` server `seq` True) `shouldBe` True
