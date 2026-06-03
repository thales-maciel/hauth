module Spec.Verify.DatabaseSpec (spec) where

import Hauth.Verify (Check (..))
import Hauth.Verify.Database (checks)
import Test.Hspec (Spec, describe, it, shouldBe)

spec :: Spec
spec = do
    describe "database checks exported" $ do
        it "database checks count is 3" $
            length checks `shouldBe` 3

        it "first check name is config.parse" $
            checkName (head checks) `shouldBe` "config.parse"

        it "second check name is database.connect" $
            checkName (checks !! 1) `shouldBe` "database.connect"

        it "third check name is database.migrations" $
            checkName (checks !! 2) `shouldBe` "database.migrations"
