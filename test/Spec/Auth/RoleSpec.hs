module Spec.Auth.RoleSpec (spec) where

import Data.Text (Text)
import Hauth.Auth.Role (isReservedRole, sanitizeSessionRole)
import Test.Hspec (Spec, describe, it, shouldBe)

reservedCases :: [Text]
reservedCases =
    [ "service_role"
    , "anon"
    , "supabase_admin"
    , "supabase_auth_admin"
    ]

passthroughCases :: [Text]
passthroughCases =
    [ "authenticated"
    , "custom_app_role"
    , "vip"
    , "Service_Role" -- case-sensitive: only the exact reserved spelling is blocked
    ]

spec :: Spec
spec = do
    describe "isReservedRole" $ do
        mapM_
            ( \r ->
                it ("treats " <> show r <> " as reserved") $
                    isReservedRole r `shouldBe` True
            )
            reservedCases
        mapM_
            ( \r ->
                it ("does not reserve " <> show r) $
                    isReservedRole r `shouldBe` False
            )
            passthroughCases
        it "does not reserve the empty string" $
            isReservedRole "" `shouldBe` False

    describe "sanitizeSessionRole" $ do
        mapM_
            ( \r ->
                it ("rewrites " <> show r <> " to authenticated") $
                    sanitizeSessionRole r `shouldBe` "authenticated"
            )
            reservedCases
        it "rewrites the empty string to authenticated" $
            sanitizeSessionRole "" `shouldBe` "authenticated"
        mapM_
            ( \r ->
                it ("passes through " <> show r) $
                    sanitizeSessionRole r `shouldBe` r
            )
            passthroughCases
