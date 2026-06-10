module Spec.AdminUISpec (spec) where

import qualified Data.Text as T
import qualified Data.Text.Lazy as TL
import Hauth.AdminUI (homePage, loginPage)
import Test.Hspec (Spec, describe, it, shouldNotSatisfy, shouldSatisfy)
import Text.Blaze.Html.Renderer.Text (renderHtml)

spec :: Spec
spec = do
    describe "AdminUI homePage" $ do
        let rendered = TL.toStrict (renderHtml (homePage "root"))
        it "is a complete HTML document" $
            rendered `shouldSatisfy` T.isInfixOf "<!DOCTYPE HTML>"
        it "carries the heading" $
            rendered `shouldSatisfy` T.isInfixOf "Hauth admin"
        it "links to the v0.3 milestone" $
            rendered `shouldSatisfy` T.isInfixOf "milestone/3"
        it "sets a UTF-8 charset" $
            rendered `shouldSatisfy` T.isInfixOf "charset=\"utf-8\""
        it "ships an inline base stylesheet" $
            rendered `shouldSatisfy` T.isInfixOf "<style>"
        it "names the signed-in admin" $
            rendered `shouldSatisfy` T.isInfixOf "Signed in as <strong>root</strong>"
        it "offers a logout form" $
            rendered `shouldSatisfy` T.isInfixOf "action=\"/admin/ui/logout\""

    describe "AdminUI loginPage" $ do
        let rendered = TL.toStrict (renderHtml (loginPage False))
            renderedWithError = TL.toStrict (renderHtml (loginPage True))
        it "posts to the login endpoint" $
            rendered `shouldSatisfy` T.isInfixOf "action=\"/admin/ui/login\""
        it "asks for username and password" $ do
            rendered `shouldSatisfy` T.isInfixOf "name=\"username\""
            rendered `shouldSatisfy` T.isInfixOf "name=\"password\""
        it "masks the password input" $
            rendered `shouldSatisfy` T.isInfixOf "type=\"password\""
        it "stays quiet without an error flag" $
            rendered `shouldNotSatisfy` T.isInfixOf "Invalid username or password"
        it "shows a generic message on failed attempts" $
            renderedWithError `shouldSatisfy` T.isInfixOf "Invalid username or password"
