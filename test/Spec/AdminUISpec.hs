module Spec.AdminUISpec (spec) where

import qualified Data.Text as T
import qualified Data.Text.Lazy as TL
import Hauth.AdminUI (placeholderPage)
import Test.Hspec (Spec, describe, it, shouldSatisfy)
import Text.Blaze.Html.Renderer.Text (renderHtml)

spec :: Spec
spec = describe "AdminUI placeholderPage" $ do
    let rendered = TL.toStrict (renderHtml placeholderPage)
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
