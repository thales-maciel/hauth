module Spec.AdminUISessionSpec (spec) where

import qualified Data.Text as T
import qualified Data.Text.Encoding as TE
import Hauth.AdminUI.Session (
    buildSessionCookie,
    clearSessionCookie,
    hashSessionToken,
    lookupSessionCookie,
    newSessionToken,
 )
import Test.Hspec (Spec, describe, it, shouldBe, shouldNotBe, shouldSatisfy)

spec :: Spec
spec = do
    describe "newSessionToken" $ do
        it "is 43 chars of unpadded base64url (256 bits)" $ do
            token <- newSessionToken
            T.length token `shouldBe` 43
            token `shouldSatisfy` T.all (`elem` base64UrlAlphabet)
        it "never repeats" $ do
            a <- newSessionToken
            b <- newSessionToken
            a `shouldNotBe` b

    describe "hashSessionToken" $ do
        it "produces a 64-char hex digest distinct from the token" $ do
            let digest = hashSessionToken "some-token"
            T.length digest `shouldBe` 64
            digest `shouldNotBe` "some-token"
        it "is deterministic" $
            hashSessionToken "x" `shouldBe` hashSessionToken "x"

    describe "buildSessionCookie" $ do
        let cookie = buildSessionCookie "tok123" 900
        it "carries the token under the admin cookie name" $
            cookie `shouldSatisfy` T.isPrefixOf "hauth_admin_session=tok123;"
        it "sets the #206 attributes" $ do
            cookie `shouldSatisfy` T.isInfixOf "HttpOnly"
            cookie `shouldSatisfy` T.isInfixOf "Secure"
            cookie `shouldSatisfy` T.isInfixOf "SameSite=Lax"
            cookie `shouldSatisfy` T.isInfixOf "Max-Age=900"
            cookie `shouldSatisfy` T.isInfixOf "Path=/admin/ui"

    describe "clearSessionCookie" $
        it "expires the cookie immediately" $ do
            clearSessionCookie `shouldSatisfy` T.isPrefixOf "hauth_admin_session=;"
            clearSessionCookie `shouldSatisfy` T.isInfixOf "Max-Age=0"

    describe "lookupSessionCookie" $ do
        it "finds the token in a single-pair header" $
            lookupSessionCookie "hauth_admin_session=abc" `shouldBe` Just "abc"
        it "finds the token among other cookies" $
            lookupSessionCookie "theme=dark; hauth_admin_session=abc; lang=en"
                `shouldBe` Just "abc"
        it "ignores other cookie names" $
            lookupSessionCookie "theme=dark; lang=en" `shouldBe` Nothing
        it "ignores an empty value" $
            lookupSessionCookie "hauth_admin_session=" `shouldBe` Nothing
        it "round-trips a freshly built cookie" $ do
            token <- newSessionToken
            let pair = T.takeWhile (/= ';') (buildSessionCookie token 60)
            lookupSessionCookie (TE.encodeUtf8 pair) `shouldBe` Just token

base64UrlAlphabet :: String
base64UrlAlphabet =
    ['A' .. 'Z'] <> ['a' .. 'z'] <> ['0' .. '9'] <> "-_"
