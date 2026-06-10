{-# LANGUAGE OverloadedStrings #-}

-- | Full login/logout flow for the operator-facing admin UI (#206).
module E2E.AdminUISpec (spec) where

import qualified Data.ByteString as BS
import qualified Data.ByteString.Char8 as BSC
import qualified Data.ByteString.Lazy as BSL
import Data.Text (Text)
import qualified Data.Text.Encoding as TE
import Database.PostgreSQL.Simple (Only (..), execute, query_)
import E2E.Helpers (TestEnv (..), expectStatus, runApp)
import Hauth.AdminUI.Session (hashSessionToken)
import Hauth.Env (withDatabaseConnection)
import Network.HTTP.Types (HeaderName, hContentType, hCookie, hLocation)
import Network.Wai (requestHeaders, requestMethod)
import Network.Wai.Test (
    SRequest (..),
    SResponse (..),
    Session,
    defaultRequest,
    setPath,
    srequest,
 )
import Test.Hspec (SpecWith, describe, expectationFailure, it, shouldBe, shouldSatisfy)

spec :: SpecWith TestEnv
spec = do
    describe "auth wrapper on /admin/ui" $ do
        it "redirects anonymous requests to the login page" \env -> do
            resp <- runApp env (htmlGet "/admin/ui" Nothing)
            expectStatus 303 resp
            responseHeader hLocation resp `shouldBe` Just "/admin/ui/login"

        it "redirects a garbage cookie and clears it" \env -> do
            resp <- runApp env (htmlGet "/admin/ui" (Just "hauth_admin_session=garbage"))
            expectStatus 303 resp
            responseHeader hLocation resp `shouldBe` Just "/admin/ui/login"
            setCookie <- requireHeader "Set-Cookie" resp
            setCookie `shouldSatisfy` BS.isInfixOf "Max-Age=0"

    describe "login" $ do
        it "serves the form anonymously, with the error flag opt-in" \env -> do
            plain <- runApp env (htmlGet "/admin/ui/login" Nothing)
            expectStatus 200 plain
            bodyContains plain "action=\"/admin/ui/login\"" `shouldBe` True
            bodyContains plain "Invalid username or password" `shouldBe` False
            flagged <- runApp env (htmlGet "/admin/ui/login?error=1" Nothing)
            expectStatus 200 flagged
            bodyContains flagged "Invalid username or password" `shouldBe` True

        it "redirects bad passwords back without a cookie" \env -> do
            resp <- runApp env (loginPost "admin" "wrong-password")
            expectStatus 303 resp
            responseHeader hLocation resp `shouldBe` Just "/admin/ui/login?error=1"
            responseHeader "Set-Cookie" resp `shouldBe` Nothing

        it "redirects unknown usernames identically" \env -> do
            resp <- runApp env (loginPost "nobody" "e2e-admin-password")
            expectStatus 303 resp
            responseHeader hLocation resp `shouldBe` Just "/admin/ui/login?error=1"
            responseHeader "Set-Cookie" resp `shouldBe` Nothing

        it "sets a hardened session cookie and stores only the token digest" \env -> do
            resp <- runApp env (loginPost "admin" "e2e-admin-password")
            expectStatus 303 resp
            responseHeader hLocation resp `shouldBe` Just "/admin/ui"
            setCookie <- requireHeader "Set-Cookie" resp
            setCookie `shouldSatisfy` BS.isPrefixOf "hauth_admin_session="
            setCookie `shouldSatisfy` BS.isInfixOf "HttpOnly"
            setCookie `shouldSatisfy` BS.isInfixOf "Secure"
            setCookie `shouldSatisfy` BS.isInfixOf "SameSite=Lax"
            setCookie `shouldSatisfy` BS.isInfixOf "Max-Age=3600"
            setCookie `shouldSatisfy` BS.isInfixOf "Path=/admin/ui"
            let token = cookieToken setCookie
            rows <- sessionRows env
            rows `shouldBe` [(hashSessionToken (TE.decodeUtf8 token), "admin")]

        it "authenticates the home page with the fresh cookie" \env -> do
            token <- loginToken env
            resp <- runApp env (htmlGet "/admin/ui" (Just ("hauth_admin_session=" <> token)))
            expectStatus 200 resp
            bodyContains resp "Signed in as <strong>admin</strong>" `shouldBe` True

    describe "logout" $ do
        it "deletes the session row and clears the cookie" \env -> do
            token <- loginToken env
            let cookie = "hauth_admin_session=" <> token
            resp <- runApp env (formPost "/admin/ui/logout" "" (Just cookie))
            expectStatus 303 resp
            responseHeader hLocation resp `shouldBe` Just "/admin/ui/login"
            setCookie <- requireHeader "Set-Cookie" resp
            setCookie `shouldSatisfy` BS.isInfixOf "Max-Age=0"
            rows <- sessionRows env
            rows `shouldBe` []
            replay <- runApp env (htmlGet "/admin/ui" (Just cookie))
            expectStatus 303 replay

    describe "expiry" $
        it "stops authenticating once expires_at passes" \env -> do
            token <- loginToken env
            _ <-
                withDatabaseConnection (testAppEnv env) \conn ->
                    execute
                        conn
                        "UPDATE auth.admin_ui_sessions SET expires_at = now() - interval '1 second' WHERE token_hash = ?"
                        (Only (hashSessionToken (TE.decodeUtf8 token)))
            resp <- runApp env (htmlGet "/admin/ui" (Just ("hauth_admin_session=" <> token)))
            expectStatus 303 resp
            responseHeader hLocation resp `shouldBe` Just "/admin/ui/login"

-- Log in with the harness credential and return the raw cookie token.
loginToken :: TestEnv -> IO BS.ByteString
loginToken env = do
    resp <- runApp env (loginPost "admin" "e2e-admin-password")
    expectStatus 303 resp
    setCookie <- requireHeader "Set-Cookie" resp
    pure (cookieToken setCookie)

loginPost :: BS.ByteString -> BS.ByteString -> Session SResponse
loginPost username password =
    formPost "/admin/ui/login" ("username=" <> username <> "&password=" <> password) Nothing

htmlGet :: BS.ByteString -> Maybe BS.ByteString -> Session SResponse
htmlGet path mCookie =
    srequest (SRequest (setPath defaultRequest{requestHeaders = cookieHeaders mCookie} path) BSL.empty)

formPost :: BS.ByteString -> BS.ByteString -> Maybe BS.ByteString -> Session SResponse
formPost path body mCookie = do
    let headers =
            (hContentType, "application/x-www-form-urlencoded")
                : cookieHeaders mCookie
        req =
            setPath
                defaultRequest{requestMethod = "POST", requestHeaders = headers}
                path
    srequest (SRequest req (BSL.fromStrict body))

cookieHeaders :: Maybe BS.ByteString -> [(HeaderName, BS.ByteString)]
cookieHeaders = \case
    Nothing -> []
    Just cookie -> [(hCookie, cookie)]

responseHeader :: HeaderName -> SResponse -> Maybe BS.ByteString
responseHeader name resp = lookup name (simpleHeaders resp)

requireHeader :: HeaderName -> SResponse -> IO BS.ByteString
requireHeader name resp =
    case responseHeader name resp of
        Just value -> pure value
        Nothing -> do
            expectationFailure ("missing response header: " <> show name)
            error "unreachable"

-- First Set-Cookie pair value: "hauth_admin_session=<token>; ..."
cookieToken :: BS.ByteString -> BS.ByteString
cookieToken setCookie =
    BSC.drop 1 (BSC.dropWhile (/= '=') (BSC.takeWhile (/= ';') setCookie))

bodyContains :: SResponse -> BS.ByteString -> Bool
bodyContains resp needle =
    needle `BS.isInfixOf` BSL.toStrict (simpleBody resp)

sessionRows :: TestEnv -> IO [(Text, Text)]
sessionRows env =
    withDatabaseConnection
        (testAppEnv env)
        (`query_` "SELECT token_hash, username FROM auth.admin_ui_sessions ORDER BY created_at")
