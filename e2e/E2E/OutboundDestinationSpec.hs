{-# LANGUAGE OverloadedStrings #-}

{- | End-to-end tests confirming that /admin/hooks and /admin/webhooks reject
blocked destinations at the API layer.

These tests exercise the full stack: HTTP request → handler validation →
'Hauth.Security.OutboundDestination.checkDestination' with the real DNS
resolver.  Because the blocked-IP and blocked-hostname checks in
'checkDestination' use 'defaultResolver', IP-literal URLs (e.g.
@http://127.0.0.1/...@) are classified directly without a DNS lookup; the
DNS step only matters for hostnames.

Error shape: both endpoints return @{\"error\":\"invalid_url\", ...}@
with HTTP 400 for all blocked destinations.
-}
module E2E.OutboundDestinationSpec (spec) where

import qualified Data.Aeson as Aeson
import qualified Data.Aeson.KeyMap as KeyMap
import qualified Data.Text as T
import E2E.Helpers (
    TestEnv,
    decodeBody,
    expectStatus,
    jsonPost,
    mintServiceRoleJwt,
    runApp,
 )
import Test.Hspec (SpecWith, describe, it, shouldBe)

spec :: SpecWith TestEnv
spec = do
    describe "POST /admin/hooks — blocked destinations" $ do
        it "rejects http://127.0.0.1 (loopback)" \env -> do
            svcJwt <- mintServiceRoleJwt env
            resp <-
                runApp env $
                    jsonPost
                        "/admin/hooks"
                        ( Aeson.object
                            [ "hook_point" Aeson..= ("before-user-created" :: T.Text)
                            , "url" Aeson..= ("http://127.0.0.1/hook" :: T.Text)
                            ]
                        )
                        (Just svcJwt)
            expectStatus 400 resp
            (obj :: Aeson.Object) <- decodeBody resp
            KeyMap.lookup "error" obj `shouldBe` Just (Aeson.String "invalid_url")

        it "rejects http://169.254.169.254 (cloud metadata)" \env -> do
            svcJwt <- mintServiceRoleJwt env
            resp <-
                runApp env $
                    jsonPost
                        "/admin/hooks"
                        ( Aeson.object
                            [ "hook_point" Aeson..= ("before-user-created" :: T.Text)
                            , "url" Aeson..= ("http://169.254.169.254/latest/meta-data/" :: T.Text)
                            ]
                        )
                        (Just svcJwt)
            expectStatus 400 resp
            (obj :: Aeson.Object) <- decodeBody resp
            KeyMap.lookup "error" obj `shouldBe` Just (Aeson.String "invalid_url")

        it "rejects http://10.0.0.1 (RFC1918)" \env -> do
            svcJwt <- mintServiceRoleJwt env
            resp <-
                runApp env $
                    jsonPost
                        "/admin/hooks"
                        ( Aeson.object
                            [ "hook_point" Aeson..= ("before-user-created" :: T.Text)
                            , "url" Aeson..= ("http://10.0.0.1/hook" :: T.Text)
                            ]
                        )
                        (Just svcJwt)
            expectStatus 400 resp
            (obj :: Aeson.Object) <- decodeBody resp
            KeyMap.lookup "error" obj `shouldBe` Just (Aeson.String "invalid_url")

        it "rejects http://192.168.0.1 (RFC1918)" \env -> do
            svcJwt <- mintServiceRoleJwt env
            resp <-
                runApp env $
                    jsonPost
                        "/admin/hooks"
                        ( Aeson.object
                            [ "hook_point" Aeson..= ("before-user-created" :: T.Text)
                            , "url" Aeson..= ("http://192.168.0.1/hook" :: T.Text)
                            ]
                        )
                        (Just svcJwt)
            expectStatus 400 resp
            (obj :: Aeson.Object) <- decodeBody resp
            KeyMap.lookup "error" obj `shouldBe` Just (Aeson.String "invalid_url")

    describe "POST /admin/webhooks — blocked destinations" $ do
        it "rejects http://127.0.0.1 (loopback)" \env -> do
            svcJwt <- mintServiceRoleJwt env
            resp <-
                runApp env $
                    jsonPost
                        "/admin/webhooks"
                        ( Aeson.object
                            [ "url" Aeson..= ("http://127.0.0.1/webhook" :: T.Text)
                            ]
                        )
                        (Just svcJwt)
            expectStatus 400 resp
            (obj :: Aeson.Object) <- decodeBody resp
            KeyMap.lookup "error" obj `shouldBe` Just (Aeson.String "invalid_url")

        it "rejects http://169.254.169.254 (cloud metadata)" \env -> do
            svcJwt <- mintServiceRoleJwt env
            resp <-
                runApp env $
                    jsonPost
                        "/admin/webhooks"
                        ( Aeson.object
                            [ "url" Aeson..= ("http://169.254.169.254/latest/meta-data/" :: T.Text)
                            ]
                        )
                        (Just svcJwt)
            expectStatus 400 resp
            (obj :: Aeson.Object) <- decodeBody resp
            KeyMap.lookup "error" obj `shouldBe` Just (Aeson.String "invalid_url")

        it "rejects http://10.0.0.1 (RFC1918)" \env -> do
            svcJwt <- mintServiceRoleJwt env
            resp <-
                runApp env $
                    jsonPost
                        "/admin/webhooks"
                        ( Aeson.object
                            [ "url" Aeson..= ("http://10.0.0.1/webhook" :: T.Text)
                            ]
                        )
                        (Just svcJwt)
            expectStatus 400 resp
            (obj :: Aeson.Object) <- decodeBody resp
            KeyMap.lookup "error" obj `shouldBe` Just (Aeson.String "invalid_url")

        it "rejects http://192.168.0.1 (RFC1918)" \env -> do
            svcJwt <- mintServiceRoleJwt env
            resp <-
                runApp env $
                    jsonPost
                        "/admin/webhooks"
                        ( Aeson.object
                            [ "url" Aeson..= ("http://192.168.0.1/webhook" :: T.Text)
                            ]
                        )
                        (Just svcJwt)
            expectStatus 400 resp
            (obj :: Aeson.Object) <- decodeBody resp
            KeyMap.lookup "error" obj `shouldBe` Just (Aeson.String "invalid_url")
