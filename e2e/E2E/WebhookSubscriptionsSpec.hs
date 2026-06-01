{-# LANGUAGE OverloadedStrings #-}

module E2E.WebhookSubscriptionsSpec (spec) where

import qualified Data.Aeson as Aeson
import qualified Data.Aeson.KeyMap as KeyMap
import qualified Data.Text as T
import qualified Data.Text.Encoding as TE
import E2E.Helpers (
    TestEnv,
    decodeBody,
    expectStatus,
    jsonDelete,
    jsonGet,
    jsonPost,
    jsonPut,
    mintServiceRoleJwt,
    mintSessionJwt,
    runApp,
 )
import Test.Hspec (SpecWith, describe, it, shouldBe, shouldNotBe)

spec :: SpecWith TestEnv
spec = do
    describe "POST /admin/webhooks" $ do
        it "returns 401 without bearer" \env -> do
            resp <-
                runApp env $
                    jsonPost
                        "/admin/webhooks"
                        (Aeson.object ["url" Aeson..= ("https://example.com/hook" :: T.Text)])
                        Nothing
            expectStatus 401 resp

        it "returns 401 with non-service-role JWT" \env -> do
            tok <- mintSessionJwt env "00000000-0000-0000-0000-000000000099" "00000000-0000-0000-0000-000000000098"
            resp <-
                runApp env $
                    jsonPost
                        "/admin/webhooks"
                        (Aeson.object ["url" Aeson..= ("https://example.com/hook" :: T.Text)])
                        (Just tok)
            expectStatus 401 resp

        it "returns 400 for invalid URL" \env -> do
            svcJwt <- mintServiceRoleJwt env
            resp <-
                runApp env $
                    jsonPost
                        "/admin/webhooks"
                        (Aeson.object ["url" Aeson..= ("not-a-url" :: T.Text)])
                        (Just svcJwt)
            expectStatus 400 resp

        it "creates subscription with generated secret on minimal body" \env -> do
            svcJwt <- mintServiceRoleJwt env
            resp <-
                runApp env $
                    jsonPost
                        "/admin/webhooks"
                        (Aeson.object ["url" Aeson..= ("https://example.com/hook1" :: T.Text)])
                        (Just svcJwt)
            expectStatus 200 resp
            (obj :: Aeson.Object) <- decodeBody resp
            KeyMap.member "id" obj `shouldBe` True
            KeyMap.member "secret" obj `shouldBe` True
            case KeyMap.lookup "secret" obj of
                Just (Aeson.String s) -> T.null s `shouldBe` False
                _ -> fail "expected secret string"

        it "echoes back explicit secret" \env -> do
            svcJwt <- mintServiceRoleJwt env
            resp <-
                runApp env $
                    jsonPost
                        "/admin/webhooks"
                        ( Aeson.object
                            [ "url" Aeson..= ("https://example.com/hook2" :: T.Text)
                            , "secret" Aeson..= ("mysecret" :: T.Text)
                            ]
                        )
                        (Just svcJwt)
            expectStatus 200 resp
            (obj :: Aeson.Object) <- decodeBody resp
            KeyMap.lookup "secret" obj `shouldBe` Just (Aeson.String "mysecret")

        it "returns 409 on duplicate URL" \env -> do
            svcJwt <- mintServiceRoleJwt env
            let body = Aeson.object ["url" Aeson..= ("https://example.com/hook-dup" :: T.Text)]
            resp1 <- runApp env $ jsonPost "/admin/webhooks" body (Just svcJwt)
            expectStatus 200 resp1
            resp2 <- runApp env $ jsonPost "/admin/webhooks" body (Just svcJwt)
            expectStatus 409 resp2

    describe "GET /admin/webhooks" $ do
        it "returns 401 without bearer" \env -> do
            resp <- runApp env $ jsonGet "/admin/webhooks" Nothing
            expectStatus 401 resp

        it "returns list including created subscription" \env -> do
            svcJwt <- mintServiceRoleJwt env
            _ <-
                runApp env $
                    jsonPost
                        "/admin/webhooks"
                        (Aeson.object ["url" Aeson..= ("https://example.com/list-test" :: T.Text)])
                        (Just svcJwt)
            listResp <- runApp env $ jsonGet "/admin/webhooks" (Just svcJwt)
            expectStatus 200 listResp
            (obj :: Aeson.Object) <- decodeBody listResp
            KeyMap.member "webhooks" obj `shouldBe` True

    describe "GET /admin/webhooks/:id" $ do
        it "returns the subscription row" \env -> do
            svcJwt <- mintServiceRoleJwt env
            createResp <-
                runApp env $
                    jsonPost
                        "/admin/webhooks"
                        (Aeson.object ["url" Aeson..= ("https://example.com/get-by-id" :: T.Text)])
                        (Just svcJwt)
            expectStatus 200 createResp
            (created :: Aeson.Object) <- decodeBody createResp
            subId <- extractString "id" created
            getResp <- runApp env $ jsonGet ("/admin/webhooks/" <> TE.encodeUtf8 subId) (Just svcJwt)
            expectStatus 200 getResp
            (got :: Aeson.Object) <- decodeBody getResp
            KeyMap.lookup "id" got `shouldBe` Just (Aeson.String subId)

        it "returns 404 for unknown id" \env -> do
            svcJwt <- mintServiceRoleJwt env
            resp <- runApp env $ jsonGet "/admin/webhooks/00000000-0000-0000-0000-000000000000" (Just svcJwt)
            expectStatus 404 resp

    describe "PUT /admin/webhooks/:id" $ do
        it "updates fields and reflects in subsequent GET" \env -> do
            svcJwt <- mintServiceRoleJwt env
            createResp <-
                runApp env $
                    jsonPost
                        "/admin/webhooks"
                        ( Aeson.object
                            [ "url" Aeson..= ("https://example.com/put-test" :: T.Text)
                            , "secret" Aeson..= ("oldsecret" :: T.Text)
                            ]
                        )
                        (Just svcJwt)
            expectStatus 200 createResp
            (created :: Aeson.Object) <- decodeBody createResp
            subId <- extractString "id" created
            putResp <-
                runApp env $
                    jsonPut
                        ("/admin/webhooks/" <> TE.encodeUtf8 subId)
                        ( Aeson.object
                            [ "url" Aeson..= ("https://example.com/put-test-updated" :: T.Text)
                            , "secret" Aeson..= ("newsecret" :: T.Text)
                            ]
                        )
                        (Just svcJwt)
            expectStatus 200 putResp
            (updated :: Aeson.Object) <- decodeBody putResp
            KeyMap.lookup "url" updated `shouldBe` Just (Aeson.String "https://example.com/put-test-updated")
            KeyMap.lookup "secret" updated `shouldBe` Just (Aeson.String "newsecret")
            -- Verify via GET
            getResp <- runApp env $ jsonGet ("/admin/webhooks/" <> TE.encodeUtf8 subId) (Just svcJwt)
            expectStatus 200 getResp
            (got :: Aeson.Object) <- decodeBody getResp
            KeyMap.lookup "url" got `shouldBe` Just (Aeson.String "https://example.com/put-test-updated")

        it "returns 404 for unknown id" \env -> do
            svcJwt <- mintServiceRoleJwt env
            resp <-
                runApp env $
                    jsonPut
                        "/admin/webhooks/00000000-0000-0000-0000-000000000000"
                        (Aeson.object ["url" Aeson..= ("https://example.com/x" :: T.Text)])
                        (Just svcJwt)
            expectStatus 404 resp

    describe "DELETE /admin/webhooks/:id" $ do
        it "returns 204 and subsequent GET returns 404" \env -> do
            svcJwt <- mintServiceRoleJwt env
            createResp <-
                runApp env $
                    jsonPost
                        "/admin/webhooks"
                        (Aeson.object ["url" Aeson..= ("https://example.com/delete-test" :: T.Text)])
                        (Just svcJwt)
            expectStatus 200 createResp
            (created :: Aeson.Object) <- decodeBody createResp
            subId <- extractString "id" created
            delResp <- runApp env $ jsonDelete ("/admin/webhooks/" <> TE.encodeUtf8 subId) (Just svcJwt)
            expectStatus 204 delResp
            getResp <- runApp env $ jsonGet ("/admin/webhooks/" <> TE.encodeUtf8 subId) (Just svcJwt)
            expectStatus 404 getResp

        it "returns 404 for unknown id" \env -> do
            svcJwt <- mintServiceRoleJwt env
            resp <- runApp env $ jsonDelete "/admin/webhooks/00000000-0000-0000-0000-000000000000" (Just svcJwt)
            expectStatus 404 resp

    describe "events field" $ do
        it "defaults to empty list when not provided" \env -> do
            svcJwt <- mintServiceRoleJwt env
            resp <-
                runApp env $
                    jsonPost
                        "/admin/webhooks"
                        (Aeson.object ["url" Aeson..= ("https://example.com/events-test" :: T.Text)])
                        (Just svcJwt)
            expectStatus 200 resp
            (obj :: Aeson.Object) <- decodeBody resp
            KeyMap.lookup "events" obj `shouldBe` Just (Aeson.Array mempty)

        it "stores and returns provided events" \env -> do
            svcJwt <- mintServiceRoleJwt env
            resp <-
                runApp env $
                    jsonPost
                        "/admin/webhooks"
                        ( Aeson.object
                            [ "url" Aeson..= ("https://example.com/events-test2" :: T.Text)
                            , "events" Aeson..= (["user.signed_up", "user.deleted"] :: [T.Text])
                            ]
                        )
                        (Just svcJwt)
            expectStatus 200 resp
            (obj :: Aeson.Object) <- decodeBody resp
            case KeyMap.lookup "events" obj of
                Just (Aeson.Array arr) -> length arr `shouldNotBe` 0
                _ -> fail "expected events array"

extractString :: Aeson.Key -> Aeson.Object -> IO T.Text
extractString k obj = case KeyMap.lookup k obj of
    Just (Aeson.String t) -> pure t
    other -> error ("expected string at " <> show k <> "; got " <> show other)
