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

        it "echoes back explicit secret on create (one-time reveal)" \env -> do
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
            -- Create response reveals the real secret exactly once.
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
        it "updates URL and reflects in subsequent GET (secret is not changed)" \env -> do
            svcJwt <- mintServiceRoleJwt env
            createResp <-
                runApp env $
                    jsonPost
                        "/admin/webhooks"
                        ( Aeson.object
                            [ "url" Aeson..= ("https://example.com/put-test" :: T.Text)
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
                            ]
                        )
                        (Just svcJwt)
            expectStatus 200 putResp
            (updated :: Aeson.Object) <- decodeBody putResp
            KeyMap.lookup "url" updated `shouldBe` Just (Aeson.String "https://example.com/put-test-updated")
            -- Secret is always redacted in PUT/GET responses.
            KeyMap.lookup "secret" updated `shouldBe` Just (Aeson.String "***redacted***")
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

    describe "Secret write-only behaviour" $ do
        it "GET /admin/webhooks/:id redacts the secret" \env -> do
            svcJwt <- mintServiceRoleJwt env
            createResp <-
                runApp env $
                    jsonPost
                        "/admin/webhooks"
                        ( Aeson.object
                            [ "url" Aeson..= ("https://example.com/wh-redact-test" :: T.Text)
                            , "secret" Aeson..= ("plaintextsecret" :: T.Text)
                            ]
                        )
                        (Just svcJwt)
            expectStatus 200 createResp
            (created :: Aeson.Object) <- decodeBody createResp
            -- Create response shows real secret.
            KeyMap.lookup "secret" created `shouldBe` Just (Aeson.String "plaintextsecret")
            subId <- extractString "id" created
            getResp <- runApp env $ jsonGet ("/admin/webhooks/" <> TE.encodeUtf8 subId) (Just svcJwt)
            expectStatus 200 getResp
            (got :: Aeson.Object) <- decodeBody getResp
            -- GET response must redact the secret.
            KeyMap.lookup "secret" got `shouldBe` Just (Aeson.String "***redacted***")

        it "GET /admin/webhooks (list) redacts secrets" \env -> do
            svcJwt <- mintServiceRoleJwt env
            _ <-
                runApp env $
                    jsonPost
                        "/admin/webhooks"
                        ( Aeson.object
                            [ "url" Aeson..= ("https://example.com/wh-list-redact" :: T.Text)
                            , "secret" Aeson..= ("mylistsecret" :: T.Text)
                            ]
                        )
                        (Just svcJwt)
            listResp <- runApp env $ jsonGet "/admin/webhooks" (Just svcJwt)
            expectStatus 200 listResp
            (listObj :: Aeson.Object) <- decodeBody listResp
            case KeyMap.lookup "webhooks" listObj of
                Just (Aeson.Array arr) ->
                    mapM_
                        ( \case
                            Aeson.Object wObj ->
                                KeyMap.lookup "secret" wObj
                                    `shouldBe` Just (Aeson.String "***redacted***")
                            _ -> fail "expected subscription object in array"
                        )
                        arr
                _ -> fail "expected webhooks array"

        it "PUT /admin/webhooks/:id does not rotate the secret" \env -> do
            svcJwt <- mintServiceRoleJwt env
            createResp <-
                runApp env $
                    jsonPost
                        "/admin/webhooks"
                        ( Aeson.object
                            [ "url" Aeson..= ("https://example.com/wh-put-secret-test" :: T.Text)
                            , "secret" Aeson..= ("originalSecret" :: T.Text)
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
                            [ "url" Aeson..= ("https://example.com/wh-put-secret-updated" :: T.Text)
                            ]
                        )
                        (Just svcJwt)
            expectStatus 200 putResp
            (putObj :: Aeson.Object) <- decodeBody putResp
            -- The PUT response still redacts the secret.
            KeyMap.lookup "secret" putObj `shouldBe` Just (Aeson.String "***redacted***")

    describe "POST /admin/webhooks/:id/rotate-secret" $ do
        it "returns 404 for unknown subscription" \env -> do
            svcJwt <- mintServiceRoleJwt env
            resp <-
                runApp env $
                    jsonPost
                        "/admin/webhooks/00000000-0000-0000-0000-000000000000/rotate-secret"
                        (Aeson.object [] :: Aeson.Value)
                        (Just svcJwt)
            expectStatus 404 resp

        it "generates a new server secret when no body secret is provided" \env -> do
            svcJwt <- mintServiceRoleJwt env
            createResp <-
                runApp env $
                    jsonPost
                        "/admin/webhooks"
                        ( Aeson.object
                            [ "url" Aeson..= ("https://example.com/wh-rotate-gen" :: T.Text)
                            , "secret" Aeson..= ("beforeRotate" :: T.Text)
                            ]
                        )
                        (Just svcJwt)
            expectStatus 200 createResp
            (created :: Aeson.Object) <- decodeBody createResp
            subId <- extractString "id" created
            rotateResp <-
                runApp env $
                    jsonPost
                        ("/admin/webhooks/" <> TE.encodeUtf8 subId <> "/rotate-secret")
                        (Aeson.object [] :: Aeson.Value)
                        (Just svcJwt)
            expectStatus 200 rotateResp
            (rotateObj :: Aeson.Object) <- decodeBody rotateResp
            case KeyMap.lookup "secret" rotateObj of
                Just (Aeson.String s) -> do
                    T.length s `shouldBe` 64
                    (s == "beforeRotate") `shouldBe` False
                _ -> fail "expected secret string in rotate response"

        it "uses caller-supplied secret when provided" \env -> do
            svcJwt <- mintServiceRoleJwt env
            createResp <-
                runApp env $
                    jsonPost
                        "/admin/webhooks"
                        ( Aeson.object
                            [ "url" Aeson..= ("https://example.com/wh-rotate-explicit" :: T.Text)
                            ]
                        )
                        (Just svcJwt)
            expectStatus 200 createResp
            (created :: Aeson.Object) <- decodeBody createResp
            subId <- extractString "id" created
            rotateResp <-
                runApp env $
                    jsonPost
                        ("/admin/webhooks/" <> TE.encodeUtf8 subId <> "/rotate-secret")
                        (Aeson.object ["secret" Aeson..= ("explicit-new-secret" :: T.Text)])
                        (Just svcJwt)
            expectStatus 200 rotateResp
            (rotateObj :: Aeson.Object) <- decodeBody rotateResp
            KeyMap.lookup "secret" rotateObj
                `shouldBe` Just (Aeson.String "explicit-new-secret")

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
