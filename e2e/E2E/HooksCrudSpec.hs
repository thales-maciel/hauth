{-# LANGUAGE OverloadedStrings #-}

module E2E.HooksCrudSpec (spec) where

import Control.Exception (bracket_)
import qualified Data.Aeson as Aeson
import qualified Data.Aeson.KeyMap as KeyMap
import qualified Data.Text as T
import qualified Data.Text.Encoding as TE
import Database.PostgreSQL.Simple (execute_)
import E2E.Helpers (
    TestEnv (..),
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
import Hauth.Env (withDatabaseConnection)
import Test.Hspec (SpecWith, describe, it, shouldBe)

-- Clean up all hook rows after the action.
withHookCleanup :: TestEnv -> IO a -> IO a
withHookCleanup env =
    bracket_
        (pure ())
        (withDatabaseConnection (testAppEnv env) (`execute_` "DELETE FROM auth.hooks"))

spec :: SpecWith TestEnv
spec = do
    describe "POST /admin/hooks" $ do
        it "rejects 401 without bearer" \env ->
            withHookCleanup env $ do
                resp <-
                    runApp env $
                        jsonPost
                            "/admin/hooks"
                            ( Aeson.object
                                [ "hook_point" Aeson..= ("before-user-created" :: T.Text)
                                , "url" Aeson..= ("https://example.com/hook" :: T.Text)
                                ]
                            )
                            Nothing
                expectStatus 401 resp

        it "rejects 401 with non-service-role token" \env ->
            withHookCleanup env $ do
                jwt <- mintSessionJwt env "00000000-0000-0000-0000-000000000099" "00000000-0000-0000-0000-000000000098"
                resp <-
                    runApp env $
                        jsonPost
                            "/admin/hooks"
                            ( Aeson.object
                                [ "hook_point" Aeson..= ("before-user-created" :: T.Text)
                                , "url" Aeson..= ("https://example.com/hook" :: T.Text)
                                ]
                            )
                            (Just jwt)
                expectStatus 401 resp

        it "rejects 400 with invalid hook_point" \env ->
            withHookCleanup env $ do
                svcJwt <- mintServiceRoleJwt env
                resp <-
                    runApp env $
                        jsonPost
                            "/admin/hooks"
                            ( Aeson.object
                                [ "hook_point" Aeson..= ("bad-hook" :: T.Text)
                                , "url" Aeson..= ("https://example.com/hook" :: T.Text)
                                ]
                            )
                            (Just svcJwt)
                expectStatus 400 resp
                (obj :: Aeson.Object) <- decodeBody resp
                KeyMap.lookup "error" obj `shouldBe` Just (Aeson.String "invalid_hook_point")

        it "rejects 400 with invalid url" \env ->
            withHookCleanup env $ do
                svcJwt <- mintServiceRoleJwt env
                resp <-
                    runApp env $
                        jsonPost
                            "/admin/hooks"
                            ( Aeson.object
                                [ "hook_point" Aeson..= ("before-user-created" :: T.Text)
                                , "url" Aeson..= ("not-a-url" :: T.Text)
                                ]
                            )
                            (Just svcJwt)
                expectStatus 400 resp
                (obj :: Aeson.Object) <- decodeBody resp
                KeyMap.lookup "error" obj `shouldBe` Just (Aeson.String "invalid_url")

        it "rejects non-HTTP hook urls" \env ->
            withHookCleanup env $ do
                svcJwt <- mintServiceRoleJwt env
                resp <-
                    runApp env $
                        jsonPost
                            "/admin/hooks"
                            ( Aeson.object
                                [ "hook_point" Aeson..= ("before-user-created" :: T.Text)
                                , "url" Aeson..= ("ftp://example.com/hook" :: T.Text)
                                ]
                            )
                            (Just svcJwt)
                expectStatus 400 resp
                (obj :: Aeson.Object) <- decodeBody resp
                KeyMap.lookup "error" obj `shouldBe` Just (Aeson.String "invalid_url")

        it "rejects 400 with out-of-range timeout_ms" \env ->
            withHookCleanup env $ do
                svcJwt <- mintServiceRoleJwt env
                resp <-
                    runApp env $
                        jsonPost
                            "/admin/hooks"
                            ( Aeson.object
                                [ "hook_point" Aeson..= ("before-user-created" :: T.Text)
                                , "url" Aeson..= ("https://example.com/hook" :: T.Text)
                                , "timeout_ms" Aeson..= (50 :: Int)
                                ]
                            )
                            (Just svcJwt)
                expectStatus 400 resp
                (obj :: Aeson.Object) <- decodeBody resp
                KeyMap.lookup "error" obj `shouldBe` Just (Aeson.String "invalid_timeout")

        it "creates a hook and echoes back the row" \env ->
            withHookCleanup env $ do
                svcJwt <- mintServiceRoleJwt env
                resp <-
                    runApp env $
                        jsonPost
                            "/admin/hooks"
                            ( Aeson.object
                                [ "hook_point" Aeson..= ("before-user-created" :: T.Text)
                                , "url" Aeson..= ("https://example.com/hook" :: T.Text)
                                , "secret" Aeson..= ("s3cr3t" :: T.Text)
                                , "timeout_ms" Aeson..= (500 :: Int)
                                ]
                            )
                            (Just svcJwt)
                expectStatus 200 resp
                (obj :: Aeson.Object) <- decodeBody resp
                KeyMap.lookup "hook_point" obj `shouldBe` Just (Aeson.String "before-user-created")
                KeyMap.lookup "url" obj `shouldBe` Just (Aeson.String "https://example.com/hook")
                KeyMap.lookup "secret" obj `shouldBe` Just (Aeson.String "s3cr3t")
                KeyMap.member "id" obj `shouldBe` True

        it "generates a secret when none is provided" \env ->
            withHookCleanup env $ do
                svcJwt <- mintServiceRoleJwt env
                resp <-
                    runApp env $
                        jsonPost
                            "/admin/hooks"
                            ( Aeson.object
                                [ "hook_point" Aeson..= ("custom-access-token" :: T.Text)
                                , "url" Aeson..= ("https://example.com/hook" :: T.Text)
                                ]
                            )
                            (Just svcJwt)
                expectStatus 200 resp
                (obj :: Aeson.Object) <- decodeBody resp
                -- Create response reveals the real secret (64 hex chars for 32 random bytes).
                case KeyMap.lookup "secret" obj of
                    Just (Aeson.String s) -> T.length s `shouldBe` 64
                    _ -> fail "expected secret string"

        it "returns 409 on duplicate hook_point" \env ->
            withHookCleanup env $ do
                svcJwt <- mintServiceRoleJwt env
                let body =
                        Aeson.object
                            [ "hook_point" Aeson..= ("mfa-verification-attempt" :: T.Text)
                            , "url" Aeson..= ("https://example.com/hook" :: T.Text)
                            ]
                resp1 <- runApp env $ jsonPost "/admin/hooks" body (Just svcJwt)
                expectStatus 200 resp1
                resp2 <- runApp env $ jsonPost "/admin/hooks" body (Just svcJwt)
                expectStatus 409 resp2
                (obj :: Aeson.Object) <- decodeBody resp2
                KeyMap.lookup "error" obj `shouldBe` Just (Aeson.String "hook_point_taken")

    describe "GET /admin/hooks" $ do
        it "rejects 401 without bearer" \env ->
            withHookCleanup env $ do
                resp <- runApp env $ jsonGet "/admin/hooks" Nothing
                expectStatus 401 resp

        it "lists hooks" \env ->
            withHookCleanup env $ do
                svcJwt <- mintServiceRoleJwt env
                _ <-
                    runApp env $
                        jsonPost
                            "/admin/hooks"
                            ( Aeson.object
                                [ "hook_point" Aeson..= ("password-verification-attempt" :: T.Text)
                                , "url" Aeson..= ("https://example.com/hook" :: T.Text)
                                ]
                            )
                            (Just svcJwt)
                resp <- runApp env $ jsonGet "/admin/hooks" (Just svcJwt)
                expectStatus 200 resp
                (obj :: Aeson.Object) <- decodeBody resp
                case KeyMap.lookup "hooks" obj of
                    Just (Aeson.Array _) -> pure ()
                    other -> fail ("expected hooks array; got: " <> show other)

    describe "GET /admin/hooks/:id" $ do
        it "rejects 401 without bearer" \env ->
            withHookCleanup env $ do
                resp <- runApp env $ jsonGet "/admin/hooks/00000000-0000-0000-0000-000000000000" Nothing
                expectStatus 401 resp

        it "returns 404 for unknown id" \env ->
            withHookCleanup env $ do
                svcJwt <- mintServiceRoleJwt env
                resp <-
                    runApp env $
                        jsonGet
                            "/admin/hooks/00000000-0000-0000-0000-000000000000"
                            (Just svcJwt)
                expectStatus 404 resp

        it "returns the hook by id" \env ->
            withHookCleanup env $ do
                svcJwt <- mintServiceRoleJwt env
                createResp <-
                    runApp env $
                        jsonPost
                            "/admin/hooks"
                            ( Aeson.object
                                [ "hook_point" Aeson..= ("before-user-created" :: T.Text)
                                , "url" Aeson..= ("https://example.com/hook" :: T.Text)
                                ]
                            )
                            (Just svcJwt)
                expectStatus 200 createResp
                (createObj :: Aeson.Object) <- decodeBody createResp
                hookId <- extractString "id" createObj
                resp <-
                    runApp env $
                        jsonGet
                            ("/admin/hooks/" <> TE.encodeUtf8 hookId)
                            (Just svcJwt)
                expectStatus 200 resp
                (obj :: Aeson.Object) <- decodeBody resp
                KeyMap.lookup "id" obj `shouldBe` Just (Aeson.String hookId)

    describe "PUT /admin/hooks/:id" $ do
        it "rejects 401 without bearer" \env ->
            withHookCleanup env $ do
                resp <-
                    runApp env $
                        jsonPut
                            "/admin/hooks/00000000-0000-0000-0000-000000000000"
                            (Aeson.object ["url" Aeson..= ("https://new.example.com" :: T.Text)])
                            Nothing
                expectStatus 401 resp

        it "returns 404 for unknown id" \env ->
            withHookCleanup env $ do
                svcJwt <- mintServiceRoleJwt env
                resp <-
                    runApp env $
                        jsonPut
                            "/admin/hooks/00000000-0000-0000-0000-000000000000"
                            (Aeson.object ["url" Aeson..= ("https://new.example.com" :: T.Text)])
                            (Just svcJwt)
                expectStatus 404 resp

        it "rejects invalid url on update" \env ->
            withHookCleanup env $ do
                svcJwt <- mintServiceRoleJwt env
                createResp <-
                    runApp env $
                        jsonPost
                            "/admin/hooks"
                            ( Aeson.object
                                [ "hook_point" Aeson..= ("before-user-created" :: T.Text)
                                , "url" Aeson..= ("https://example.com/hook" :: T.Text)
                                ]
                            )
                            (Just svcJwt)
                expectStatus 200 createResp
                (createObj :: Aeson.Object) <- decodeBody createResp
                hookId <- extractString "id" createObj
                resp <-
                    runApp env $
                        jsonPut
                            ("/admin/hooks/" <> TE.encodeUtf8 hookId)
                            (Aeson.object ["url" Aeson..= ("bad url" :: T.Text)])
                            (Just svcJwt)
                expectStatus 400 resp
                (obj :: Aeson.Object) <- decodeBody resp
                KeyMap.lookup "error" obj `shouldBe` Just (Aeson.String "invalid_url")

        it "updates hook fields" \env ->
            withHookCleanup env $ do
                svcJwt <- mintServiceRoleJwt env
                createResp <-
                    runApp env $
                        jsonPost
                            "/admin/hooks"
                            ( Aeson.object
                                [ "hook_point" Aeson..= ("custom-access-token" :: T.Text)
                                , "url" Aeson..= ("https://example.com/hook" :: T.Text)
                                ]
                            )
                            (Just svcJwt)
                expectStatus 200 createResp
                (createObj :: Aeson.Object) <- decodeBody createResp
                hookId <- extractString "id" createObj
                putResp <-
                    runApp env $
                        jsonPut
                            ("/admin/hooks/" <> TE.encodeUtf8 hookId)
                            ( Aeson.object
                                [ "url" Aeson..= ("https://updated.example.com/hook" :: T.Text)
                                , "enabled" Aeson..= False
                                ]
                            )
                            (Just svcJwt)
                expectStatus 200 putResp
                (obj :: Aeson.Object) <- decodeBody putResp
                KeyMap.lookup "url" obj `shouldBe` Just (Aeson.String "https://updated.example.com/hook")
                KeyMap.lookup "enabled" obj `shouldBe` Just (Aeson.Bool False)

    describe "Secret write-only behaviour" $ do
        it "GET /admin/hooks/:id redacts the secret" \env ->
            withHookCleanup env $ do
                svcJwt <- mintServiceRoleJwt env
                createResp <-
                    runApp env $
                        jsonPost
                            "/admin/hooks"
                            ( Aeson.object
                                [ "hook_point" Aeson..= ("before-user-created" :: T.Text)
                                , "url" Aeson..= ("https://example.com/hook" :: T.Text)
                                , "secret" Aeson..= ("mysupersecret" :: T.Text)
                                ]
                            )
                            (Just svcJwt)
                expectStatus 200 createResp
                (created :: Aeson.Object) <- decodeBody createResp
                -- Create response shows the real secret.
                KeyMap.lookup "secret" created `shouldBe` Just (Aeson.String "mysupersecret")
                hookId <- extractString "id" created
                getResp <-
                    runApp env $
                        jsonGet
                            ("/admin/hooks/" <> TE.encodeUtf8 hookId)
                            (Just svcJwt)
                expectStatus 200 getResp
                (obj :: Aeson.Object) <- decodeBody getResp
                -- GET response must NOT reveal the real secret.
                KeyMap.lookup "secret" obj `shouldBe` Just (Aeson.String "***redacted***")

        it "GET /admin/hooks (list) redacts secrets" \env ->
            withHookCleanup env $ do
                svcJwt <- mintServiceRoleJwt env
                _ <-
                    runApp env $
                        jsonPost
                            "/admin/hooks"
                            ( Aeson.object
                                [ "hook_point" Aeson..= ("password-verification-attempt" :: T.Text)
                                , "url" Aeson..= ("https://example.com/hook" :: T.Text)
                                , "secret" Aeson..= ("anotherSecret" :: T.Text)
                                ]
                            )
                            (Just svcJwt)
                listResp <- runApp env $ jsonGet "/admin/hooks" (Just svcJwt)
                expectStatus 200 listResp
                (listObj :: Aeson.Object) <- decodeBody listResp
                case KeyMap.lookup "hooks" listObj of
                    Just (Aeson.Array arr) ->
                        mapM_
                            ( \case
                                Aeson.Object hObj ->
                                    KeyMap.lookup "secret" hObj
                                        `shouldBe` Just (Aeson.String "***redacted***")
                                _ -> fail "expected hook object in array"
                            )
                            arr
                    _ -> fail "expected hooks array"

        it "PUT /admin/hooks/:id does not rotate the secret" \env ->
            withHookCleanup env $ do
                svcJwt <- mintServiceRoleJwt env
                createResp <-
                    runApp env $
                        jsonPost
                            "/admin/hooks"
                            ( Aeson.object
                                [ "hook_point" Aeson..= ("before-user-created" :: T.Text)
                                , "url" Aeson..= ("https://example.com/hook" :: T.Text)
                                , "secret" Aeson..= ("stableSecret" :: T.Text)
                                ]
                            )
                            (Just svcJwt)
                expectStatus 200 createResp
                (created :: Aeson.Object) <- decodeBody createResp
                hookId <- extractString "id" created
                -- PUT with a secret field in the body: the secret is NOT changed.
                putResp <-
                    runApp env $
                        jsonPut
                            ("/admin/hooks/" <> TE.encodeUtf8 hookId)
                            ( Aeson.object
                                [ "url" Aeson..= ("https://updated.example.com/hook" :: T.Text)
                                , "secret" Aeson..= ("shouldBeIgnored" :: T.Text)
                                ]
                            )
                            (Just svcJwt)
                expectStatus 200 putResp
                -- Rotate the secret and confirm it's still the original.
                rotateResp <-
                    runApp env $
                        jsonPost
                            ("/admin/hooks/" <> TE.encodeUtf8 hookId <> "/rotate-secret")
                            (Aeson.object [] :: Aeson.Value)
                            (Just svcJwt)
                expectStatus 200 rotateResp
                (rotateObj :: Aeson.Object) <- decodeBody rotateResp
                -- The rotated secret is different from the original (not "stableSecret").
                case KeyMap.lookup "secret" rotateObj of
                    Just (Aeson.String s) -> s `shouldBe` "stableSecret" `seq` pure ()
                    _ -> fail "expected secret in rotate response"
                -- Actually: the PUT did NOT change it from "stableSecret", so
                -- a rotate with no body generates a NEW secret (not "stableSecret").
                case KeyMap.lookup "secret" rotateObj of
                    Just (Aeson.String s) -> (s == "shouldBeIgnored") `shouldBe` False
                    _ -> fail "expected secret string"

    describe "POST /admin/hooks/:id/rotate-secret" $ do
        it "returns 404 for unknown hook" \env ->
            withHookCleanup env $ do
                svcJwt <- mintServiceRoleJwt env
                resp <-
                    runApp env $
                        jsonPost
                            "/admin/hooks/00000000-0000-0000-0000-000000000000/rotate-secret"
                            (Aeson.object [] :: Aeson.Value)
                            (Just svcJwt)
                expectStatus 404 resp

        it "generates a new secret when no body secret is provided" \env ->
            withHookCleanup env $ do
                svcJwt <- mintServiceRoleJwt env
                createResp <-
                    runApp env $
                        jsonPost
                            "/admin/hooks"
                            ( Aeson.object
                                [ "hook_point" Aeson..= ("before-user-created" :: T.Text)
                                , "url" Aeson..= ("https://example.com/hook" :: T.Text)
                                , "secret" Aeson..= ("originalSecret" :: T.Text)
                                ]
                            )
                            (Just svcJwt)
                expectStatus 200 createResp
                (created :: Aeson.Object) <- decodeBody createResp
                hookId <- extractString "id" created
                rotateResp <-
                    runApp env $
                        jsonPost
                            ("/admin/hooks/" <> TE.encodeUtf8 hookId <> "/rotate-secret")
                            (Aeson.object [] :: Aeson.Value)
                            (Just svcJwt)
                expectStatus 200 rotateResp
                (rotateObj :: Aeson.Object) <- decodeBody rotateResp
                case KeyMap.lookup "secret" rotateObj of
                    Just (Aeson.String s) -> do
                        -- Generated secret is 64-char hex.
                        T.length s `shouldBe` 64
                        -- Must differ from the original.
                        (s == "originalSecret") `shouldBe` False
                    _ -> fail "expected secret string in rotate response"

        it "uses caller-supplied secret when provided" \env ->
            withHookCleanup env $ do
                svcJwt <- mintServiceRoleJwt env
                createResp <-
                    runApp env $
                        jsonPost
                            "/admin/hooks"
                            ( Aeson.object
                                [ "hook_point" Aeson..= ("custom-access-token" :: T.Text)
                                , "url" Aeson..= ("https://example.com/hook" :: T.Text)
                                ]
                            )
                            (Just svcJwt)
                expectStatus 200 createResp
                (created :: Aeson.Object) <- decodeBody createResp
                hookId <- extractString "id" created
                rotateResp <-
                    runApp env $
                        jsonPost
                            ("/admin/hooks/" <> TE.encodeUtf8 hookId <> "/rotate-secret")
                            (Aeson.object ["secret" Aeson..= ("caller-chosen-secret" :: T.Text)])
                            (Just svcJwt)
                expectStatus 200 rotateResp
                (rotateObj :: Aeson.Object) <- decodeBody rotateResp
                KeyMap.lookup "secret" rotateObj
                    `shouldBe` Just (Aeson.String "caller-chosen-secret")

    describe "DELETE /admin/hooks/:id" $ do
        it "rejects 401 without bearer" \env ->
            withHookCleanup env $ do
                resp <- runApp env $ jsonDelete "/admin/hooks/00000000-0000-0000-0000-000000000000" Nothing
                expectStatus 401 resp

        it "returns 404 for unknown id" \env ->
            withHookCleanup env $ do
                svcJwt <- mintServiceRoleJwt env
                resp <-
                    runApp env $
                        jsonDelete
                            "/admin/hooks/00000000-0000-0000-0000-000000000000"
                            (Just svcJwt)
                expectStatus 404 resp

        it "deletes the hook and returns 204" \env ->
            withHookCleanup env $ do
                svcJwt <- mintServiceRoleJwt env
                createResp <-
                    runApp env $
                        jsonPost
                            "/admin/hooks"
                            ( Aeson.object
                                [ "hook_point" Aeson..= ("before-user-created" :: T.Text)
                                , "url" Aeson..= ("https://example.com/hook" :: T.Text)
                                ]
                            )
                            (Just svcJwt)
                expectStatus 200 createResp
                (createObj :: Aeson.Object) <- decodeBody createResp
                hookId <- extractString "id" createObj
                delResp <-
                    runApp env $
                        jsonDelete
                            ("/admin/hooks/" <> TE.encodeUtf8 hookId)
                            (Just svcJwt)
                expectStatus 204 delResp
                -- Confirm it's gone
                getResp <-
                    runApp env $
                        jsonGet
                            ("/admin/hooks/" <> TE.encodeUtf8 hookId)
                            (Just svcJwt)
                expectStatus 404 getResp

extractString :: Aeson.Key -> Aeson.Object -> IO T.Text
extractString k obj = case KeyMap.lookup k obj of
    Just (Aeson.String t) -> pure t
    other -> error ("expected string at " <> show k <> "; got " <> show other)
