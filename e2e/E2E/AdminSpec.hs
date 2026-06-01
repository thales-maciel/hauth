{-# LANGUAGE OverloadedStrings #-}

module E2E.AdminSpec (spec) where

import Control.Exception (bracket_)
import qualified Data.Aeson as Aeson
import qualified Data.Aeson.KeyMap as KeyMap
import qualified Data.Text as T
import qualified Data.Text.Encoding as TE
import Data.UUID (UUID)
import qualified Data.UUID.V4 as UUID4
import Database.PostgreSQL.Simple (Connection, Only (..), execute, query)
import Database.PostgreSQL.Simple.Types (PGArray (..))
import E2E.Helpers (
    TestEnv (..),
    decodeBody,
    expectStatus,
    jsonDelete,
    jsonGet,
    jsonPost,
    jsonPut,
    mintServiceRoleJwt,
    runApp,
 )
import Hauth.Env (withDatabaseConnection)
import Test.Hspec (SpecWith, describe, it, shouldBe)

spec :: SpecWith TestEnv
spec = do
    describe "service-role admin CRUD on /admin/users" $
        it "creates, reads, updates, lists, deletes" \env -> do
            svcJwt <- mintServiceRoleJwt env

            -- Create
            createResp <-
                runApp env $
                    jsonPost
                        "/admin/users"
                        ( Aeson.object
                            [ "email" Aeson..= ("ivan@example.com" :: T.Text)
                            , "password" Aeson..= ("admin generated" :: T.Text)
                            , "email_confirm" Aeson..= True
                            ]
                        )
                        (Just svcJwt)
            expectStatus 200 createResp
            (createObj :: Aeson.Object) <- decodeBody createResp
            userId <- extractString "id" createObj
            KeyMap.lookup "email" createObj `shouldBe` Just (Aeson.String "ivan@example.com")

            -- Get by id
            getResp <-
                runApp env $
                    jsonGet ("/admin/users/" <> TE.encodeUtf8 userId) (Just svcJwt)
            expectStatus 200 getResp

            -- Update metadata
            putResp <-
                runApp env $
                    jsonPut
                        ("/admin/users/" <> TE.encodeUtf8 userId)
                        ( Aeson.object
                            ["data" Aeson..= Aeson.object ["role_label" Aeson..= ("vip" :: T.Text)]]
                        )
                        (Just svcJwt)
            expectStatus 200 putResp

            -- List
            listResp <- runApp env $ jsonGet "/admin/users" (Just svcJwt)
            expectStatus 200 listResp
            (listObj :: Aeson.Object) <- decodeBody listResp
            KeyMap.member "users" listObj `shouldBe` True

            -- List identities (empty)
            idsResp <-
                runApp env $
                    jsonGet ("/admin/users/" <> TE.encodeUtf8 userId <> "/identities") (Just svcJwt)
            expectStatus 200 idsResp

            -- Delete
            delResp <-
                runApp env $
                    jsonDelete ("/admin/users/" <> TE.encodeUtf8 userId) (Just svcJwt)
            expectStatus 200 delResp

    describe "/admin/users without service-role JWT" $
        it "rejects with 401" \env -> do
            resp <- runApp env $ jsonGet "/admin/users" Nothing
            expectStatus 401 resp

    describe "admin create/update/delete emit webhook deliveries" $
        it "wildcard subscription receives user.admin_created, user.admin_updated, user.deleted" \env ->
            withDatabaseConnection (testAppEnv env) \conn -> do
                withWildcardSubscription conn \_ -> do
                    svcJwt <- mintServiceRoleJwt env

                    createResp <-
                        runApp env $
                            jsonPost
                                "/admin/users"
                                ( Aeson.object
                                    [ "email" Aeson..= ("webhook-admin@example.com" :: T.Text)
                                    , "password" Aeson..= ("adminpass1" :: T.Text)
                                    , "email_confirm" Aeson..= True
                                    ]
                                )
                                (Just svcJwt)
                    expectStatus 200 createResp
                    (createObj :: Aeson.Object) <- decodeBody createResp
                    userId <- extractString "id" createObj
                    nCreated <- countDeliveriesByType conn "user.admin_created"
                    nCreated `shouldBe` (1 :: Int)

                    _ <-
                        runApp env $
                            jsonPut
                                ("/admin/users/" <> TE.encodeUtf8 userId)
                                ( Aeson.object
                                    ["data" Aeson..= Aeson.object ["x" Aeson..= ("y" :: T.Text)]]
                                )
                                (Just svcJwt)
                    nUpdated <- countDeliveriesByType conn "user.admin_updated"
                    nUpdated `shouldBe` (1 :: Int)

                    _ <-
                        runApp env $
                            jsonDelete ("/admin/users/" <> TE.encodeUtf8 userId) (Just svcJwt)
                    nDeleted <- countDeliveriesByType conn "user.deleted"
                    nDeleted `shouldBe` (1 :: Int)

    describe "POST /admin/invite" $
        it "returns 200 and creates the user" \env -> do
            svcJwt <- mintServiceRoleJwt env
            resp <-
                runApp env $
                    jsonPost
                        "/admin/invite"
                        (Aeson.object ["email" Aeson..= ("jenny@example.com" :: T.Text)])
                        (Just svcJwt)
            expectStatus 200 resp
            (obj :: Aeson.Object) <- decodeBody resp
            KeyMap.member "message" obj `shouldBe` True

extractString :: Aeson.Key -> Aeson.Object -> IO T.Text
extractString k obj = case KeyMap.lookup k obj of
    Just (Aeson.String t) -> pure t
    other -> error ("expected string at " <> show k <> "; got " <> show other)

-- Insert a wildcard subscription, run action, then delete it (and its deliveries).
withWildcardSubscription :: Connection -> (UUID -> IO a) -> IO a
withWildcardSubscription conn action = do
    subId <- UUID4.nextRandom
    bracket_
        ( execute
            conn
            "INSERT INTO auth.webhook_subscriptions (id, url, secret, events) \
            \VALUES (?, ?, ?, ?)"
            ( subId
            , "https://example.com/webhook" :: String
            , "test-secret" :: String
            , PGArray ([] :: [String])
            )
        )
        ( execute
            conn
            "DELETE FROM auth.webhook_subscriptions WHERE id = ?"
            (Only subId)
        )
        (action subId)

countDeliveriesByType :: Connection -> T.Text -> IO Int
countDeliveriesByType conn evtType = do
    rows <- query conn "SELECT COUNT(*) FROM auth.webhook_deliveries WHERE event_type = ?" (Only evtType)
    pure $ case rows of
        [Only n] -> n
        _ -> 0
