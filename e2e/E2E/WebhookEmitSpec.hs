{-# LANGUAGE OverloadedStrings #-}

module E2E.WebhookEmitSpec (spec) where

import Control.Exception (bracket_)
import qualified Data.Aeson as Aeson
import qualified Data.Aeson.KeyMap as KeyMap
import qualified Data.Text as T
import Data.UUID (UUID)
import qualified Data.UUID.V4 as UUID4
import Database.PostgreSQL.Simple (Connection, Only (..), execute, query)
import Database.PostgreSQL.Simple.Types (PGArray (..))
import E2E.Helpers (
    TestEnv (..),
    expectStatus,
    jsonPost,
    jsonPut,
    runApp,
 )
import Hauth.Env (withDatabaseConnection)
import Hauth.User (User (..), getUserByEmail)
import Network.Wai.Test (SResponse, simpleBody)
import Test.Hspec (SpecWith, describe, it, shouldBe)

spec :: SpecWith TestEnv
spec = do
    describe "signupHandler emits UserSignedUp" $
        it "writes a delivery row when a wildcard subscription exists" \env ->
            withDatabaseConnection (testAppEnv env) \conn ->
                withWildcardSubscription conn \_ -> do
                    _ <-
                        runApp env $
                            jsonPost
                                "/signup"
                                ( Aeson.object
                                    [ "email" Aeson..= ("webhook-signup@example.com" :: T.Text)
                                    , "password" Aeson..= ("correct horse" :: T.Text)
                                    ]
                                )
                                Nothing
                    n <- countDeliveriesByType conn "user.signed_up"
                    n `shouldBe` (1 :: Int)

    describe "handleSignupVerify emits UserEmailConfirmed" $
        it "writes a delivery row when a wildcard subscription exists" \env -> do
            _ <-
                runApp env $
                    jsonPost
                        "/signup"
                        ( Aeson.object
                            [ "email" Aeson..= ("webhook-verify@example.com" :: T.Text)
                            , "password" Aeson..= ("correct horse" :: T.Text)
                            ]
                        )
                        Nothing
            mUser <- withDatabaseConnection (testAppEnv env) (`getUserByEmail` "webhook-verify@example.com")
            token <- case mUser >>= userConfirmationToken of
                Just t -> pure t
                Nothing -> error "no confirmation_token after signup"
            withDatabaseConnection (testAppEnv env) \conn ->
                withWildcardSubscription conn \_ -> do
                    _ <-
                        runApp env $
                            jsonPost
                                "/verify"
                                ( Aeson.object
                                    [ "type" Aeson..= ("signup" :: T.Text)
                                    , "token" Aeson..= token
                                    ]
                                )
                                Nothing
                    n <- countDeliveriesByType conn "user.email_confirmed"
                    n `shouldBe` (1 :: Int)

    describe "handleRecoveryVerify emits UserRecovered" $
        it "writes a delivery row when a wildcard subscription exists" \env -> do
            _ <-
                runApp env $
                    jsonPost
                        "/signup"
                        ( Aeson.object
                            [ "email" Aeson..= ("webhook-recovery@example.com" :: T.Text)
                            , "password" Aeson..= ("old password" :: T.Text)
                            ]
                        )
                        Nothing
            mUser <- withDatabaseConnection (testAppEnv env) (`getUserByEmail` "webhook-recovery@example.com")
            confirmToken <- case mUser >>= userConfirmationToken of
                Just t -> pure t
                Nothing -> error "no confirmation_token"
            _ <-
                runApp env $
                    jsonPost
                        "/verify"
                        ( Aeson.object
                            [ "type" Aeson..= ("signup" :: T.Text)
                            , "token" Aeson..= confirmToken
                            ]
                        )
                        Nothing
            _ <-
                runApp env $
                    jsonPost
                        "/recover"
                        (Aeson.object ["email" Aeson..= ("webhook-recovery@example.com" :: T.Text)])
                        Nothing
            rows <-
                withDatabaseConnection (testAppEnv env) \conn ->
                    query
                        conn
                        "SELECT recovery_token FROM auth.users WHERE email = ?"
                        (Only ("webhook-recovery@example.com" :: T.Text))
            recoveryToken <- case rows of
                [Only (Just t)] -> pure (t :: T.Text)
                _ -> error "no recovery_token"
            withDatabaseConnection (testAppEnv env) \conn ->
                withWildcardSubscription conn \_ -> do
                    _ <-
                        runApp env $
                            jsonPost
                                "/verify"
                                ( Aeson.object
                                    [ "type" Aeson..= ("recovery" :: T.Text)
                                    , "token" Aeson..= recoveryToken
                                    , "password" Aeson..= ("new password" :: T.Text)
                                    ]
                                )
                                Nothing
                    n <- countDeliveriesByType conn "user.recovered"
                    n `shouldBe` (1 :: Int)

    describe "updateUserHandler emits PasswordChanged" $
        it "writes a delivery row when a wildcard subscription exists" \env -> do
            access <- bootstrapVerifiedUser env "webhook-update@example.com" "old password"
            withDatabaseConnection (testAppEnv env) \conn ->
                withWildcardSubscription conn \_ -> do
                    _ <-
                        runApp env $
                            jsonPut
                                "/user"
                                (Aeson.object ["password" Aeson..= ("new password" :: T.Text)])
                                (Just access)
                    n <- countDeliveriesByType conn "user.password_changed"
                    n `shouldBe` (1 :: Int)

    describe "logoutHandler emits SessionRevoked" $
        it "writes a delivery row when a wildcard subscription exists" \env -> do
            access <- bootstrapVerifiedUser env "webhook-logout@example.com" "correct horse"
            withDatabaseConnection (testAppEnv env) \conn ->
                withWildcardSubscription conn \_ -> do
                    resp <- runApp env $ jsonPost "/logout" (Aeson.object []) (Just access)
                    expectStatus 204 resp
                    n <- countDeliveriesByType conn "session.revoked"
                    n `shouldBe` (1 :: Int)

    describe "refresh token reuse emits SessionRevoked" $
        it "writes a delivery row when a wildcard subscription exists" \env -> do
            _ <-
                runApp env $
                    jsonPost
                        "/signup"
                        ( Aeson.object
                            [ "email" Aeson..= ("webhook-reuse@example.com" :: T.Text)
                            , "password" Aeson..= ("correct horse" :: T.Text)
                            ]
                        )
                        Nothing
            mUser <- withDatabaseConnection (testAppEnv env) (`getUserByEmail` "webhook-reuse@example.com")
            confirmToken <- case mUser >>= userConfirmationToken of
                Just t -> pure t
                Nothing -> error "no confirmation_token"
            verifyResp <-
                runApp env $
                    jsonPost
                        "/verify"
                        ( Aeson.object
                            [ "type" Aeson..= ("signup" :: T.Text)
                            , "token" Aeson..= confirmToken
                            ]
                        )
                        Nothing
            (verifyObj :: Aeson.Object) <- decodeObject verifyResp
            refreshToken <- extractString "refresh_token" verifyObj
            -- Use the refresh token once to rotate it
            rotateResp <-
                runApp env $
                    jsonPost
                        "/token?grant_type=refresh_token"
                        (Aeson.object ["refresh_token" Aeson..= refreshToken])
                        Nothing
            expectStatus 200 rotateResp
            -- Replay the old (now-revoked) token to trigger reuse detection
            withDatabaseConnection (testAppEnv env) \conn ->
                withWildcardSubscription conn \_ -> do
                    _ <-
                        runApp env $
                            jsonPost
                                "/token?grant_type=refresh_token"
                                (Aeson.object ["refresh_token" Aeson..= refreshToken])
                                Nothing
                    n <- countDeliveriesByType conn "session.revoked"
                    n `shouldBe` (1 :: Int)

-- ---------------------------------------------------------------------------
-- Helpers
-- ---------------------------------------------------------------------------

withWildcardSubscription :: Connection -> (UUID -> IO a) -> IO a
withWildcardSubscription conn action = do
    subId <- UUID4.nextRandom
    bracket_
        ( execute
            conn
            "INSERT INTO auth.webhook_subscriptions (id, url, secret, events) \
            \VALUES (?, ?, ?, ?)"
            ( subId
            , "http://test-sink/" :: String
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
    rows <-
        query
            conn
            "SELECT COUNT(*) FROM auth.webhook_deliveries WHERE event_type = ?"
            (Only evtType)
    pure $ case rows of
        [Only n] -> n
        _ -> 0

bootstrapVerifiedUser :: TestEnv -> T.Text -> T.Text -> IO T.Text
bootstrapVerifiedUser env email password = do
    _ <-
        runApp env $
            jsonPost
                "/signup"
                (Aeson.object ["email" Aeson..= email, "password" Aeson..= password])
                Nothing
    mUser <- withDatabaseConnection (testAppEnv env) (`getUserByEmail` email)
    token <- case mUser >>= userConfirmationToken of
        Just t -> pure t
        Nothing -> error "bootstrapVerifiedUser: no confirmation_token"
    verifyResp <-
        runApp env $
            jsonPost
                "/verify"
                (Aeson.object ["type" Aeson..= ("signup" :: T.Text), "token" Aeson..= token])
                Nothing
    obj <- decodeObject verifyResp
    extractString "access_token" obj

decodeObject :: SResponse -> IO Aeson.Object
decodeObject resp =
    case Aeson.eitherDecode (simpleBody resp) of
        Left err -> error ("decodeObject: " <> err)
        Right v -> pure v

extractString :: Aeson.Key -> Aeson.Object -> IO T.Text
extractString k obj =
    case KeyMap.lookup k obj of
        Just (Aeson.String t) -> pure t
        Just other -> error ("key " <> show k <> " not a string: " <> show other)
        Nothing -> error ("missing key " <> show k)
