{-# LANGUAGE OverloadedStrings #-}

module E2E.MfaSpec (spec) where

import Control.Concurrent (forkIO, threadDelay)
import Control.Concurrent.MVar (newEmptyMVar, putMVar, takeMVar)
import Control.Exception (bracket_)
import qualified Data.Aeson as Aeson
import qualified Data.Aeson.KeyMap as KeyMap
import qualified Data.ByteString as BS
import qualified Data.ByteString.Lazy as BSL
import qualified Data.Text as T
import qualified Data.Text.Encoding as TE
import Data.Time.Clock.POSIX (getPOSIXTime)
import Data.UUID (UUID)
import qualified Data.UUID.V4 as UUID4
import Database.PostgreSQL.Simple (Connection, Only (..), execute, query)
import Database.PostgreSQL.Simple.Types (PGArray (..))
import E2E.Helpers (
    TestEnv (..),
    decodeBody,
    expectStatus,
    jsonPost,
    runApp,
 )
import Hauth.Env (withDatabaseConnection)
import Hauth.Hooks.Types (HookPoint (..), hookPointName)
import Hauth.Mfa.Totp (TotpSecret (..), decodeBase32)
import Hauth.Mfa.TotpVerify (currentTimeStep, totpCodeAtStep)
import Hauth.User (User (..), getUserByEmail)
import Network.HTTP.Types (status200)
import Network.Socket (
    Family (..),
    SockAddr (..),
    Socket,
    SocketOption (..),
    SocketType (..),
    bind,
    close,
    listen,
    maxListenQueue,
    setSocketOption,
    socket,
    socketPort,
 )
import Network.Wai (Application, responseLBS)
import qualified Network.Wai.Handler.Warp as Warp
import Test.Hspec (SpecWith, describe, it, shouldBe)

spec :: SpecWith TestEnv
spec = do
    describe "enroll → challenge → verify TOTP factor" $
        it "elevates the session to aal2" \env -> do
            access <- bootstrapVerifiedUser env "gina@example.com" "correct horse"

            -- Enroll the factor.
            enrollResp <-
                runApp env $
                    jsonPost
                        "/factors"
                        (Aeson.object ["factor_type" Aeson..= ("totp" :: T.Text), "friendly_name" Aeson..= ("Phone" :: T.Text)])
                        (Just access)
            expectStatus 200 enrollResp
            (enrollObj :: Aeson.Object) <- decodeBody enrollResp
            factorId <- extractString "id" enrollObj
            totp <- case KeyMap.lookup "totp" enrollObj of
                Just (Aeson.Object t) -> pure t
                other -> error ("expected totp object; got " <> show other)
            secretB32 <- extractString "secret" totp
            secretBytes <- case decodeBase32 secretB32 of
                Just bs -> pure bs
                Nothing -> error ("could not decode TOTP secret: " <> T.unpack secretB32)

            -- Challenge (mostly a no-op for TOTP).
            challengeResp <-
                runApp env $
                    jsonPost
                        ("/factors/" <> TE.encodeUtf8 factorId <> "/challenge")
                        (Aeson.object [])
                        (Just access)
            expectStatus 200 challengeResp
            (challengeObj :: Aeson.Object) <- decodeBody challengeResp
            challengeId <- extractString "id" challengeObj

            -- Compute a valid code for the current time and submit it.
            now <- getPOSIXTime
            let code = totpCodeAtStep (TotpSecret secretBytes) (currentTimeStep now)
            verifyResp <-
                runApp env $
                    jsonPost
                        ("/factors/" <> TE.encodeUtf8 factorId <> "/verify")
                        ( Aeson.object
                            [ "challenge_id" Aeson..= challengeId
                            , "code" Aeson..= code
                            ]
                        )
                        (Just access)
            expectStatus 200 verifyResp
            (verifyObj :: Aeson.Object) <- decodeBody verifyResp
            KeyMap.member "access_token" verifyObj `shouldBe` True

    describe "enroll emits mfa.enrolled delivery" $
        it "wildcard subscription receives one delivery" \env ->
            withDatabaseConnection (testAppEnv env) \conn -> do
                withWildcardSubscription conn \_ -> do
                    access <- bootstrapVerifiedUser env "webhook-enroll@example.com" "correct horse"
                    _ <-
                        runApp env $
                            jsonPost
                                "/factors"
                                (Aeson.object ["factor_type" Aeson..= ("totp" :: T.Text)])
                                (Just access)
                    n <- countDeliveriesByType conn "mfa.enrolled"
                    n `shouldBe` (1 :: Int)

    describe "verify emits mfa.verified delivery" $
        it "wildcard subscription receives one delivery" \env ->
            withDatabaseConnection (testAppEnv env) \conn -> do
                withWildcardSubscription conn \_ -> do
                    access <- bootstrapVerifiedUser env "webhook-verify@example.com" "correct horse"
                    enrollResp <-
                        runApp env $
                            jsonPost
                                "/factors"
                                (Aeson.object ["factor_type" Aeson..= ("totp" :: T.Text)])
                                (Just access)
                    (enrollObj :: Aeson.Object) <- decodeBody enrollResp
                    factorId <- extractString "id" enrollObj
                    totp <- case KeyMap.lookup "totp" enrollObj of
                        Just (Aeson.Object t) -> pure t
                        other -> error ("expected totp object; got " <> show other)
                    secretB32 <- extractString "secret" totp
                    secretBytes <- case decodeBase32 secretB32 of
                        Just bs -> pure bs
                        Nothing -> error ("could not decode TOTP secret: " <> T.unpack secretB32)
                    _ <-
                        runApp env $
                            jsonPost
                                ("/factors/" <> TE.encodeUtf8 factorId <> "/challenge")
                                (Aeson.object [])
                                (Just access)
                    now <- getPOSIXTime
                    let code = totpCodeAtStep (TotpSecret secretBytes) (currentTimeStep now)
                    _ <-
                        runApp env $
                            jsonPost
                                ("/factors/" <> TE.encodeUtf8 factorId <> "/verify")
                                ( Aeson.object
                                    [ "challenge_id" Aeson..= ("unused" :: T.Text)
                                    , "code" Aeson..= code
                                    ]
                                )
                                (Just access)
                    n <- countDeliveriesByType conn "mfa.verified"
                    n `shouldBe` (1 :: Int)

    describe "verify with wrong code" $
        it "returns 401 invalid_code" \env -> do
            access <- bootstrapVerifiedUser env "henry@example.com" "correct horse"
            enrollResp <-
                runApp env $
                    jsonPost
                        "/factors"
                        (Aeson.object ["factor_type" Aeson..= ("totp" :: T.Text)])
                        (Just access)
            (enrollObj :: Aeson.Object) <- decodeBody enrollResp
            factorId <- extractString "id" enrollObj
            challengeResp <-
                runApp env $
                    jsonPost
                        ("/factors/" <> TE.encodeUtf8 factorId <> "/challenge")
                        (Aeson.object [])
                        (Just access)
            (challengeObj :: Aeson.Object) <- decodeBody challengeResp
            challengeId <- extractString "id" challengeObj
            verifyResp <-
                runApp env $
                    jsonPost
                        ("/factors/" <> TE.encodeUtf8 factorId <> "/verify")
                        ( Aeson.object
                            [ "challenge_id" Aeson..= challengeId
                            , "code" Aeson..= ("000000" :: T.Text)
                            ]
                        )
                        (Just access)
            expectStatus 401 verifyResp

    describe "mfa-verification-attempt hook" $ do
        it "no hook: verify succeeds with correct code" \env -> do
            access <- bootstrapVerifiedUser env "mfa-no-hook@example.com" "correct horse"
            (factorId, secretBytes) <- enrollFactor env access
            challengeId <- challengeFactor env access factorId
            now <- getPOSIXTime
            let code = totpCodeAtStep (TotpSecret secretBytes) (currentTimeStep now)
            verifyResp <-
                runApp env $
                    jsonPost
                        ("/factors/" <> TE.encodeUtf8 factorId <> "/verify")
                        (Aeson.object ["challenge_id" Aeson..= challengeId, "code" Aeson..= code])
                        (Just access)
            expectStatus 200 verifyResp

        it "hook allow: verify succeeds with correct code" \env ->
            withMfaHookServer (allowApp env) env \port -> do
                seedMfaHook env port 5000 False
                access <- bootstrapVerifiedUser env "mfa-allow@example.com" "correct horse"
                (factorId, secretBytes) <- enrollFactor env access
                challengeId <- challengeFactor env access factorId
                now <- getPOSIXTime
                let code = totpCodeAtStep (TotpSecret secretBytes) (currentTimeStep now)
                verifyResp <-
                    runApp env $
                        jsonPost
                            ("/factors/" <> TE.encodeUtf8 factorId <> "/verify")
                            (Aeson.object ["challenge_id" Aeson..= challengeId, "code" Aeson..= code])
                            (Just access)
                expectStatus 200 verifyResp

        it "hook reject: 400 even with correct code (opaque error)" \env ->
            withMfaHookServer (rejectApp env) env \port -> do
                seedMfaHook env port 5000 False
                access <- bootstrapVerifiedUser env "mfa-reject@example.com" "correct horse"
                (factorId, secretBytes) <- enrollFactor env access
                challengeId <- challengeFactor env access factorId
                now <- getPOSIXTime
                let code = totpCodeAtStep (TotpSecret secretBytes) (currentTimeStep now)
                verifyResp <-
                    runApp env $
                        jsonPost
                            ("/factors/" <> TE.encodeUtf8 factorId <> "/verify")
                            (Aeson.object ["challenge_id" Aeson..= challengeId, "code" Aeson..= code])
                            (Just access)
                expectStatus 400 verifyResp
                (errObj :: Aeson.Object) <- decodeBody verifyResp
                KeyMap.lookup "error" errObj `shouldBe` Just (Aeson.String "mfa_or_password_blocked")

        it "hook timeout fail_open=false: rejects verify" \env ->
            withMfaHookServer (slowApp env) env \port -> do
                seedMfaHook env port 50 False
                access <- bootstrapVerifiedUser env "mfa-timeout-closed@example.com" "correct horse"
                (factorId, secretBytes) <- enrollFactor env access
                challengeId <- challengeFactor env access factorId
                now <- getPOSIXTime
                let code = totpCodeAtStep (TotpSecret secretBytes) (currentTimeStep now)
                verifyResp <-
                    runApp env $
                        jsonPost
                            ("/factors/" <> TE.encodeUtf8 factorId <> "/verify")
                            (Aeson.object ["challenge_id" Aeson..= challengeId, "code" Aeson..= code])
                            (Just access)
                expectStatus 400 verifyResp
                (errObj :: Aeson.Object) <- decodeBody verifyResp
                KeyMap.lookup "error" errObj `shouldBe` Just (Aeson.String "mfa_or_password_blocked")

        it "hook timeout fail_open=true: TOTP check proceeds" \env ->
            withMfaHookServer (slowApp env) env \port -> do
                seedMfaHook env port 50 True
                access <- bootstrapVerifiedUser env "mfa-timeout-open@example.com" "correct horse"
                (factorId, secretBytes) <- enrollFactor env access
                challengeId <- challengeFactor env access factorId
                now <- getPOSIXTime
                let code = totpCodeAtStep (TotpSecret secretBytes) (currentTimeStep now)
                verifyResp <-
                    runApp env $
                        jsonPost
                            ("/factors/" <> TE.encodeUtf8 factorId <> "/verify")
                            (Aeson.object ["challenge_id" Aeson..= challengeId, "code" Aeson..= code])
                            (Just access)
                expectStatus 200 verifyResp

-- ---------------------------------------------------------------------------
-- Hook helpers for MFA tests
-- ---------------------------------------------------------------------------

allowResponse :: BSL.ByteString
allowResponse = Aeson.encode (Aeson.object [("decision", Aeson.String "allow")])

rejectResponse :: BSL.ByteString
rejectResponse =
    Aeson.encode
        ( Aeson.object
            [ ("decision", Aeson.String "reject")
            , ("reason", Aeson.String "blocked by operator policy")
            ]
        )

allowApp :: TestEnv -> Application
allowApp _ _req respond =
    respond (responseLBS status200 [("Content-Type", "application/json")] allowResponse)

rejectApp :: TestEnv -> Application
rejectApp _ _req respond =
    respond (responseLBS status200 [("Content-Type", "application/json")] rejectResponse)

slowApp :: TestEnv -> Application
slowApp _ _req respond = do
    threadDelay 500000
    respond (responseLBS status200 [("Content-Type", "application/json")] allowResponse)

withMfaHookServer :: Application -> TestEnv -> (Int -> IO a) -> IO a
withMfaHookServer hookApp env action = do
    ready <- newEmptyMVar
    sock <- openFreeSocket
    port <- fromIntegral <$> socketPort sock
    _ <- forkIO $ do
        putMVar ready ()
        Warp.runSettingsSocket
            (Warp.setPort port Warp.defaultSettings)
            sock
            hookApp
    takeMVar ready
    threadDelay 10000
    result <-
        bracket_
            (pure ())
            ( withDatabaseConnection (testAppEnv env) \conn ->
                execute conn "DELETE FROM auth.hooks WHERE hook_point = ?" (Only (hookPointName HookMfaVerificationAttempt))
            )
            (action port)
    close sock
    pure result

seedMfaHook :: TestEnv -> Int -> Int -> Bool -> IO ()
seedMfaHook env port timeoutMs failOpen =
    withDatabaseConnection (testAppEnv env) \conn -> do
        _ <-
            execute
                conn
                "INSERT INTO auth.hooks (hook_point, url, secret, timeout_ms, fail_open, enabled) \
                \VALUES (?, ?, ?, ?, ?, true)"
                ( hookPointName HookMfaVerificationAttempt
                , "http://127.0.0.1:" <> T.pack (show port) <> "/" :: T.Text
                , "test-secret" :: T.Text
                , timeoutMs :: Int
                , failOpen
                )
        pure ()

openFreeSocket :: IO Socket
openFreeSocket = do
    sock <- socket AF_INET Stream 0
    setSocketOption sock ReuseAddr 1
    bind sock (SockAddrInet 0 0)
    listen sock maxListenQueue
    pure sock

-- Enroll a TOTP factor and return (factorId, secretBytes).
enrollFactor :: TestEnv -> T.Text -> IO (T.Text, BS.ByteString)
enrollFactor env access = do
    enrollResp <-
        runApp env $
            jsonPost
                "/factors"
                (Aeson.object ["factor_type" Aeson..= ("totp" :: T.Text), "friendly_name" Aeson..= ("Hook Test" :: T.Text)])
                (Just access)
    (enrollObj :: Aeson.Object) <- decodeBody enrollResp
    factorId <- extractString "id" enrollObj
    totp <- case KeyMap.lookup "totp" enrollObj of
        Just (Aeson.Object t) -> pure t
        other -> error ("enrollFactor: expected totp object; got " <> show other)
    secretB32 <- extractString "secret" totp
    secretBytes <- case decodeBase32 secretB32 of
        Just bs -> pure bs
        Nothing -> error "enrollFactor: could not decode TOTP secret"
    pure (factorId, secretBytes)

-- Challenge a factor and return the challengeId.
challengeFactor :: TestEnv -> T.Text -> T.Text -> IO T.Text
challengeFactor env access factorId = do
    challengeResp <-
        runApp env $
            jsonPost
                ("/factors/" <> TE.encodeUtf8 factorId <> "/challenge")
                (Aeson.object [])
                (Just access)
    (challengeObj :: Aeson.Object) <- decodeBody challengeResp
    extractString "id" challengeObj

-- Shared signup+verify bootstrap, returning the user's bearer access token.
bootstrapVerifiedUser :: TestEnv -> T.Text -> T.Text -> IO T.Text
bootstrapVerifiedUser env email password = do
    _ <-
        runApp env $
            jsonPost
                "/signup"
                (Aeson.object ["email" Aeson..= email, "password" Aeson..= password])
                Nothing
    mUser <- withDatabaseConnection (testAppEnv env) (`getUserByEmail` email)
    user <- case mUser of
        Just u -> pure u
        Nothing -> error "bootstrapVerifiedUser: no user"
    token <- case userConfirmationToken user of
        Just t -> pure t
        Nothing -> error "bootstrapVerifiedUser: no confirmation_token"
    verifyResp <-
        runApp env $
            jsonPost
                "/verify"
                (Aeson.object ["type" Aeson..= ("signup" :: T.Text), "token" Aeson..= token])
                Nothing
    (obj :: Aeson.Object) <- decodeBody verifyResp
    extractString "access_token" obj

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
