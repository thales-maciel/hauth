{- | E2E tests: auth handlers call the env-injected EmailSender.

Uses a fake capturing sender injected into the TestEnv so tests are
deterministic and need no live SMTP server. Covers signup, /resend, /recover,
and /admin/invite email-emission paths.
-}
module E2E.EmailDeliverySpec (spec) where

import Control.Concurrent.MVar (MVar, modifyMVar_, newMVar, readMVar)
import qualified Data.Aeson as Aeson
import qualified Data.Aeson.KeyMap as KeyMap
import qualified Data.Text as T
import Database.PostgreSQL.Simple (Only (..), query)
import E2E.Helpers (
    TestEnv (..),
    decodeBody,
    expectStatus,
    jsonGet,
    jsonPost,
    mintServiceRoleJwt,
    runApp,
 )
import Hauth.Email (EmailMessage (..), EmailSender (..))
import Hauth.Env (AppEnv (..), withDatabaseConnection)
import Hauth.User (User (..), getUserByEmail)
import Network.Wai.Test (Session)
import Test.Hspec (SpecWith, describe, it, shouldBe, shouldSatisfy)

spec :: SpecWith TestEnv
spec = do
    describe "signup emits confirmation email" $
        it "sends one email to the signed-up address" \env -> do
            withCapturingSender env \(capturedVar, senderEnv) -> do
                resp <-
                    runApp (senderEnv env) $
                        jsonPost
                            "/signup"
                            (Aeson.object ["email" Aeson..= ("smtp-signup@example.com" :: T.Text), "password" Aeson..= ("correct horse" :: T.Text)])
                            Nothing
                expectStatus 200 resp
                captured <- readMVar capturedVar
                length captured `shouldBe` 1
                let msg = head captured
                emailTo msg `shouldBe` "smtp-signup@example.com"

    describe "/resend emits confirmation email" $
        it "sends one email to the resend address" \env -> do
            -- First sign up (also emits, but we start fresh)
            withCapturingSender env \(capturedVar, senderEnv) -> do
                _ <-
                    runApp (senderEnv env) $
                        jsonPost
                            "/signup"
                            (Aeson.object ["email" Aeson..= ("smtp-resend@example.com" :: T.Text), "password" Aeson..= ("correct horse" :: T.Text)])
                            Nothing
                -- Clear captured emails and resend
                modifyMVar_ capturedVar (\_ -> pure [])
                resendResp <-
                    runApp (senderEnv env) $
                        jsonPost
                            "/resend"
                            ( Aeson.object
                                [ "email" Aeson..= ("smtp-resend@example.com" :: T.Text)
                                , "type" Aeson..= ("signup" :: T.Text)
                                ]
                            )
                            Nothing
                expectStatus 200 resendResp
                captured <- readMVar capturedVar
                length captured `shouldBe` 1
                let msg = head captured
                emailTo msg `shouldBe` "smtp-resend@example.com"

    describe "/recover emits recovery email" $
        it "sends one email for a password user" \env -> do
            -- Signup + confirm so user has a password
            _ <-
                runApp env $
                    jsonPost
                        "/signup"
                        (Aeson.object ["email" Aeson..= ("smtp-recover@example.com" :: T.Text), "password" Aeson..= ("correct horse" :: T.Text)])
                        Nothing
            confirmUser env "smtp-recover@example.com"
            withCapturingSender env \(capturedVar, senderEnv) -> do
                resp <-
                    runApp (senderEnv env) $
                        jsonPost "/recover" (Aeson.object ["email" Aeson..= ("smtp-recover@example.com" :: T.Text)]) Nothing
                expectStatus 200 resp
                captured <- readMVar capturedVar
                length captured `shouldBe` 1
                let msg = head captured
                emailTo msg `shouldBe` "smtp-recover@example.com"

    describe "/admin/invite emits invite email" $
        it "sends one email to the invited address" \env -> do
            bearer <- mintServiceRoleJwt env
            withCapturingSender env \(capturedVar, senderEnv) -> do
                resp <-
                    runApp (senderEnv env) $
                        jsonPost
                            "/admin/invite"
                            (Aeson.object ["email" Aeson..= ("smtp-invite@example.com" :: T.Text)])
                            (Just bearer)
                expectStatus 200 resp
                captured <- readMVar capturedVar
                length captured `shouldBe` 1
                let msg = head captured
                emailTo msg `shouldBe` "smtp-invite@example.com"

-- ---------------------------------------------------------------------------
-- Helpers
-- ---------------------------------------------------------------------------

-- | Build a TestEnv variant with a capturing fake sender and give it to the action.
withCapturingSender :: TestEnv -> ((MVar [EmailMessage], TestEnv -> TestEnv) -> IO a) -> IO a
withCapturingSender _ action = do
    capturedVar <- newMVar []
    let fakeSender =
            EmailSender
                { sendEmail = \msg -> do
                    modifyMVar_ capturedVar (\acc -> pure (acc <> [msg]))
                    pure (Right ())
                }
        -- Override the email sender on the AppEnv inside the TestEnv
        injectSender env =
            env{testAppEnv = (testAppEnv env){appEmailSender = fakeSender}}
    action (capturedVar, injectSender)

-- | Verify the signup and return the confirmation token.
confirmUser :: TestEnv -> T.Text -> IO ()
confirmUser env email = do
    mUser <- withDatabaseConnection (testAppEnv env) (`getUserByEmail` email)
    case mUser >>= userConfirmationToken of
        Nothing -> error ("confirmUser: no token for " <> T.unpack email)
        Just tok -> do
            _ <-
                runApp env $
                    jsonPost
                        "/verify"
                        (Aeson.object ["type" Aeson..= ("signup" :: T.Text), "token" Aeson..= tok])
                        Nothing
            pure ()
