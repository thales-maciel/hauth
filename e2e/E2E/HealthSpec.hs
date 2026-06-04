module E2E.HealthSpec (spec) where

import Control.Exception (bracket_)
import Data.Aeson (Value (..))
import qualified Data.Aeson as Aeson
import qualified Data.Aeson.KeyMap as KeyMap
import Data.Foldable (toList)
import Data.Text (Text)
import E2E.Helpers (TestEnv (..), expectStatus, jsonGet, runApp)
import Hauth.Env (
    BackgroundServiceName (..),
    BackgroundServiceStatus (..),
    recordBackgroundServiceStatus,
 )
import Network.Wai.Test (SResponse, simpleBody)
import Test.Hspec (SpecWith, it, shouldBe)

spec :: SpecWith TestEnv
spec = do
    it "reports background services as healthy in deep health" \env -> do
        resp <- runApp env $ jsonGet "/healthz/deep" Nothing
        expectStatus 200 resp
        body <- decodeValue resp
        checkStatus body "webhook_worker" `shouldBe` Just "ok"
        checkStatus body "template_listener" `shouldBe` Just "ok"

    -- The deep-health policy lives in 'Hauth.Server.Health.aggregateStatus':
    -- failing the required webhook worker flips the response to "unhealthy" /
    -- 503; failing the optional template listener is "degraded" / 200. We
    -- fail both here and assert each is classified per the policy.
    it "classifies background services per required/optional policy" \env ->
        bracket_ (failStatuses env) (restoreStatuses env) do
            resp <- runApp env $ jsonGet "/healthz/deep" Nothing
            expectStatus 503 resp
            body <- decodeValue resp
            checkStatus body "webhook_worker" `shouldBe` Just "failed"
            checkReason body "webhook_worker" `shouldBe` Just "worker boom"
            checkStatus body "template_listener" `shouldBe` Just "degraded"
            checkReason body "template_listener" `shouldBe` Just "listener boom"

    -- Only the optional template listener is down — overall status must stay
    -- "degraded" and the response must be 200 so monitors don't false-page.
    it "stays 200 / degraded when only the optional listener fails" \env ->
        bracket_ (failTemplateListener env) (restoreStatuses env) do
            resp <- runApp env $ jsonGet "/healthz/deep" Nothing
            expectStatus 200 resp
            body <- decodeValue resp
            topStatus body `shouldBe` Just "degraded"
            checkStatus body "webhook_worker" `shouldBe` Just "ok"
            checkStatus body "template_listener" `shouldBe` Just "degraded"

failStatuses :: TestEnv -> IO ()
failStatuses env = do
    recordBackgroundServiceStatus (testAppEnv env) WebhookWorker (BackgroundServiceFailed "worker boom")
    recordBackgroundServiceStatus (testAppEnv env) TemplateListener (BackgroundServiceFailed "listener boom")

failTemplateListener :: TestEnv -> IO ()
failTemplateListener env =
    recordBackgroundServiceStatus (testAppEnv env) TemplateListener (BackgroundServiceFailed "listener boom")

restoreStatuses :: TestEnv -> IO ()
restoreStatuses env = do
    recordBackgroundServiceStatus (testAppEnv env) WebhookWorker BackgroundServiceRunning
    recordBackgroundServiceStatus (testAppEnv env) TemplateListener BackgroundServiceRunning

decodeValue :: SResponse -> IO Value
decodeValue resp =
    case Aeson.eitherDecode (simpleBody resp) of
        Left err ->
            fail ("deep health JSON decode failed: " <> err)
        Right value ->
            pure value

checkStatus :: Value -> Text -> Maybe Text
checkStatus value name = do
    Object check <- findCheck value name
    case KeyMap.lookup "status" check of
        Just (String status) -> Just status
        _ -> Nothing

topStatus :: Value -> Maybe Text
topStatus (Object obj) =
    case KeyMap.lookup "status" obj of
        Just (String status) -> Just status
        _ -> Nothing
topStatus _ = Nothing

checkReason :: Value -> Text -> Maybe Text
checkReason value name = do
    Object check <- findCheck value name
    case KeyMap.lookup "reason" check of
        Just (String reason) -> Just reason
        _ -> Nothing

findCheck :: Value -> Text -> Maybe Value
findCheck (Object obj) name = do
    Array checks <- KeyMap.lookup "checks" obj
    findByName name (toList checks)
findCheck _ _ =
    Nothing

findByName :: Text -> [Value] -> Maybe Value
findByName name = \case
    [] ->
        Nothing
    check@(Object obj) : rest ->
        case KeyMap.lookup "name" obj of
            Just (String actual)
                | actual == name ->
                    Just check
            _ ->
                findByName name rest
    _ : rest ->
        findByName name rest
