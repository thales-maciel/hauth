module Hauth.Server.Hooks (
    createHookHandler,
    deleteHookHandler,
    getHookHandler,
    listHooksHandler,
    rotateHookSecretHandler,
    updateHookHandler,
) where

import Control.Exception (try)
import Control.Monad.Except (throwError)
import Control.Monad.IO.Class (liftIO)
import Control.Monad.Reader (ReaderT, ask)
import qualified Crypto.Random as CR
import qualified Data.Aeson as Aeson
import Data.ByteArray.Encoding (Base (..), convertToBase)
import qualified Data.ByteString as BS
import Data.Maybe (fromMaybe)
import qualified Data.Text as T
import qualified Data.Text.Encoding as TE
import Data.UUID (UUID)
import qualified Data.UUID as UUID
import Database.PostgreSQL.Simple (Only (..), SqlError (..), execute, query, sqlErrorMsg)
import Hauth.API.Auth (ServiceRolePrincipal)
import Hauth.API.Types (
    CreateHookRequest (..),
    HookCreateResponse (..),
    HookId (..),
    HookRow (..),
    ListHooksResponse (..),
    RotateHookSecretRequest (..),
    RotateHookSecretResponse (..),
    UpdateHookRequest (..),
    toCreateResponse,
 )
import Hauth.Env (AppEnv (..), withDatabaseConnection)
import Hauth.Hooks.Types (HookPoint, hookPointName, parseHookPoint)
import Hauth.Validation.URL (parseHttpUrl)
import Servant.API (NoContent (..))
import Servant.Server (Handler, ServerError (..), err400, err404, err409)

type AppHandler = ReaderT AppEnv Handler

-- ---------------------------------------------------------------------------
-- Validation helpers
-- ---------------------------------------------------------------------------

validateUrl :: T.Text -> Either ServerError ()
validateUrl u =
    case parseHttpUrl u of
        Right _ -> Right ()
        Left _ ->
            Left
                err400
                    { errBody =
                        Aeson.encode $
                            Aeson.object
                                [ "error" Aeson..= ("invalid_url" :: T.Text)
                                , "msg" Aeson..= ("url must be an absolute http:// or https:// URI" :: T.Text)
                                ]
                    }

validateTimeout :: Int -> Either ServerError ()
validateTimeout ms =
    if ms < 100 || ms > 3000
        then
            Left
                err400
                    { errBody =
                        Aeson.encode $
                            Aeson.object
                                [ "error" Aeson..= ("invalid_timeout" :: T.Text)
                                , "msg" Aeson..= ("timeout_ms must be between 100 and 3000" :: T.Text)
                                ]
                    }
        else Right ()

validateHookPoint :: T.Text -> Either ServerError HookPoint
validateHookPoint t =
    case parseHookPoint t of
        Nothing ->
            Left
                err400
                    { errBody =
                        Aeson.encode $
                            Aeson.object
                                [ "error" Aeson..= ("invalid_hook_point" :: T.Text)
                                , "msg" Aeson..= ("hook_point must be one of: before-user-created, custom-access-token, mfa-verification-attempt, password-verification-attempt" :: T.Text)
                                ]
                    }
        Just hp -> Right hp

-- ---------------------------------------------------------------------------
-- Database helpers
-- ---------------------------------------------------------------------------

rowToHookRow :: (UUID, T.Text, T.Text, T.Text, Int, Bool, Bool) -> Maybe HookRow
rowToHookRow (i, hp, u, s, t, fo, en) =
    case parseHookPoint hp of
        Nothing -> Nothing
        Just p ->
            Just
                HookRow
                    { hookRowId = i
                    , hookRowPoint = p
                    , hookRowUrl = u
                    , hookRowSecret = s
                    , hookRowTimeoutMs = t
                    , hookRowFailOpen = fo
                    , hookRowEnabled = en
                    }

fetchById :: AppEnv -> UUID -> IO (Maybe HookRow)
fetchById env hid = do
    rows <-
        withDatabaseConnection env \conn ->
            query
                conn
                "SELECT id, hook_point, url, secret, timeout_ms, fail_open, enabled \
                \FROM auth.hooks WHERE id = ?"
                (Only hid)
    pure $ case rows of
        (r : _) -> rowToHookRow r
        [] -> Nothing

parseHookId :: T.Text -> AppHandler UUID
parseHookId hid =
    case UUID.fromText hid of
        Nothing ->
            throwError
                err400
                    { errBody =
                        Aeson.encode $
                            Aeson.object
                                [ "error" Aeson..= ("invalid_id" :: T.Text)
                                , "msg" Aeson..= ("malformed hook id" :: T.Text)
                                ]
                    }
        Just u -> pure u

-- ---------------------------------------------------------------------------
-- Handlers
-- ---------------------------------------------------------------------------

generateSecret :: IO T.Text
generateSecret = do
    bytes <- CR.getRandomBytes 32 :: IO BS.ByteString
    pure (TE.decodeUtf8 (convertToBase Base16 bytes))

{- | Create a new hook. Returns the plaintext secret once in the response;
subsequent GET/list responses will redact it.
-}
createHookHandler :: ServiceRolePrincipal -> CreateHookRequest -> AppHandler HookCreateResponse
createHookHandler _ req = do
    hp <- either throwError pure (validateHookPoint (createHookPoint req))
    either throwError pure (validateUrl (createHookUrl req))
    case createHookTimeoutMs req of
        Just ms -> either throwError pure (validateTimeout ms)
        Nothing -> pure ()
    env <- ask
    secret <- case createHookSecret req of
        Just s -> pure s
        Nothing -> liftIO generateSecret
    let timeoutMs = fromMaybe 2000 (createHookTimeoutMs req)
        failOpen = fromMaybe False (createHookFailOpen req)
        enabled = fromMaybe True (createHookEnabled req)
    result <- liftIO $
        try $
            withDatabaseConnection env \conn ->
                query
                    conn
                    "INSERT INTO auth.hooks (hook_point, url, secret, timeout_ms, fail_open, enabled) \
                    \VALUES (?, ?, ?, ?, ?, ?) \
                    \RETURNING id, hook_point, url, secret, timeout_ms, fail_open, enabled"
                    ( hookPointName hp
                    , createHookUrl req
                    , secret
                    , timeoutMs
                    , failOpen
                    , enabled
                    )
    case (result :: Either SqlError [(UUID, T.Text, T.Text, T.Text, Int, Bool, Bool)]) of
        Left err
            | "unique" `T.isInfixOf` T.toLower (TE.decodeUtf8 (sqlErrorMsg err)) ->
                throwError
                    err409
                        { errBody =
                            Aeson.encode $
                                Aeson.object
                                    [ "error" Aeson..= ("hook_point_taken" :: T.Text)
                                    , "msg" Aeson..= ("A hook is already configured for this hook_point" :: T.Text)
                                    ]
                        }
        Left err ->
            throwError
                err400
                    { errBody =
                        Aeson.encode $
                            Aeson.object
                                [ "error" Aeson..= ("db_error" :: T.Text)
                                , "msg" Aeson..= TE.decodeUtf8 (sqlErrorMsg err)
                                ]
                    }
        Right rows ->
            case rows of
                (r : _) ->
                    case rowToHookRow r of
                        Just hr -> pure (toCreateResponse hr)
                        Nothing ->
                            throwError
                                err400
                                    { errBody = Aeson.encode $ Aeson.object ["error" Aeson..= ("parse_error" :: T.Text)]
                                    }
                [] ->
                    throwError
                        err400
                            { errBody = Aeson.encode $ Aeson.object ["error" Aeson..= ("insert_failed" :: T.Text)]
                            }

listHooksHandler :: ServiceRolePrincipal -> AppHandler ListHooksResponse
listHooksHandler _ = do
    env <- ask
    rows <- liftIO $
        withDatabaseConnection env \conn ->
            query
                conn
                "SELECT id, hook_point, url, secret, timeout_ms, fail_open, enabled \
                \FROM auth.hooks ORDER BY created_at"
                ()
    let hooks = [hr | r <- rows, Just hr <- [rowToHookRow r]]
    pure ListHooksResponse{listHookRows = hooks}

getHookHandler :: ServiceRolePrincipal -> HookId -> AppHandler HookRow
getHookHandler _ (HookId hid) = do
    uid <- parseHookId hid
    env <- ask
    mHook <- liftIO (fetchById env uid)
    case mHook of
        Nothing -> throwError hookNotFoundError
        Just hr -> pure hr

updateHookHandler :: ServiceRolePrincipal -> HookId -> UpdateHookRequest -> AppHandler HookRow
updateHookHandler _ (HookId hid) req = do
    uid <- parseHookId hid
    case updateHookUrl req of
        Just u -> either throwError pure (validateUrl u)
        Nothing -> pure ()
    case updateHookTimeoutMs req of
        Just ms -> either throwError pure (validateTimeout ms)
        Nothing -> pure ()
    env <- ask
    mHook <- liftIO (fetchById env uid)
    case mHook of
        Nothing -> throwError hookNotFoundError
        Just current -> do
            let newUrl = fromMaybe (hookRowUrl current) (updateHookUrl req)
                -- Secret is NOT updated via PUT. Use POST /:id/rotate-secret.
                newSecret = hookRowSecret current
                newTimeout = fromMaybe (hookRowTimeoutMs current) (updateHookTimeoutMs req)
                newFailOpen = fromMaybe (hookRowFailOpen current) (updateHookFailOpen req)
                newEnabled = fromMaybe (hookRowEnabled current) (updateHookEnabled req)
            _ <- liftIO $
                withDatabaseConnection env \conn ->
                    execute
                        conn
                        "UPDATE auth.hooks \
                        \SET url = ?, secret = ?, timeout_ms = ?, fail_open = ?, enabled = ?, updated_at = now() \
                        \WHERE id = ?"
                        (newUrl, newSecret, newTimeout, newFailOpen, newEnabled, uid)
            mUpdated <- liftIO (fetchById env uid)
            case mUpdated of
                Nothing -> throwError hookNotFoundError
                Just hr -> pure hr

{- | POST /admin/hooks/:id/rotate-secret
Rotate the HMAC signing secret for a hook. Supply @{"secret":"..."}@ to
use a caller-provided value, or omit the body to have the server generate
a fresh 32-byte hex secret. Returns the new secret once as
@{"secret":"<plaintext>"}@; subsequent reads will redact it.
-}
rotateHookSecretHandler ::
    ServiceRolePrincipal ->
    HookId ->
    RotateHookSecretRequest ->
    AppHandler RotateHookSecretResponse
rotateHookSecretHandler _ (HookId hid) req = do
    uid <- parseHookId hid
    env <- ask
    mHook <- liftIO (fetchById env uid)
    case mHook of
        Nothing -> throwError hookNotFoundError
        Just _ -> do
            newSecret <- case rotateHookSecret req of
                Just s -> pure s
                Nothing -> liftIO generateSecret
            _ <- liftIO $
                withDatabaseConnection env \conn ->
                    execute
                        conn
                        "UPDATE auth.hooks SET secret = ?, updated_at = now() WHERE id = ?"
                        (newSecret, uid)
            pure RotateHookSecretResponse{rotateHookNewSecret = newSecret}

deleteHookHandler :: ServiceRolePrincipal -> HookId -> AppHandler NoContent
deleteHookHandler _ (HookId hid) = do
    uid <- parseHookId hid
    env <- ask
    n <- liftIO $
        withDatabaseConnection env \conn ->
            execute conn "DELETE FROM auth.hooks WHERE id = ?" (Only uid)
    if n == 0
        then throwError hookNotFoundError
        else pure NoContent

hookNotFoundError :: ServerError
hookNotFoundError =
    err404
        { errBody =
            Aeson.encode $
                Aeson.object
                    [ "error" Aeson..= ("hook_not_found" :: T.Text)
                    , "msg" Aeson..= ("Hook not found" :: T.Text)
                    ]
        }
