module Hauth.OAuth (
    FlowState (..),
    FlowStateId (..),
    IdentityClaims (..),
    OAuthError (..),
    ProviderName (..),
    buildStubAuthorizeUrl,
    consumeFlowState,
    createFlowState,
    findOrCreateIdentity,
    generateState,
    isFlowStateExpired,
    lookupProvider,
    validateRedirectTo,
) where

import Control.Exception (Exception, throwIO, try)
import Data.Aeson (Value)
import Data.List (find)
import Data.Maybe (fromMaybe)
import Data.Text (Text)
import qualified Data.Text as T
import qualified Data.Text.Encoding as TE
import Data.Time (UTCTime)
import Data.Time.Clock (diffUTCTime)
import Data.UUID (UUID)
import qualified Data.UUID.V4 as UUID4
import Database.PostgreSQL.Simple (Connection, Only (..), SqlError (..), execute, execute_, query, withTransaction)
import Database.PostgreSQL.Simple.FromRow (FromRow (..), field)
import Hauth.Config (OAuthConfig (..), OAuthProviderConfig (..), SiteConfig (..))
import Hauth.Session (generateOpaqueToken)
import qualified Hauth.User as User
import Network.HTTP.Types.URI (renderSimpleQuery)
import System.IO (hPutStrLn, stderr)

-- ---------------------------------------------------------------------------
-- Core types
-- ---------------------------------------------------------------------------

newtype ProviderName = ProviderName {unProviderName :: Text}
    deriving stock (Eq, Show)

newtype FlowStateId = FlowStateId {unFlowStateId :: UUID}
    deriving stock (Eq, Show)

data FlowState = FlowState
    { flowStateId :: FlowStateId
    , flowStateAuthCode :: Text
    -- ^ The state token stored in auth_code column.
    , flowStateProviderType :: Text
    -- ^ Provider name e.g. "google" | "github".
    , flowStateAuthenticationMethod :: Text
    -- ^ Always "oauth" for OAuth flows.
    , flowStateCreatedAt :: UTCTime
    , flowStateExpiresAfterSeconds :: Int
    -- ^ v0.1: hard-coded 600 (10 minutes).
    }
    deriving stock (Eq, Show)

data OAuthError
    = OAuthUnknownProvider Text
    | OAuthStateExpired
    | OAuthStateInvalid
    | OAuthMissingParam Text
    | -- | Identity row unexpectedly absent after an insert attempt.
      -- The 'Text' carries the provider and provider_id for diagnostics.
      OAuthIdentityMissing Text
    deriving stock (Eq, Show)

instance Exception OAuthError

data IdentityClaims = IdentityClaims
    { identityProvider :: Text
    , identityProviderId :: Text
    -- ^ Provider's user id (sub from id_token, etc.).
    , identityEmail :: Maybe Text
    , identityData :: Value
    -- ^ Raw provider userinfo blob.
    }
    deriving stock (Eq, Show)

-- ---------------------------------------------------------------------------
-- Flow state expiry (seconds)
-- ---------------------------------------------------------------------------

flowStateMaxAgeSecs :: Int
flowStateMaxAgeSecs = 600

-- ---------------------------------------------------------------------------
-- Pure helpers
-- ---------------------------------------------------------------------------

{- | Case-insensitive lookup of a provider by name against 'OAuthConfig'.

Returns 'Right' the matching 'OAuthProviderConfig' or
'Left' ('OAuthUnknownProvider' name).
-}
lookupProvider :: OAuthConfig -> Text -> Either OAuthError OAuthProviderConfig
lookupProvider OAuthConfig{oauthProviders} name =
    case find (\p -> T.toLower (oauthProviderName p) == T.toLower name) oauthProviders of
        Just cfg -> Right cfg
        Nothing -> Left (OAuthUnknownProvider name)

{- | Validate that a redirect URL is listed in 'SiteConfig.siteAllowedRedirectUrls'.

Returns 'Right' the redirect URL if allowed, 'Left' otherwise.
-}
validateRedirectTo :: SiteConfig -> Text -> Either OAuthError Text
validateRedirectTo SiteConfig{siteAllowedRedirectUrls} redirectTo =
    if redirectTo `elem` siteAllowedRedirectUrls
        then Right redirectTo
        else Left (OAuthMissingParam "redirect_to")

{- | Check whether a flow state has expired.

Returns 'True' when @now - createdAt > maxAgeSecs@.
-}
isFlowStateExpired :: UTCTime -> UTCTime -> Int -> Bool
isFlowStateExpired now createdAt maxAgeSecs =
    diffUTCTime now createdAt > fromIntegral maxAgeSecs

{- | Build the authorization redirect URL for a configured provider.

Concatenates fixed OAuth 2.0 query parameters onto the provider's
authorization endpoint as configured in @oauth.providers[].discovery_url@.
The emitted parameters are:

* @state@ — the server-issued single-use flow-state token.
* @client_id@ — taken from the provider config.
* @redirect_uri@ — the @\<site.url\>/auth/v1/callback@ that hauth registers
  with providers.
* @response_type=code@ — authorization-code flow.
* @scope=openid email profile@ — fixed for every provider in v0.2; Google
  honors all three, GitHub ignores them.

Despite the @discovery_url@ field name, hauth does not fetch an OIDC
discovery document — per-provider token and userinfo endpoints are
compiled in (see "Hauth.OAuth.Google" and "Hauth.OAuth.Github").
Per-provider scope configuration and runtime discovery are deferred to
v0.4; see @docs\/OAUTH.md@ ("Status and limitations").
-}
buildStubAuthorizeUrl ::
    OAuthProviderConfig ->
    -- | State token.
    Text ->
    -- | Callback URL (redirect_uri sent to provider).
    Text ->
    -- | Original redirect_to from the caller (for reference).
    Text ->
    Text
buildStubAuthorizeUrl OAuthProviderConfig{oauthProviderDiscoveryUrl, oauthProviderClientId} state callbackUrl _redirectTo =
    oauthProviderDiscoveryUrl <> "?" <> renderedQuery
  where
    renderedQuery =
        TE.decodeUtf8 $
            renderSimpleQuery
                False
                [ ("state", TE.encodeUtf8 state)
                , ("client_id", TE.encodeUtf8 oauthProviderClientId)
                , ("redirect_uri", TE.encodeUtf8 callbackUrl)
                , ("response_type", "code")
                , ("scope", "openid email profile")
                ]

-- ---------------------------------------------------------------------------
-- IO helpers
-- ---------------------------------------------------------------------------

{- | Generate a cryptographically random state token.

Delegates to 'Hauth.Session.generateOpaqueToken' which produces 32 random
bytes base64url-encoded without padding (43 characters).
-}
generateState :: IO Text
generateState = generateOpaqueToken

-- ---------------------------------------------------------------------------
-- Database operations
-- ---------------------------------------------------------------------------

instance FromRow FlowState where
    fromRow =
        FlowState . FlowStateId
            <$> field
            <*> field
            <*> field
            <*> field
            <*> field
            <*> pure flowStateMaxAgeSecs

{- | Insert a new row into @auth.flow_state@ and return the persisted record.

The state token is stored in the @auth_code@ column.
-}
createFlowState :: Connection -> ProviderName -> Text -> IO FlowState
createFlowState conn (ProviderName providerName) stateToken = do
    fid <- UUID4.nextRandom
    rows <-
        query
            conn
            "INSERT INTO auth.flow_state \
            \  (id, auth_code, provider_type, authentication_method) \
            \VALUES \
            \  (?, ?, ?, 'oauth') \
            \RETURNING \
            \  id, auth_code, provider_type, authentication_method, created_at"
            (fid, stateToken, providerName)
    case rows of
        [row] -> pure row
        _ -> fail "createFlowState: expected exactly one row returned"

{- | Look up a flow state by its state token (@auth_code@) and consume it.

If the row does not exist → 'Left' 'OAuthStateInvalid'.
If it is older than 'flowStateMaxAgeSecs' → delete it and return
'Left' 'OAuthStateExpired'.
Otherwise → delete it and return 'Right' the 'FlowState'.
-}
consumeFlowState :: Connection -> Text -> IO (Either OAuthError FlowState)
consumeFlowState conn stateToken =
    withTransaction conn do
        rows <-
            query
                conn
                "DELETE FROM auth.flow_state \
                \WHERE auth_code = ? \
                \RETURNING id, auth_code, provider_type, authentication_method, created_at"
                (Only stateToken)
        case rows of
            [] -> pure (Left OAuthStateInvalid)
            (row : _) -> do
                let fs = row{flowStateExpiresAfterSeconds = flowStateMaxAgeSecs}
                nowRows <-
                    query
                        conn
                        "SELECT now()"
                        ()
                case (nowRows :: [Only UTCTime]) of
                    [Only now] ->
                        if isFlowStateExpired now (flowStateCreatedAt fs) flowStateMaxAgeSecs
                            then pure (Left OAuthStateExpired)
                            else pure (Right fs)
                    _ -> pure (Right fs)

{- | Find or create a user linked to the given OAuth identity.

Look up @auth.identities@ by @(provider, provider_id)@.

- If found: return the linked @user_id@ with @isNewUser = False@.
- If not found and email matches an existing user: link the identity and
  return that user's id with @isNewUser = False@.
- If not found and no user with that email exists: create a new user, insert
  the identity, and return the new user's id with @isNewUser = True@.

All three steps run inside a single transaction. On a concurrent first-login
race the identity INSERT may hit the (provider, provider_id) unique constraint;
the conflict is caught and the existing row is re-read so both callers resolve
to the same user.

The new-user path guards the 'User.createUser' call with a SAVEPOINT so that
the race loser's @auth.users@ row is rolled back when the identity INSERT is
skipped (0 rows affected), preventing orphan user accumulation.
-}
findOrCreateIdentity :: Connection -> IdentityClaims -> IO (User.UserId, Bool)
findOrCreateIdentity conn IdentityClaims{identityProvider, identityProviderId, identityEmail, identityData} =
    withTransaction conn go
  where
    go = do
        existingRows <-
            query
                conn
                "SELECT user_id FROM auth.identities \
                \WHERE provider = ? AND provider_id = ?"
                (identityProvider, identityProviderId)
        case (existingRows :: [Only UUID]) of
            (Only uid : _) ->
                pure (User.UserId uid, False)
            [] -> do
                -- No existing identity; try to link by email.
                mUser <- case identityEmail of
                    Nothing -> pure Nothing
                    Just email -> User.getUserByEmail conn email
                case mUser of
                    Just user -> do
                        -- Link the identity to the email-matched user.
                        insertIdentityOrFetch conn (User.unUserId (User.userId user)) identityProvider identityProviderId identityEmail identityData
                        -- Re-read: a concurrent caller may have already linked this identity to a
                        -- different user (the persisted identity row is authoritative).
                        resolvedUid <- fetchIdentityUserId conn identityProvider identityProviderId
                        -- Warn when the persisted identity diverges from the email-matched user.
                        -- The session will bind to `resolvedUid` (the winner); this is correct
                        -- behaviour — the identity row is the source of truth — but it means the
                        -- email-match was superseded by a concurrent link.
                        if resolvedUid /= User.userId user
                            then do
                                hPutStrLn stderr $
                                    "findOrCreateIdentity: email-matched user "
                                        <> show (User.unUserId (User.userId user))
                                        <> " superseded by concurrent identity link for "
                                        <> "(provider="
                                        <> T.unpack identityProvider
                                        <> ", provider_id="
                                        <> T.unpack identityProviderId
                                        <> "); binding session to winning user "
                                        <> show (User.unUserId resolvedUid)
                                pure (resolvedUid, False)
                            else pure (resolvedUid, False)
                    Nothing -> do
                        -- No existing user; set a SAVEPOINT before creating one so the
                        -- loser's auth.users row can be rolled back when the identity
                        -- INSERT is skipped due to a concurrent winner.
                        _ <- execute_ conn "SAVEPOINT before_create_user"
                        let newUser =
                                User.NewUser
                                    { User.newUserEmail = fromMaybe "" identityEmail
                                    , User.newUserEncryptedPassword = ""
                                    , User.newUserConfirmationToken = Nothing
                                    , User.newUserUserMetadata = identityData
                                    , User.newUserAud = "authenticated"
                                    }
                        eCreated <- try (User.createUser conn newUser)
                        case eCreated of
                            Left (e :: SqlError)
                                | sqlState e == "23505" -> do
                                    -- Concurrent caller already inserted a user with
                                    -- this email (collides on users_email_partial_key,
                                    -- which fires even for empty-string emails on the
                                    -- no-email OAuth path). Roll back and resolve to
                                    -- the winning identity.
                                    _ <- execute_ conn "ROLLBACK TO SAVEPOINT before_create_user"
                                    resolvedUid <- fetchIdentityUserId conn identityProvider identityProviderId
                                    pure (resolvedUid, False)
                                | otherwise -> throwIO e
                            Right createdUser -> do
                                let candidateUid = User.userId createdUser
                                iid <- UUID4.nextRandom
                                rows <-
                                    execute
                                        conn
                                        "INSERT INTO auth.identities \
                                        \  (id, user_id, provider_id, provider, identity_data) \
                                        \VALUES \
                                        \  (?, ?, ?, ?, ?) \
                                        \ON CONFLICT (provider, provider_id) DO NOTHING"
                                        ( T.pack (show iid)
                                        , User.unUserId candidateUid
                                        , identityProviderId
                                        , identityProvider
                                        , identityData
                                        )
                                if rows == 1
                                    then do
                                        -- We won the race: commit the savepoint and return the new user.
                                        _ <- execute_ conn "RELEASE SAVEPOINT before_create_user"
                                        pure (candidateUid, True)
                                    else do
                                        -- We lost the race: roll back the orphan auth.users row and
                                        -- re-read the winning identity.
                                        _ <- execute_ conn "ROLLBACK TO SAVEPOINT before_create_user"
                                        resolvedUid <- fetchIdentityUserId conn identityProvider identityProviderId
                                        pure (resolvedUid, False)

-- | Read the user_id for an existing (provider, provider_id) identity row.
fetchIdentityUserId :: Connection -> Text -> Text -> IO User.UserId
fetchIdentityUserId conn provider providerId = do
    rows <-
        query
            conn
            "SELECT user_id FROM auth.identities WHERE provider = ? AND provider_id = ?"
            (provider, providerId)
    case (rows :: [Only UUID]) of
        (Only uid : _) -> pure (User.UserId uid)
        [] ->
            throwIO $
                OAuthIdentityMissing
                    ("identity row not found after insert: provider=" <> provider <> " provider_id=" <> providerId)

{- | Insert an identity row; on (provider, provider_id) PK conflict do nothing
(the row already exists from a concurrent first-login).
-}
insertIdentityOrFetch :: Connection -> UUID -> Text -> Text -> Maybe Text -> Value -> IO ()
insertIdentityOrFetch conn uid provider providerId _email idData = do
    iid <- UUID4.nextRandom
    _ <-
        execute
            conn
            "INSERT INTO auth.identities \
            \  (id, user_id, provider_id, provider, identity_data) \
            \VALUES \
            \  (?, ?, ?, ?, ?) \
            \ON CONFLICT (provider, provider_id) DO NOTHING"
            (T.pack (show iid), uid, providerId, provider, idData)
    pure ()
