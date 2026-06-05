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
import Database.PostgreSQL.Simple (Connection, Only (..), execute, query, withTransaction)
import Database.PostgreSQL.Simple.FromRow (FromRow (..), field)
import Hauth.Config (OAuthConfig (..), OAuthProviderConfig (..), SiteConfig (..))
import Hauth.Session (generateOpaqueToken)
import qualified Hauth.User as User
import Network.HTTP.Types.URI (renderSimpleQuery)

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
    deriving stock (Eq, Show)

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
v0.3; see @docs\/OAUTH.md@ ("Status and limitations").
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
consumeFlowState conn stateToken = do
    rows <-
        query
            conn
            "SELECT \
            \  id, auth_code, provider_type, authentication_method, created_at \
            \FROM auth.flow_state \
            \WHERE auth_code = ?"
            (Only stateToken)
    case rows of
        [] -> pure (Left OAuthStateInvalid)
        (row : _) -> do
            let fs = row{flowStateExpiresAfterSeconds = flowStateMaxAgeSecs}
            -- Always delete the row regardless of expiry to prevent reuse.
            _ <-
                execute
                    conn
                    "DELETE FROM auth.flow_state WHERE auth_code = ?"
                    (Only stateToken)
            -- Check expiry against DB clock for consistency.
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
                        -- Link the identity to the existing user.
                        insertIdentityOrFetch conn (User.unUserId (User.userId user)) identityProvider identityProviderId identityEmail identityData
                        -- Re-read to get the committed user_id (concurrent winner may differ).
                        resolvedUid <- fetchIdentityUserId conn identityProvider identityProviderId
                        pure (resolvedUid, False)
                    Nothing -> do
                        -- Create a brand-new user, use the returned row directly.
                        let newUser =
                                User.NewUser
                                    { User.newUserEmail = fromMaybe "" identityEmail
                                    , User.newUserEncryptedPassword = ""
                                    , User.newUserConfirmationToken = Nothing
                                    , User.newUserUserMetadata = identityData
                                    , User.newUserAud = "authenticated"
                                    }
                        createdUser <- User.createUser conn newUser
                        let candidateUid = User.userId createdUser
                        insertIdentityOrFetch conn (User.unUserId candidateUid) identityProvider identityProviderId identityEmail identityData
                        -- Re-read: concurrent winner may have inserted identity linking a different user.
                        resolvedUid <- fetchIdentityUserId conn identityProvider identityProviderId
                        let isNew = resolvedUid == candidateUid
                        pure (resolvedUid, isNew)

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
        [] -> fail "fetchIdentityUserId: identity row not found after insert"

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
