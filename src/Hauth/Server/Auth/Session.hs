{- | Shared session-issuance helper for the public auth handlers.

'issueSessionForUser' is the helper used by the verify and password-grant
flows to mint a fresh session for an already-authenticated user. Kept in
its own module so that both 'Hauth.Server.Auth.Verify' and
'Hauth.Server.Auth.Token' (when they need it) can import it without forming
a cycle.
-}
module Hauth.Server.Auth.Session (
    AppHandler,
    issueSessionForUser,
) where

import Control.Monad.Except (throwError)
import Control.Monad.IO.Class (liftIO)
import Control.Monad.Reader (ReaderT, ask)
import qualified Data.Text as T
import Data.Time.Clock (addUTCTime, getCurrentTime)
import Data.Time.Clock.POSIX (utcTimeToPOSIXSeconds)
import qualified Data.UUID as UUID
import Hauth.API.Types
import Hauth.Auth.Jwt (AccessTokenClaims (..), AmrEntry (..), issueAccessToken)
import Hauth.Auth.Role (sanitizeSessionRole)
import Hauth.Config (Config (..), JwtConfig (..))
import Hauth.Env (AppEnv (..), withDatabaseConnection)
import Hauth.Server.Errors (oauth2ErrorBody)
import Hauth.Session (
    NewSession (..),
    SessionId (..),
    createRefreshToken,
    createSession,
    refreshTokenToken,
    sessionId,
 )
import qualified Hauth.User as User
import Servant.Server (Handler, ServerError (errBody), err500)

type AppHandler = ReaderT AppEnv Handler

issueSessionForUser :: User.User -> T.Text -> AppHandler SessionResponse
issueSessionForUser user methodName = do
    env <- ask
    let AppEnv{appConfig} = env
        Config{configJwt} = appConfig
        JwtConfig{jwtAccessTokenTtlSeconds} = configJwt
    now <- liftIO getCurrentTime
    let uid = User.unUserId (User.userId user)
        ttl = fromIntegral jwtAccessTokenTtlSeconds
        expiry = addUTCTime ttl now
        iatSecs = floor (utcTimeToPOSIXSeconds now) :: Integer
        newSess =
            NewSession
                { newSessionUserId = uid
                , newSessionAal = "aal1"
                , newSessionFactorId = Nothing
                , newSessionUserAgent = Nothing
                , newSessionIp = Nothing
                , newSessionNotAfter = Nothing
                }
    session <- liftIO (withDatabaseConnection env (`createSession` newSess))
    let sid = sessionId session
    refreshTok <- liftIO (withDatabaseConnection env (\conn -> createRefreshToken conn sid Nothing))
    let claims =
            AccessTokenClaims
                { claimSub = UUID.toText uid
                , claimRole = sanitizeSessionRole (User.userRole user)
                , claimEmail = User.userEmail user
                , claimPhone = Nothing
                , claimAppMetadata = User.userRawAppMetaData user
                , claimUserMetadata = User.userRawUserMetaData user
                , claimAal = "aal1"
                , claimAmr =
                    [ AmrEntry
                        { amrMethod = methodName
                        , amrTimestamp = iatSecs
                        }
                    ]
                , claimSessionId = UUID.toText (unSessionId sid)
                , claimIssuedAt = now
                , claimExpiresAt = expiry
                }
    signResult <- liftIO (issueAccessToken env claims)
    accessToken <- case signResult of
        Left err ->
            throwError
                err500
                    { errBody = oauth2ErrorBody "token_issuance_blocked" (T.pack (show err))
                    }
        Right t -> pure t
    pure
        SessionResponse
            { sessionAccessToken = accessToken
            , sessionExpiresIn = jwtAccessTokenTtlSeconds
            , sessionRefreshToken = refreshTokenToken refreshTok
            , sessionUser = buildUserResponse user
            }
