{- | Pure helpers for the password grant login flow.

These functions are extracted so they can be unit-tested without a database
or IO.  The IO wiring lives in 'Hauth.Server'.
-}
module Hauth.Auth.Login (
    LoginError (..),
    authorizeLogin,
    buildLoginClaims,
    extractCredentials,
) where

import Data.Text (Text)
import qualified Data.Text as T
import Data.Time.Clock (UTCTime, addUTCTime)
import Data.Time.Clock.POSIX (utcTimeToPOSIXSeconds)
import qualified Data.UUID as UUID
import Hauth.API.Types (Email (..), Password (..), TokenRequest (..))
import Hauth.Auth.Jwt (AccessTokenClaims (..), AmrEntry (..))
import Hauth.Config (JwtConfig (..))
import Hauth.Session (SessionId (..))
import Hauth.User (User (..), UserId (..))

-- | Errors that can occur during the password grant login flow.
data LoginError
    = -- | The request is missing email or password (or they are blank).
      LoginMissingFields
    | -- | User not found, no stored password, or password mismatch.
      LoginInvalidGrant
    | -- | User exists and credentials matched, but email is not confirmed.
      LoginEmailNotConfirmed
    deriving stock (Eq, Show)

{- | Extract email and password from a 'TokenRequest'.

Returns 'Left' 'LoginMissingFields' if either field is absent or blank.
-}
extractCredentials :: TokenRequest -> Either LoginError (Text, Text)
extractCredentials TokenRequest{tokenRequestEmail, tokenRequestPassword} = do
    emailText <- case tokenRequestEmail of
        Nothing -> Left LoginMissingFields
        Just (Email e)
            | T.null e -> Left LoginMissingFields
            | otherwise -> Right e
    passwordText <- case tokenRequestPassword of
        Nothing -> Left LoginMissingFields
        Just (Password p)
            | T.null p -> Left LoginMissingFields
            | otherwise -> Right p
    pure (emailText, passwordText)

{- | Decide whether a user can log in.

- Password failure always yields 'LoginInvalidGrant', regardless of
  email-confirmation state (prevents leaking whether an account exists).
- If the password verified but the email is unconfirmed, yields
  'LoginEmailNotConfirmed'.
- If both are fine, yields 'Right ()'.
-}
authorizeLogin ::
    -- | Result of 'verifyPassword': 'True' means the password matched.
    Bool ->
    -- | 'userEmailConfirmedAt' from the persisted user row.
    Maybe UTCTime ->
    Either LoginError ()
authorizeLogin False _ = Left LoginInvalidGrant
authorizeLogin True Nothing = Left LoginEmailNotConfirmed
authorizeLogin True (Just _) = Right ()

{- | Build 'AccessTokenClaims' for a freshly-created session.

Pure given the JWT configuration, the persisted 'User', the new 'SessionId',
and the current time.
-}
buildLoginClaims :: JwtConfig -> User -> SessionId -> UTCTime -> AccessTokenClaims
buildLoginClaims JwtConfig{jwtAccessTokenTtlSeconds} user (SessionId sid) now =
    let ttl = fromIntegral jwtAccessTokenTtlSeconds
        expiry = addUTCTime ttl now
        iatSecs = floor (utcTimeToPOSIXSeconds now) :: Integer
        UserId uid = userId user
     in AccessTokenClaims
            { claimSub = UUID.toText uid
            , claimRole = "authenticated"
            , claimEmail = userEmail user
            , claimPhone = Nothing
            , claimAppMetadata = userRawAppMetaData user
            , claimUserMetadata = userRawUserMetaData user
            , claimAal = "aal1"
            , claimAmr =
                [ AmrEntry
                    { amrMethod = "password"
                    , amrTimestamp = iatSecs
                    }
                ]
            , claimSessionId = UUID.toText sid
            , claimIssuedAt = now
            , claimExpiresAt = expiry
            }
