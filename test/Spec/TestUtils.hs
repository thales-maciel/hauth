module Spec.TestUtils (
    testLogger,
    validConfigBytes,
    invalidConfigBytes,
    testCfg,
    makeTestClaims,
) where

import Data.Aeson (Value (..))
import qualified Data.Aeson.KeyMap as KeyMap
import qualified Data.ByteString.Char8 as BSC
import Data.Time.Clock (UTCTime, addUTCTime)
import Hauth.Auth.Jwt (AccessTokenClaims (..), AmrEntry (..))
import Hauth.Config (JwtConfig (..))
import Hauth.Env (Logger (..))

testLogger :: Logger
testLogger =
    Logger \_level _message ->
        pure ()

validConfigBytes :: BSC.ByteString
validConfigBytes =
    BSC.pack $
        unlines
            [ "{"
            , "  \"database\": {"
            , "    \"url\": \"postgresql://hauth:hauth@localhost:5432/hauth\","
            , "    \"pool_size\": 5"
            , "  },"
            , "  \"jwt\": {"
            , "    \"secret\": \"0123456789abcdef0123456789abcdef\","
            , "    \"issuer\": \"hauth\","
            , "    \"audience\": \"authenticated\","
            , "    \"access_token_ttl_seconds\": 3600,"
            , "    \"refresh_token_ttl_seconds\": 2592000"
            , "  },"
            , "  \"site\": {"
            , "    \"url\": \"http://localhost:3000\","
            , "    \"allowed_redirect_urls\": [\"http://localhost:3000/auth/callback\"]"
            , "  },"
            , "  \"email\": {"
            , "    \"from\": \"noreply@example.com\","
            , "    \"smtp_host\": \"localhost\","
            , "    \"smtp_port\": 1025"
            , "  },"
            , "  \"oauth\": {"
            , "    \"providers\": ["
            , "      {"
            , "        \"name\": \"github\","
            , "        \"client_id\": \"github-client-id\","
            , "        \"client_secret\": \"github-client-secret\","
            , "        \"discovery_url\": \"https://github.com/.well-known/openid-configuration\""
            , "      }"
            , "    ]"
            , "  },"
            , "  \"server\": {"
            , "    \"host\": \"127.0.0.1\","
            , "    \"port\": 8080"
            , "  }"
            , "}"
            ]

invalidConfigBytes :: BSC.ByteString
invalidConfigBytes =
    BSC.pack $
        unlines
            [ "{"
            , "  \"database\": {"
            , "    \"url\": \"mysql://localhost/hauth\","
            , "    \"pool_size\": 0"
            , "  },"
            , "  \"jwt\": {"
            , "    \"secret\": \"short\","
            , "    \"issuer\": \"\","
            , "    \"audience\": \"\","
            , "    \"access_token_ttl_seconds\": 0,"
            , "    \"refresh_token_ttl_seconds\": -1"
            , "  },"
            , "  \"site\": {"
            , "    \"url\": \"localhost:3000\","
            , "    \"allowed_redirect_urls\": [\"ftp://localhost/callback\"]"
            , "  },"
            , "  \"email\": {"
            , "    \"from\": \"noreply\","
            , "    \"smtp_host\": \"\","
            , "    \"smtp_port\": 70000"
            , "  },"
            , "  \"oauth\": {"
            , "    \"providers\": ["
            , "      {"
            , "        \"name\": \"\","
            , "        \"client_id\": \"\","
            , "        \"client_secret\": \"\","
            , "        \"discovery_url\": \"github.com\""
            , "      }"
            , "    ]"
            , "  },"
            , "  \"server\": {"
            , "    \"host\": \"\","
            , "    \"port\": 0"
            , "  }"
            , "}"
            ]

testCfg :: JwtConfig
testCfg =
    JwtConfig
        { jwtSecret = "0123456789abcdef0123456789abcdef"
        , jwtIssuer = "https://auth.example.com"
        , jwtAudience = "authenticated"
        , jwtAccessTokenTtlSeconds = 3600
        , jwtRefreshTokenTtlSeconds = 2592000
        }

-- | Build test claims using the given current time.
makeTestClaims :: UTCTime -> AccessTokenClaims
makeTestClaims now =
    let futureTime = addUTCTime 3600 now
     in AccessTokenClaims
            { claimSub = "00000000-0000-0000-0000-000000000000"
            , claimRole = "authenticated"
            , claimEmail = Just "user@example.com"
            , claimPhone = Nothing
            , claimAppMetadata = Object (KeyMap.fromList [])
            , claimUserMetadata = Object (KeyMap.fromList [])
            , claimAal = "aal1"
            , claimAmr = [AmrEntry{amrMethod = "password", amrTimestamp = 1780000000}]
            , claimSessionId = "00000000-0000-0000-0000-000000000001"
            , claimIssuedAt = now
            , claimExpiresAt = futureTime
            }
