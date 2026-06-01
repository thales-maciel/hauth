module Hauth.Verify.Identity (
    checks,
    placeholderJwtSecret,
) where

import qualified Data.ByteString as BS
import Data.List (group, nub, sort)
import Data.Text (Text)
import qualified Data.Text as T
import qualified Data.Text.Encoding as TE
import Hauth.Config (Config (..), JwtConfig (..), SiteConfig (..))
import Hauth.Env (AppEnv (..))
import Hauth.Verify.Types (Check (..), CheckOutcome (..))
import Network.URI (parseAbsoluteURI, uriAuthority, uriRegName, uriScheme)

-- | The literal placeholder JWT secret from config.example.json.
placeholderJwtSecret :: Text
placeholderJwtSecret = "0123456789abcdef0123456789abcdef"

checks :: [Check]
checks =
    [ checkJwtSecret
    , checkSiteUrl
    , checkRedirectAllowlist
    ]

checkJwtSecret :: Check
checkJwtSecret =
    Check
        { checkName = "jwt.secret"
        , checkLabel = "JWT secret strength"
        , checkRun = \env ->
            let secret = jwtSecret (configJwt (appConfig env))
                bytes = TE.encodeUtf8 secret
             in pure $
                    if BS.length bytes < 32
                        then CheckFail "secret is under 32 bytes (256 bits)"
                        else
                            if secret == placeholderJwtSecret
                                then CheckFail "matches the example value — generate fresh entropy with `openssl rand -hex 32`"
                                else CheckOk
        }

checkSiteUrl :: Check
checkSiteUrl =
    Check
        { checkName = "site.url"
        , checkLabel = "Site URL"
        , checkRun = \env ->
            let url = T.unpack (siteUrl (configSite (appConfig env)))
             in pure $ case parseAbsoluteURI url of
                    Nothing ->
                        CheckFail ("not a valid absolute URI: " <> T.pack url)
                    Just uri ->
                        let scheme = uriScheme uri
                            host = maybe "" uriRegName (uriAuthority uri)
                         in if scheme == "http:" && host `notElem` localHosts
                                then CheckWarn "http in production — cookies may not be secure"
                                else CheckOk
        }

localHosts :: [String]
localHosts = ["localhost", "127.0.0.1", "::1"]

checkRedirectAllowlist :: Check
checkRedirectAllowlist =
    Check
        { checkName = "site.redirect_allowlist"
        , checkLabel = "Redirect allowlist"
        , checkRun = \env ->
            let urls = siteAllowedRedirectUrls (configSite (appConfig env))
             in pure $ case urls of
                    [] ->
                        CheckWarn "empty allowlist — OAuth and email-link redirects will all fail"
                    _ ->
                        let badUrls = filter (not . isAbsoluteUri) urls
                         in if not (null badUrls)
                                then CheckFail ("unparseable URLs: " <> T.intercalate ", " badUrls)
                                else
                                    let dupes = findDupes urls
                                     in if not (null dupes)
                                            then CheckWarn ("duplicate entries: " <> T.intercalate ", " dupes)
                                            else CheckOk
        }

isAbsoluteUri :: Text -> Bool
isAbsoluteUri url = case parseAbsoluteURI (T.unpack url) of
    Nothing -> False
    Just _ -> True

findDupes :: (Ord a) => [a] -> [a]
findDupes xs = nub [x | x : _ : _ <- group (sort xs)]
