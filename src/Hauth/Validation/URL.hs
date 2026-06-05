{- | Shared helper for parsing and validating absolute HTTP(S) URLs.

Use 'parseHttpUrl' wherever a config field or API request field must be an
absolute @http:\/\/@ or @https:\/\/@ URL.  The returned 'URI' carries the
fully-parsed value so downstream consumers (e.g. the SSRF-policy layer,
issue #192) can inspect host, path, and query without re-parsing.
-}
module Hauth.Validation.URL (
    parseHttpUrl,
) where

import Data.Text (Text)
import qualified Data.Text as T
import Network.URI (URI (..), URIAuth (..), parseAbsoluteURI)

{- | Parse an absolute HTTP(S) URL.

Returns @'Right' uri@ when the input is a syntactically valid absolute URI
whose scheme is @http:@ or @https:@ and whose authority (host) is
non-empty.

Returns @'Left' message@ otherwise, where @message@ is a short
human-readable reason suitable for embedding in validation errors.
-}
parseHttpUrl :: Text -> Either String URI
parseHttpUrl t =
    case parseAbsoluteURI (T.unpack t) of
        Nothing ->
            Left "must be an absolute http:// or https:// URL"
        Just uri
            | uriScheme uri `notElem` ["http:", "https:"] ->
                Left "must be an absolute http:// or https:// URL"
            | maybe True (null . uriRegName) (uriAuthority uri) ->
                Left "must be an absolute http:// or https:// URL"
            | otherwise ->
                Right uri
