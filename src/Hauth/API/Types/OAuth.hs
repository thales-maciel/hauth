-- | Wire types for the OAuth authorize flow.
module Hauth.API.Types.OAuth (
    OAuthAuthorizeResponse (..),
) where

import Data.Aeson (FromJSON (..), ToJSON (toJSON), object, (.=))
import qualified Data.Aeson as Aeson
import Data.Text (Text)
import GHC.Generics (Generic)

data OAuthAuthorizeResponse = OAuthAuthorizeResponse
    { oauthAuthorizeUrl :: Text
    , oauthAuthorizeState :: Text
    }
    deriving stock (Eq, Generic, Show)

instance ToJSON OAuthAuthorizeResponse where
    toJSON OAuthAuthorizeResponse{oauthAuthorizeUrl, oauthAuthorizeState} =
        object
            [ "url" .= oauthAuthorizeUrl
            , "state" .= oauthAuthorizeState
            ]

instance FromJSON OAuthAuthorizeResponse where
    parseJSON = Aeson.withObject "OAuthAuthorizeResponse" \o ->
        OAuthAuthorizeResponse
            <$> o Aeson..: "url"
            <*> o Aeson..: "state"
