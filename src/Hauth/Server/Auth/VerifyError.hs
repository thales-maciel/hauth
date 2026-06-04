{- | Shared error-body helper for the verify and resend endpoints.

Historical wire shape: @{\"error\", \"msg\"}@ — neither OAuth2 nor Supabase
canonical. Preserved verbatim; tracked as a follow-up.
-}
module Hauth.Server.Auth.VerifyError (
    verifyErrorBody,
) where

import qualified Data.Aeson as Aeson
import Data.Text (Text)

verifyErrorBody :: Text -> Text -> Aeson.Value
verifyErrorBody code msg =
    Aeson.object
        [ "error" Aeson..= code
        , "msg" Aeson..= msg
        ]
