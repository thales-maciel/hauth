-- | Wire shapes for the operator-facing admin UI (form bodies, not JSON).
module Hauth.API.Types.AdminUI (
    AdminLoginForm (..),
) where

import Data.Text (Text)
import Web.FormUrlEncoded (FromForm (fromForm), parseUnique)

-- | Body of @POST /admin/ui/login@ (application/x-www-form-urlencoded).
data AdminLoginForm = AdminLoginForm
    { loginFormUsername :: Text
    , loginFormPassword :: Text
    }
    deriving stock (Eq, Show)

instance FromForm AdminLoginForm where
    fromForm form =
        AdminLoginForm
            <$> parseUnique "username" form
            <*> parseUnique "password" form
