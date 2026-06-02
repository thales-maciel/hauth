{- | Shared JSON error-body builders for HTTP handlers.

Centralizes two response shapes the public API emits today:

* 'oauth2ErrorBody' — @{"error": code, "error_description": msg}@. Required by
  OAuth2 RFC 6749 for the @/token@ endpoint; also used historically by
  @/verify@ and @/recover@ (preserved here as-is — see follow-up note in the
  refactor PR introducing this module).

* 'supabaseErrorBody' — @{"code": code, "msg": msg}@. The shape Supabase Auth
  emits for signup, session, and admin endpoints; existing clients depend on
  it.

This module deliberately does NOT pick one canonical shape. Each handler keeps
the shape it emitted before the refactor; consolidating to a single shape is a
separate wire-format change.
-}
module Hauth.Server.Errors (
    oauth2ErrorBody,
    oauth2ErrorOnly,
    supabaseErrorBody,
    supabaseErrorOnly,
) where

import qualified Data.Aeson as Aeson
import qualified Data.ByteString.Lazy as BSL
import Data.Text (Text)

oauth2ErrorBody :: Text -> Text -> BSL.ByteString
oauth2ErrorBody code description =
    Aeson.encode $
        Aeson.object
            [ "error" Aeson..= code
            , "error_description" Aeson..= description
            ]

{- | Single-field OAuth2 error: @{"error": code}@ with no description. Matches
the existing wire shape for grants like @unsupported_grant_type@.
-}
oauth2ErrorOnly :: Text -> BSL.ByteString
oauth2ErrorOnly code =
    Aeson.encode $ Aeson.object ["error" Aeson..= code]

supabaseErrorBody :: Text -> Text -> BSL.ByteString
supabaseErrorBody code msg =
    Aeson.encode $
        Aeson.object
            [ "code" Aeson..= code
            , "msg" Aeson..= msg
            ]

{- | Single-field Supabase error: @{"code": code}@. Used at the (rare) sites
that emit a code with no human message.
-}
supabaseErrorOnly :: Text -> BSL.ByteString
supabaseErrorOnly code =
    Aeson.encode $ Aeson.object ["code" Aeson..= code]
