{- | Server-rendered HTML for the operator-facing admin UI.

The admin UI is plain server-rendered HTML inside the same static binary —
no JavaScript build step, no separate package, no client-side framework.
Pages are built with @blaze-html@ as type-checked combinators; styling is a
single embedded stylesheet served from the layout. The design target is
@beautifully boring@: predictable form patterns, neutral colours, system
fonts, no animation.

This module exposes pure 'Html' values; HTTP wiring lives in
"Hauth.Server.AdminUI".
-}
module Hauth.AdminUI (
    homePage,
    loginPage,
) where

import Data.Text (Text)
import Text.Blaze.Html5 (Html, (!))
import qualified Text.Blaze.Html5 as H
import qualified Text.Blaze.Html5.Attributes as A

{- | Authenticated landing page served at @\/admin\/ui@. Still a placeholder
until the real shell (#207) and per-resource pages (#208 onward) land.
-}
homePage :: Text -> Html
homePage username = layout "Hauth admin" $ do
    H.h1 "Hauth admin"
    H.p
        "Placeholder. The operator-facing admin UI is being built out under \
        \milestone v0.3. This route exists so the rendering pipeline can be \
        \exercised end-to-end before the real pages land."
    H.p $ do
        "Tracking issues: "
        H.a ! A.href "https://github.com/thales-maciel/hauth/milestone/3" $
            "github.com/thales-maciel/hauth/milestone/3"
        "."
    H.p ! A.class_ "session" $ do
        "Signed in as "
        H.strong (H.toHtml username)
        "."
    H.form ! A.method "post" ! A.action "/admin/ui/logout" $
        H.button ! A.type_ "submit" $
            "Log out"

{- | Login form served at @\/admin\/ui\/login@; the flag shows the
generic failed-attempt message.
-}
loginPage :: Bool -> Html
loginPage showError = layout "Log in — Hauth admin" $ do
    H.h1 "Log in"
    if showError
        then H.p ! A.class_ "error" $ "Invalid username or password."
        else mempty
    H.form ! A.method "post" ! A.action "/admin/ui/login" $ do
        H.label ! A.for "username" $ "Username"
        H.input
            ! A.type_ "text"
            ! A.id "username"
            ! A.name "username"
            ! A.required "required"
            ! A.autofocus "autofocus"
        H.label ! A.for "password" $ "Password"
        H.input
            ! A.type_ "password"
            ! A.id "password"
            ! A.name "password"
            ! A.required "required"
        H.button ! A.type_ "submit" $ "Log in"

{- | The single base layout every admin page renders through. Inline
styles only — no external assets, no CDN. System font stack and neutral
colours per the @beautifully boring@ design target.
-}
layout :: Html -> Html -> Html
layout title body =
    H.docTypeHtml $ do
        H.head $ do
            H.meta ! A.charset "utf-8"
            H.meta ! A.name "viewport" ! A.content "width=device-width, initial-scale=1"
            H.title title
            H.style baseStylesheet
        H.body $
            H.main ! A.class_ "container" $
                body

baseStylesheet :: Html
baseStylesheet =
    H.toHtml @String $
        ":root { color-scheme: light dark; }\n\
        \body { \
        \  font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, \
        \    Oxygen, Ubuntu, Cantarell, sans-serif; \
        \  line-height: 1.5; \
        \  margin: 0; \
        \  color: #1a1a1a; \
        \  background: #fafafa; \
        \}\n\
        \@media (prefers-color-scheme: dark) { \
        \  body { color: #e6e6e6; background: #1a1a1a; } \
        \  a { color: #8ab4f8; } \
        \  input { color: inherit; background: #262626; border-color: #555; } \
        \}\n\
        \.container { max-width: 48rem; margin: 2rem auto; padding: 0 1rem; }\n\
        \h1 { font-size: 1.5rem; margin: 0 0 1rem; }\n\
        \p { margin: 0 0 1rem; }\n\
        \a { color: #1a73e8; }\n\
        \label { display: block; margin: 0 0 0.25rem; }\n\
        \input { \
        \  display: block; \
        \  width: 100%; \
        \  max-width: 20rem; \
        \  margin: 0 0 1rem; \
        \  padding: 0.4rem 0.5rem; \
        \  font: inherit; \
        \  border: 1px solid #bbb; \
        \  border-radius: 3px; \
        \  box-sizing: border-box; \
        \}\n\
        \button { font: inherit; padding: 0.4rem 1rem; cursor: pointer; }\n\
        \.error { color: #b3261e; }\n"
