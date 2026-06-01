module Hauth.Email.Templates (
    knownTemplateNames,
    isKnownTemplate,
) where

import Data.Set (Set)
import qualified Data.Set as Set
import Data.Text (Text)

-- | The well-known template names seeded by migration 0011 and embedded in templates/.
knownTemplateNames :: Set Text
knownTemplateNames =
    Set.fromList
        [ "confirmation"
        , "email_change"
        , "invite"
        , "recovery"
        ]

isKnownTemplate :: Text -> Bool
isKnownTemplate = (`Set.member` knownTemplateNames)
