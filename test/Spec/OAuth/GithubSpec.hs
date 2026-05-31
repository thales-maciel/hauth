module Spec.OAuth.GithubSpec (runSpec) where

import Data.Aeson (Value (..))
import qualified Data.Aeson as Aeson
import qualified Data.ByteString as BS
import qualified Data.Text as T
import qualified Data.Text.Encoding as TE
import Hauth.Config (OAuthProviderConfig (..))
import Hauth.OAuth.Github (
    GithubExchangeError (..),
    buildGithubTokenForm,
    githubProviderName,
    parseGithubEmails,
    parseGithubUser,
    pickPrimaryEmail,
 )
import Spec.TestUtils (assertEqual)

runSpec :: IO ()
runSpec = do
    -- githubProviderName
    assertEqual "githubProviderName is 'github'" "github" githubProviderName

    -- parseGithubUser: valid with email
    let userWithEmail =
            Aeson.object
                [ "id" Aeson..= (1234 :: Int)
                , "login" Aeson..= ("alice" :: T.Text)
                , "email" Aeson..= ("a@b.com" :: T.Text)
                ]
    assertEqual
        "parseGithubUser with id and email"
        (Right ("1234", Just "a@b.com"))
        (parseGithubUser userWithEmail)

    -- parseGithubUser: missing id
    let userNoId =
            Aeson.object
                ["login" Aeson..= ("x" :: T.Text)]
    assertEqual
        "parseGithubUser missing id returns GithubMissingId"
        (Left GithubMissingId)
        (parseGithubUser userNoId)

    -- parseGithubUser: id present but no email field
    let userNoEmail =
            Aeson.object
                ["id" Aeson..= (99 :: Int)]
    assertEqual
        "parseGithubUser with id but no email returns Nothing email"
        (Right ("99", Nothing))
        (parseGithubUser userNoEmail)

    -- parseGithubUser: id present with null email treated as Nothing
    let userNullEmail =
            Aeson.object
                [ "id" Aeson..= (42 :: Int)
                , "email" Aeson..= Null
                ]
    assertEqual
        "parseGithubUser with null email returns Nothing email"
        (Right ("42", Nothing))
        (parseGithubUser userNullEmail)

    -- parseGithubUser: not an object
    assertEqual
        "parseGithubUser on non-object returns GithubUserInvalid"
        (Left (GithubUserInvalid "expected a JSON object"))
        (parseGithubUser (String "oops"))

    -- parseGithubEmails: valid array
    let emailsJson =
            Aeson.toJSON
                [ Aeson.object
                    [ "email" Aeson..= ("a@b.com" :: T.Text)
                    , "primary" Aeson..= True
                    , "verified" Aeson..= True
                    ]
                , Aeson.object
                    [ "email" Aeson..= ("c@d.com" :: T.Text)
                    , "primary" Aeson..= False
                    , "verified" Aeson..= True
                    ]
                ]
    assertEqual
        "parseGithubEmails valid array"
        (Right [("a@b.com", True, True), ("c@d.com", False, True)])
        (parseGithubEmails emailsJson)

    -- parseGithubEmails: empty array
    assertEqual
        "parseGithubEmails empty array"
        (Right ([] :: [(T.Text, Bool, Bool)]))
        (parseGithubEmails (Aeson.toJSON ([] :: [Value])))

    -- parseGithubEmails: not an array
    assertEqual
        "parseGithubEmails non-array returns error"
        (Left (GithubEmailsInvalid "expected a JSON array"))
        (parseGithubEmails (String "nope"))

    -- pickPrimaryEmail: single primary+verified
    assertEqual
        "pickPrimaryEmail single primary+verified"
        (Just "primary@example.com")
        (pickPrimaryEmail [("primary@example.com", True, True)])

    -- pickPrimaryEmail: no primary, one verified
    assertEqual
        "pickPrimaryEmail no primary, returns first verified"
        (Just "verified@example.com")
        ( pickPrimaryEmail
            [ ("unverified@example.com", False, False)
            , ("verified@example.com", False, True)
            ]
        )

    -- pickPrimaryEmail: none verified
    assertEqual
        "pickPrimaryEmail none verified returns Nothing"
        Nothing
        (pickPrimaryEmail [("a@b.com", False, False)])

    -- pickPrimaryEmail: empty list
    assertEqual
        "pickPrimaryEmail empty list returns Nothing"
        Nothing
        (pickPrimaryEmail [])

    -- pickPrimaryEmail: prefers primary+verified over just verified
    assertEqual
        "pickPrimaryEmail prefers primary+verified"
        (Just "p@example.com")
        ( pickPrimaryEmail
            [ ("v@example.com", False, True)
            , ("p@example.com", True, True)
            ]
        )

    -- buildGithubTokenForm
    let providerCfg =
            OAuthProviderConfig
                { oauthProviderName = "github"
                , oauthProviderClientId = "my-client-id"
                , oauthProviderClientSecret = "my-secret"
                , oauthProviderDiscoveryUrl = "https://github.com/.well-known/openid-configuration"
                }
        callbackUrl = "https://example.com/auth/v1/callback"
        authCode = "auth-code-xyz"
        form = buildGithubTokenForm providerCfg callbackUrl authCode
        lookupForm :: BS.ByteString -> Maybe T.Text
        lookupForm key = fmap TE.decodeUtf8 (lookup key form)
    assertEqual
        "buildGithubTokenForm client_id value"
        (Just "my-client-id")
        (lookupForm "client_id")
    assertEqual
        "buildGithubTokenForm client_secret value"
        (Just "my-secret")
        (lookupForm "client_secret")
    assertEqual
        "buildGithubTokenForm code value"
        (Just authCode)
        (lookupForm "code")
    assertEqual
        "buildGithubTokenForm redirect_uri value"
        (Just callbackUrl)
        (lookupForm "redirect_uri")
