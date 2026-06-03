module Spec.OAuth.GithubSpec (spec) where

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
import Test.Hspec (Spec, describe, it, shouldBe)

spec :: Spec
spec = do
    describe "githubProviderName" $ do
        it "githubProviderName is 'github'" $
            githubProviderName `shouldBe` "github"

    describe "parseGithubUser" $ do
        it "parseGithubUser with id and email" $ do
            let userWithEmail =
                    Aeson.object
                        [ "id" Aeson..= (1234 :: Int)
                        , "login" Aeson..= ("alice" :: T.Text)
                        , "email" Aeson..= ("a@b.com" :: T.Text)
                        ]
            parseGithubUser userWithEmail `shouldBe` Right ("1234", Just "a@b.com")

        it "parseGithubUser missing id returns GithubMissingId" $ do
            let userNoId =
                    Aeson.object
                        ["login" Aeson..= ("x" :: T.Text)]
            parseGithubUser userNoId `shouldBe` Left GithubMissingId

        it "parseGithubUser with id but no email returns Nothing email" $ do
            let userNoEmail =
                    Aeson.object
                        ["id" Aeson..= (99 :: Int)]
            parseGithubUser userNoEmail `shouldBe` Right ("99", Nothing)

        it "parseGithubUser with null email returns Nothing email" $ do
            let userNullEmail =
                    Aeson.object
                        [ "id" Aeson..= (42 :: Int)
                        , "email" Aeson..= Null
                        ]
            parseGithubUser userNullEmail `shouldBe` Right ("42", Nothing)

        it "parseGithubUser on non-object returns GithubUserInvalid" $
            parseGithubUser (String "oops")
                `shouldBe` Left (GithubUserInvalid "expected a JSON object")

    describe "parseGithubEmails" $ do
        it "parseGithubEmails valid array" $ do
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
            parseGithubEmails emailsJson
                `shouldBe` Right [("a@b.com", True, True), ("c@d.com", False, True)]

        it "parseGithubEmails empty array" $
            parseGithubEmails (Aeson.toJSON ([] :: [Value]))
                `shouldBe` Right ([] :: [(T.Text, Bool, Bool)])

        it "parseGithubEmails non-array returns error" $
            parseGithubEmails (String "nope")
                `shouldBe` Left (GithubEmailsInvalid "expected a JSON array")

    describe "pickPrimaryEmail" $ do
        it "pickPrimaryEmail single primary+verified" $
            pickPrimaryEmail [("primary@example.com", True, True)]
                `shouldBe` Just "primary@example.com"

        it "pickPrimaryEmail no primary, returns first verified" $
            pickPrimaryEmail
                [ ("unverified@example.com", False, False)
                , ("verified@example.com", False, True)
                ]
                `shouldBe` Just "verified@example.com"

        it "pickPrimaryEmail none verified returns Nothing" $
            pickPrimaryEmail [("a@b.com", False, False)]
                `shouldBe` Nothing

        it "pickPrimaryEmail empty list returns Nothing" $
            pickPrimaryEmail [] `shouldBe` Nothing

        it "pickPrimaryEmail prefers primary+verified" $
            pickPrimaryEmail
                [ ("v@example.com", False, True)
                , ("p@example.com", True, True)
                ]
                `shouldBe` Just "p@example.com"

    describe "buildGithubTokenForm" $ do
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

        it "buildGithubTokenForm client_id value" $
            lookupForm "client_id" `shouldBe` Just "my-client-id"

        it "buildGithubTokenForm client_secret value" $
            lookupForm "client_secret" `shouldBe` Just "my-secret"

        it "buildGithubTokenForm code value" $
            lookupForm "code" `shouldBe` Just authCode

        it "buildGithubTokenForm redirect_uri value" $
            lookupForm "redirect_uri" `shouldBe` Just callbackUrl
