{-# LANGUAGE LambdaCase #-}

module Spec.CLISpec (spec) where

import Hauth.CLI (
    CliError (..),
    Command (..),
    HelpTopic (..),
    MigrateCommand (..),
    MigrateOptions (..),
    OutputFormat (..),
    Port (..),
    ServeOptions (..),
    VerifyOptions (..),
    parseCommand,
    resolveMigrateConfigPath,
    resolveServeConfigPath,
    resolveServePort,
    resolveVerifyConfigPath,
 )
import Test.Hspec (Spec, describe, it, shouldBe, shouldSatisfy)

spec :: Spec
spec = do
    describe "parseCommand top-level" $ do
        it "top-level help" $
            parseCommand ["--help"] `shouldBe` Right (Help TopLevelHelp)
        it "missing command" $
            parseCommand [] `shouldSatisfy` (\case Left CliError{} -> True; _ -> False)
        it "unknown command" $
            parseCommand ["wat"] `shouldSatisfy` (\case Left CliError{} -> True; _ -> False)

    describe "parseCommand serve" $ do
        it "serve default" $
            parseCommand ["serve"] `shouldBe` Right (Serve (ServeOptions Nothing Nothing))
        it "serve config" $
            parseCommand ["serve", "--config", "config.json"]
                `shouldBe` Right (Serve (ServeOptions (Just "config.json") Nothing))
        it "serve port" $
            parseCommand ["serve", "--port", "18080"]
                `shouldBe` Right (Serve (ServeOptions Nothing (Just (Port 18080))))
        it "serve config and port" $
            parseCommand ["serve", "--config=config.json", "--port=18080"]
                `shouldBe` Right (Serve (ServeOptions (Just "config.json") (Just (Port 18080))))
        it "bad port" $
            parseCommand ["serve", "--port", "nope"] `shouldSatisfy` (\case Left CliError{} -> True; _ -> False)

    describe "parseCommand migrate" $ do
        it "migrate status" $
            parseCommand ["migrate", "status"]
                `shouldBe` Right (Migrate (MigrateOptions Nothing) MigrateStatus)
        it "migrate up" $
            parseCommand ["migrate", "up"]
                `shouldBe` Right (Migrate (MigrateOptions Nothing) MigrateUp)
        it "migrate status --config" $
            parseCommand ["migrate", "status", "--config", "migrate.json"]
                `shouldBe` Right (Migrate (MigrateOptions (Just "migrate.json")) MigrateStatus)
        it "migrate up --config=" $
            parseCommand ["migrate", "up", "--config=migrate.json"]
                `shouldBe` Right (Migrate (MigrateOptions (Just "migrate.json")) MigrateUp)
        it "migrate up -c" $
            parseCommand ["migrate", "up", "-c", "migrate.json"]
                `shouldBe` Right (Migrate (MigrateOptions (Just "migrate.json")) MigrateUp)
        it "missing migrate subcommand" $
            parseCommand ["migrate"] `shouldSatisfy` (\case Left CliError{} -> True; _ -> False)
        it "unknown migrate subcommand" $
            parseCommand ["migrate", "wat"] `shouldSatisfy` (\case Left CliError{} -> True; _ -> False)
        it "migrate missing --config value" $
            parseCommand ["migrate", "up", "--config"] `shouldSatisfy` (\case Left CliError{} -> True; _ -> False)
        it "migrate unknown option" $
            parseCommand ["migrate", "up", "--bogus"] `shouldSatisfy` (\case Left CliError{} -> True; _ -> False)

    describe "resolveMigrateConfigPath" $ do
        it "migrate config path" $
            resolveMigrateConfigPath Nothing (MigrateOptions (Just "migrate.json"))
                `shouldBe` Right "migrate.json"
        it "migrate env config path" $
            resolveMigrateConfigPath (Just "env.json") (MigrateOptions Nothing)
                `shouldBe` Right "env.json"
        it "migrate option overrides env" $
            resolveMigrateConfigPath (Just "env.json") (MigrateOptions (Just "override.json"))
                `shouldBe` Right "override.json"

    describe "resolveServeConfigPath" $ do
        it "config path" $
            resolveServeConfigPath Nothing (ServeOptions (Just "config.json") Nothing)
                `shouldBe` Right "config.json"
        it "env config path" $
            resolveServeConfigPath (Just "env.json") (ServeOptions Nothing Nothing)
                `shouldBe` Right "env.json"

    describe "resolveServePort" $ do
        it "config port" $
            resolveServePort (Port 8080) Nothing (ServeOptions Nothing Nothing)
                `shouldBe` Right (Port 8080)
        it "env port" $
            resolveServePort (Port 8080) (Just "18081") (ServeOptions Nothing Nothing)
                `shouldBe` Right (Port 18081)
        it "option overrides env" $
            resolveServePort (Port 8080) (Just "18081") (ServeOptions Nothing (Just (Port 18082)))
                `shouldBe` Right (Port 18082)

    describe "parseCommand verify" $ do
        it "verify default" $
            parseCommand ["verify"]
                `shouldBe` Right (Verify (VerifyOptions Nothing FormatText))
        it "verify --config" $
            parseCommand ["verify", "--config", "config.json"]
                `shouldBe` Right (Verify (VerifyOptions (Just "config.json") FormatText))
        it "verify -c" $
            parseCommand ["verify", "-c", "config.json"]
                `shouldBe` Right (Verify (VerifyOptions (Just "config.json") FormatText))
        it "verify --config=" $
            parseCommand ["verify", "--config=config.json"]
                `shouldBe` Right (Verify (VerifyOptions (Just "config.json") FormatText))
        it "verify --format json" $
            parseCommand ["verify", "--format", "json"]
                `shouldBe` Right (Verify (VerifyOptions Nothing FormatJson))
        it "verify --format text" $
            parseCommand ["verify", "--format", "text"]
                `shouldBe` Right (Verify (VerifyOptions Nothing FormatText))
        it "verify --format=json" $
            parseCommand ["verify", "--format=json"]
                `shouldBe` Right (Verify (VerifyOptions Nothing FormatJson))
        it "verify --config and --format json" $
            parseCommand ["verify", "--config", "config.json", "--format", "json"]
                `shouldBe` Right (Verify (VerifyOptions (Just "config.json") FormatJson))
        it "verify help" $
            parseCommand ["verify", "--help"] `shouldBe` Right (Help VerifyHelp)
        it "verify unknown option" $
            parseCommand ["verify", "--bogus"] `shouldSatisfy` (\case Left CliError{} -> True; _ -> False)
        it "verify missing --config value" $
            parseCommand ["verify", "--config"] `shouldSatisfy` (\case Left CliError{} -> True; _ -> False)
        it "verify missing --format value" $
            parseCommand ["verify", "--format"] `shouldSatisfy` (\case Left CliError{} -> True; _ -> False)
        it "verify unknown format" $
            parseCommand ["verify", "--format", "xml"] `shouldSatisfy` (\case Left CliError{} -> True; _ -> False)

    describe "resolveVerifyConfigPath" $ do
        it "verify config path resolution" $
            resolveVerifyConfigPath Nothing (VerifyOptions (Just "config.json") FormatText)
                `shouldBe` Right "config.json"
        it "verify env config path" $
            resolveVerifyConfigPath (Just "env.json") (VerifyOptions Nothing FormatText)
                `shouldBe` Right "env.json"
        it "verify option overrides env" $
            resolveVerifyConfigPath (Just "env.json") (VerifyOptions (Just "override.json") FormatText)
                `shouldBe` Right "override.json"
