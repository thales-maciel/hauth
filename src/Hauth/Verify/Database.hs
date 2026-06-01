module Hauth.Verify.Database (checks) where

import Control.Exception (SomeException, try)
import Data.List (sort, (\\))
import Data.Text (Text)
import qualified Data.Text as T
import Database.PostgreSQL.Simple (Only (..), fromOnly, query_)
import Hauth.Env (withDatabaseConnection)
import Hauth.Migrate (MigrationFile (..), embeddedMigrations)
import Hauth.Verify.Types (Check (..), CheckOutcome (..))

checks :: [Check]
checks =
    [ checkConfigParse
    , checkDatabaseConnect
    , checkDatabaseMigrations
    ]

checkConfigParse :: Check
checkConfigParse =
    Check
        { checkName = "config.parse"
        , checkLabel = "Config parsed"
        , checkRun = \_env -> pure CheckOk
        }

checkDatabaseConnect :: Check
checkDatabaseConnect =
    Check
        { checkName = "database.connect"
        , checkLabel = "Database connectivity"
        , checkRun = \env -> do
            result <- try @SomeException $
                withDatabaseConnection env \conn ->
                    query_ conn "SELECT 1" :: IO [Only Int]
            pure $ case result of
                Left err -> CheckFail (T.take 200 (T.pack (show err)))
                Right _ -> CheckOk
        }

checkDatabaseMigrations :: Check
checkDatabaseMigrations =
    Check
        { checkName = "database.migrations"
        , checkLabel = "Migration status"
        , checkRun = \env -> do
            result <- try @SomeException $
                withDatabaseConnection env \conn -> do
                    rows <- query_ conn "SELECT filename FROM auth.schema_migrations ORDER BY filename"
                    pure (fmap fromOnly rows :: [Text])
            case result of
                Left err -> pure $ CheckFail (T.take 200 (T.pack (show err)))
                Right applied -> pure (migrationOutcome applied)
        }

migrationOutcome :: [Text] -> CheckOutcome
migrationOutcome applied =
    let embeddedNames = sort (fmap migrationName embeddedMigrations)
        appliedSorted = sort applied
        unknown = appliedSorted \\ embeddedNames
        pending = embeddedNames \\ appliedSorted
     in if not (null unknown)
            then CheckFail ("applied migrations not in binary: " <> commaList unknown)
            else
                if null pending
                    then CheckOk
                    else CheckWarn (T.pack (show (length pending)) <> " pending: " <> commaList pending)

commaList :: [Text] -> Text
commaList = T.intercalate ", "
