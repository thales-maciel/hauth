-- v0.1 bootstrap.
--
-- The auth schema and the migration tracking table (auth.schema_migrations)
-- are created by the runner prologue before any embedded migration runs, so
-- this file only needs to mark the bootstrap as complete. Real auth schema
-- content lands in issue #6.

DO $$ BEGIN END $$;
