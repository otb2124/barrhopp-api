-- Baseline migration. Intentionally does not create domain tables yet
-- (Venue / VenueFact land in V2, once entities are designed) --
-- this just confirms the schema is in the expected starting state and
-- gives Flyway a V1 to anchor its history on.

-- Fail fast in any environment where the init script didn't run
-- (e.g. a Postgres instance that isn't the postgis/postgis image).
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_extension WHERE extname = 'postgis') THEN
        RAISE EXCEPTION 'PostGIS extension is not installed. Use the postgis/postgis Docker image, or run: CREATE EXTENSION postgis;';
    END IF;
END $$;
