-- Runs once, automatically, on first container start (postgres image convention:
-- anything in /docker-entrypoint-initdb.d/ executes only against an empty data volume).
-- Enables PostGIS before Flyway's baseline migration runs, since ST_DWithin/ST_Distance
-- (§4.2) and the geometry column on venues both depend on it existing first.
CREATE EXTENSION IF NOT EXISTS postgis;
