# Verifying the skeleton

I couldn't run these myself — no Docker and no Maven Central access in this
sandbox — so please run them on your machine before trusting this compiles.

```bash
# 1. Start Postgres/PostGIS
docker compose up -d
docker compose logs db | grep -i postgis   # confirm the init script ran

# 2. Build (downloads deps on first run)
./mvnw clean compile        # or: mvn clean compile

# 3. Boot it — Flyway should run V1__baseline and the app should come up
#    on :8080 with no errors
./mvnw spring-boot:run

# 4. In another terminal:
curl http://localhost:8080/actuator/health
# expect: {"status":"UP"}
```

If `mvn spring-boot:run` fails, the most likely first-run issues are:
- **Flyway can't find PostGIS**: the init script only runs against an *empty*
  volume. If you'd already run `docker compose up` before `init-postgis.sql`
  existed, run `docker compose down -v` to wipe the volume and retry.
- **Port 5432 already in use**: something else on your machine is on that
  port — either stop it or remap `ports: ["5433:5432"]` in docker-compose.yml
  and update `DB_PORT` accordingly.

There's no Maven wrapper (`mvnw`) checked in yet — I didn't generate one since
I can't verify it against a real Maven install here. Run `mvn -N
io.takari:maven:wrapper -Dmaven=3.9.9` once to add it if you want `./mvnw`.
