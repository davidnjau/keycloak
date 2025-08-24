# Keycloak + Spring Boot Reference Service

Production‑grade reference implementation for federated authentication and role‑based authorization with Keycloak and Spring Boot (Java 17). This repository is a multi‑module Maven project with an `auth` service (REST API) and a shared `common` module.

> **Elevator pitch:** Ship secure, token‑based auth fast. Containerized Keycloak, wired Spring Security, and ready‑to‑use endpoints for registration, login, and RBAC.

---

## Architecture at a glance

* **Keycloak** (containerized) – Identity Provider (OIDC). Backed by **PostgreSQL**.
* **auth** module – Spring Boot 3.2.x service exposing REST endpoints, validating JWTs, and enforcing roles.
* **common** module – Shareable dependencies and utilities.
* **Grant types** – Client Credentials (service‑to‑service) and Resource Owner Password Credentials for legacy flows (use with caution; prefer Authorization Code + PKCE for user login via frontends).

```
client → (Auth Code/Password) → Keycloak → JWT → Spring Boot Resource Server → RBAC
```

---

## Repository layout

```
keycloak/
  ├── pom.xml                 # parent POM (Spring Boot 3.2.2)
  ├── auth/
  │   ├── pom.xml             # service dependencies (Keycloak starter 20.0.3)
  │   ├── src/main/java/com/keycloak/auth/
  │   │   ├── UauthApplication.java
  │   │   ├── AuthController.java
  │   │   ├── AdminController.java        # sample RBAC endpoints
  │   │   ├── KeycloakConfig.java         # admin client bean
  │   │   ├── KeycloakProperties.java
  │   │   └── security/
  │   │       ├── SecurityConfig.java     # HTTP security rules / JWT wiring
  │   │       └── JwtConverter.java       # token → authorities converter
  │   ├── src/main/kotlin/com/keycloak/auth/DbDataClass.kt
  │   ├── src/main/resources/application.yml
  │   └── keycloak/
  │       ├── docker-compose.yaml         # Keycloak + Postgres (dev)
  │       └── .env                        # Keycloak bootstrapping vars
  └── common/
      └── pom.xml
```

---

## Technology stack

* **JDK:** 17
* **Build:** Maven
* **Spring:** Boot 3.2.x, Security, Actuator
* **Keycloak:** Server 23.x (Docker), Spring Boot Starter 20.0.3, Admin Client
* **Database (IdP):** Postgres 14 (for Keycloak)

> **Note on version alignment:** The Spring adapter (`keycloak-spring-boot-starter`) 20.x works with modern Keycloak servers, but always validate adapter/server compatibility. Pin both in lock‑step during upgrades.

---

## Quick start (local development)

### 1) Bring up Keycloak + Postgres (dev only)

From `keycloak/auth/keycloak`:

```bash
cp .env .env.local   # optional: customize credentials/ports
docker compose -f docker-compose.yaml --env-file .env up -d
# Keycloak will be available at http://localhost:8999 (proxied to container :8080)
```

Default admin credentials are defined in `.env` (`KEYCLOAK_ADMIN` / `KEYCLOAK_ADMIN_PASSWORD`).

### 2) Create realm & client

1. Sign in to Keycloak Admin Console → `http://localhost:8999`.
2. Create **Realm**: `keycloak-spring-boot-realm`.
3. Create **Client**: `keycloak-spring-boot-client`.

    * Access type: **Confidential** (not Public).
    * **Client Secret**: generate and copy.
    * Valid redirect URIs (if using browser flows): your app URLs.
4. Create **Realm Roles**: `admin`, `manager`, `user`.
5. (Optional) Map `preferred_username` as a token claim.

### 3) Configure the Spring service

Edit `auth/src/main/resources/application.yml`:

```yaml
server:
  port: 8099

keycloak:
  server-url: http://localhost:8999
  realm: keycloak-spring-boot-realm
  client-id: keycloak-spring-boot-client
  client-secret: <PUT_YOUR_CLIENT_SECRET_HERE>
  admin-username: keycloakadmin
  admin-password: keycloakpassword
  principle-attribute: preferred_username

spring:
  mvc:
    log-request-details: true
logging:
  level:
    org.springframework.security: DEBUG
```

> Prefer environment variables in production; avoid committing secrets.

### 4) Run the service

From repository root:

```bash
./mvnw -q -DskipTests package
cd auth
../mvnw spring-boot:run
```

Service available on `http://localhost:8099`.

---

## API surface

### Auth endpoints (sample)

* `POST /auth/register` – Registers a user in Keycloak.

    * Body (`application/json`):

      ```json
      {
        "username": "jdoe",
        "email": "jdoe@example.com",
        "password": "Passw0rd!",
        "firstName": "John",
        "lastName": "Doe"
      }
      ```
* `POST /auth/login` – Exchanges credentials for tokens (access/refresh). Returns a `TokenResponse`.
* `GET /auth/userinfo` – Proxy to OIDC userinfo (requires `Authorization: Bearer <token>`).

> The `KeycloakAuthService` demonstrates token acquisition, user creation via Admin API, and JWT verification.

### RBAC endpoints (examples)

* `GET /admin/dashboard` – requires role `admin`.
* `GET /admin/reports` – requires any of `admin`, `manager`.

Roles are expected as **realm roles**. In Spring, they are checked as `ROLE_admin`, `ROLE_manager`, etc.

### Curl examples

```bash
# 1) Login (password grant)
TOKEN=$(curl -s \
  -d "client_id=keycloak-spring-boot-client" \
  -d "client_secret=$CLIENT_SECRET" \
  -d "grant_type=password" \
  -d "username=jdoe" -d "password=Passw0rd!" \
  http://localhost:8999/realms/keycloak-spring-boot-realm/protocol/openid-connect/token \
  | jq -r .access_token)

# 2) Call a protected endpoint
curl -H "Authorization: Bearer $TOKEN" http://localhost:8099/admin/dashboard
```

---

## Security hardening (production)

* **TLS everywhere:** Terminate HTTPS at the ingress/controller or reverse proxy. Disable `KC_HTTP_ENABLED` and enforce HTTPS for Keycloak.
* **Confidential clients only:** For server‑side apps and APIs, use **Confidential** clients with strong secrets. Rotate secrets.
* **Use Authorization Code + PKCE** for browser/native apps (avoid password grant in production).
* **CORS & CSRF:** Configure CORS at the gateway/API. Prefer stateless JWT validation.
* **Token scopes & mappers:** Issue least‑privilege tokens. Map only required claims.
* **Clock skew:** Allow small tolerance for token validation across services.
* **Session & refresh tokens:** Tune lifetimes to balance UX and risk. Revoke on compromise.
* **Admin API:** Lock down Keycloak Admin Console and network access. Use service accounts for automation.

---

## Observability & ops

* **Health checks:** Enable Spring Boot Actuator (`/actuator/health`, `/actuator/info`).
* **Keycloak health:** Expose Keycloak health endpoints via ingress for platform readiness.
* **Structured logs:** Correlate request IDs across gateway → services → Keycloak.
* **Metrics:** Instrument auth success/fail rates, token issuance latency, and 401/403 counts.

---

## CI/CD guidelines

* Build once, promote across environments.
* Run unit tests and static analysis (SpotBugs, OWASP Dependency Check).
* Container image scanning for Keycloak and app images.
* Externalize configuration via environment and Kubernetes secrets.

---

## Troubleshooting playbook

* **401 Unauthorized**

    * Missing/expired token; wrong audience; realm mismatch. Confirm `iss` matches `server-url/realms/<realm>`.
* **403 Forbidden**

    * Token valid but role missing. Ensure realm role assignment and mapper → `roles` claim.
* **JWK retrieval errors** (e.g., `Couldn't retrieve remote JWK set`)

    * Verify Keycloak is reachable from the app. Check realm OpenID config `/.well-known/openid-configuration` and that the `jwks_uri` is accessible. Confirm HTTP→HTTPS proxies aren’t blocking.
* **405 Method Not Allowed** during token/userinfo calls

    * Ensure correct HTTP method (`POST` for token endpoint), correct URL paths, and no gateway method overrides.
* **Version drift**

    * Align Keycloak server and Spring adapter versions. Validate after upgrades.

---

## Environment variables (suggested mapping)

Map these to `application.yml` via Spring config:

| Env var                   | Purpose                             |
| ------------------------- | ----------------------------------- |
| `KEYCLOAK_SERVER_URL`     | e.g., `https://sso.example.com`     |
| `KEYCLOAK_REALM`          | Realm name                          |
| `KEYCLOAK_CLIENT_ID`      | Client ID                           |
| `KEYCLOAK_CLIENT_SECRET`  | Client secret (Confidential client) |
| `KEYCLOAK_ADMIN_USERNAME` | Admin bootstrap user                |
| `KEYCLOAK_ADMIN_PASSWORD` | Admin bootstrap password            |

Example JVM overrides:

```bash
java -jar app.jar \
  --keycloak.server-url=https://sso.example.com \
  --keycloak.realm=keycloak-spring-boot-realm \
  --keycloak.client-id=keycloak-spring-boot-client \
  --keycloak.client-secret=$CLIENT_SECRET
```

---

## Local development tips

* Use `http://localhost:8999/realms/<realm>/.well-known/openid-configuration` to discover endpoints.
* In Postman, set an **OAuth 2.0** token with the realm’s token URL.
* For role testing, create users and assign realm roles directly; re‑issue tokens after changes.

---

## Roadmap / Nice‑to‑haves

* Authorization Code + PKCE sample flow.
* Resource Server with `spring-boot-starter-oauth2-resource-server` (pure Spring validation of JWT).
* Integration tests with **Testcontainers** for Keycloak.
* Helm chart / K8s manifests for Keycloak and the service.

---

## License

MIT or as specified by the owning organization.

---

## Appendix A – Keycloak container (dev)

Key files under `auth/keycloak`:

* `docker-compose.yaml` – Spins up Postgres and Keycloak `quay.io/keycloak/keycloak:23.0.7` on `8999`.
* `.env` – DB and Keycloak bootstrap env vars. **Do not use in production as‑is.**

Bring up:

```bash
docker compose up -d
```

Tear down:

```bash
docker compose down -v
```

---

**Status:** Ready for integration. Drop‐in for greenfield projects or to standardize auth across services.
