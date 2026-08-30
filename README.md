# podatek-license-worker

Stateless JVM HTTP service that injects the Plan 3 Minecraft license client into an
arbitrary plugin JAR using ASM bytecode manipulation, and returns an "injected base" JAR:
the client shaded + relocated under a random per-build package, `GeneratedConfig` rewritten
with the request's real values, and the host plugin's `onEnable`/`onDisable` hooked to drive
`PodatekLicense.init` / `shutdown`.

The worker is **stateless**: it never touches a DB or storage and never executes host plugin
code (static ASM analysis only). The Plan 3 client jar is baked into the image at
`libs/podatek-license-client-<ver>.jar`; its version is reported by `/healthz`.

## HTTP contract

### `POST /inject`
- **Auth:** `Authorization: Bearer <INJECT_WORKER_SECRET>` (401 otherwise).
- **Request:** `multipart/form-data`
  - `jar`: the master plugin jar (<= 100 MB).
  - `config`: a JSON text field:
    ```json
    {
      "baseUrl": "https://auth4.podatek.dev/api/license",
      "pluginId": "my-plugin-slug",
      "publicKeys": { "k1": "<base64 raw32>" },
      "activeKeyId": "k1",
      "licenseKeyFileName": "license.key"
    }
    ```
- **200:** `application/java-archive` (the injected-base bytes) plus audit headers:
  - `X-Inject-Hook-Mode: shim | asm-insert`
  - `X-Inject-Reloc-Prefix: <random package>`
  - `X-Inject-Build-Id: <uuid>`
  - `X-Inject-Warnings: <optional>`
- **Errors** (JSON `{ "error": "..." }`): `400` (no jar / no plugin.yml-main / bad config / malformed
  archive), `401` (bad secret), `413` (jar over 100 MB), `422` (paper-only plugin, or main class not
  injectable), `500`.

### `GET /healthz`
- `200 { "ok": true, "clientVersion": "<baked Plan 3 version>" }`.

## Configuration (env)
- `INJECT_WORKER_SECRET` — Bearer secret; must match the Next.js app. **Required.**
- `PORT` — listen port (default `8080`; Coolify injects it).

## Build & run locally
```bash
./gradlew clean build          # runs the JUnit suite
./gradlew shadowJar            # -> build/libs/podatek-license-worker-1.0.0-all.jar
INJECT_WORKER_SECRET=dev java -jar build/libs/*-all.jar
curl localhost:8080/healthz
```

## Docker
```bash
docker build -t plw .
docker run -e INJECT_WORKER_SECRET=x -p 8080:8080 plw
curl localhost:8080/healthz     # {"ok":true,"clientVersion":"1.0.0"}
```

## Bumping the Plan 3 client
Replace `libs/podatek-license-client-<ver>.jar` with the newer shaded client build, update the
`files(...)` dependency version in `build.gradle.kts`, rebuild the image, redeploy, then have the
admin "rebuild" injected bases for existing plugins. The client version is surfaced at `/healthz`
so a version drift between worker and app is detectable.

## Deploy (Coolify / Oracle)
Private endpoint (not public), reachable only from the Next.js app via `INJECT_WORKER_SECRET`.
Coolify builds from this repo's `Dockerfile`, health-check `GET /healthz`. See the `oracle` /
`go-live` skills for the actual deploy steps.
