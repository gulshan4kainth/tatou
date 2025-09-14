# Tatou Security Hardening — Summary (2025-09-14)

This document summarizes the security-focused changes completed on 2025‑09‑13/14, including what changed, why it was necessary, and which files were modified.

## Highlights
- Enforced strong authentication and per-user authorization across sensitive routes.
- Eliminated shell execution and tightened file-system safety (uploads, path traversal).
- Hardened plugin loading and disabled it by default (`ENABLE_PLUGIN_LOAD=false`).
- Replaced predictable identifiers with cryptographically random tokens.
- Cleaned up Docker build/runtime to keep secrets out of images.
- Added database uniqueness constraints to prevent account ambiguity.

## Application Changes

### Authentication & Tokens
- Require Bearer token on protected routes with TTL via `itsdangerous`.
- Fail fast if `SECRET_KEY` is missing.
- Why: Prevent unauthenticated access and ensure tokens expire.
- Files: `server/src/server.py`.

### Authorization (Owner Checks)
- All document and version routes enforce `ownerid = :uid` (list, get, delete, watermark read/apply).
- Why: Stop Insecure Direct Object Reference (IDOR) attacks.
- Files: `server/src/server.py`.

### SQL Injection Mitigation
- Parameterized all SQL; removed string-concatenated queries and risky joins.
- Why: Prevent SQL injection.
- Files: `server/src/server.py`.

### File Upload & Path Safety
- Sanitize filenames using `secure_filename()`.
- Validate uploaded content as PDF by checking `%PDF-` header.
- Save under `STORAGE_DIR/files/u_<uid>/` and validate paths via a resolver that enforces containment.
- Why: Prevent path traversal, malicious uploads, and cross-tenant access.
- Files: `server/src/server.py`.

### Watermark Methods — No Shell
- Rewrote methods to pure Python; removed any `subprocess`/`shell=True`.
- Why: Eliminate command-injection/RCE paths.
- Files: `server/src/unsafe_bash_bridge_append_eof.py`, `server/src/add_after_eof.py`.

### Plugin Loader Hardening
- Disabled by default via `.env`/compose: `ENABLE_PLUGIN_LOAD=false`.
- Restricted load path to `STORAGE_DIR/files/plugins` with extension allowlist (`.pkl`, `.dill`).
- Prevent overwriting existing plugins; tightened error handling/logging.
- Why: Reduce risk from untrusted deserialization and path abuse.
- Files: `server/src/server.py`.

### Non-Predictable Links
- Version links are now cryptographically random instead of SHA1-derived.
- Why: Prevent enumeration/guessing of version resources.
- Files: `server/src/server.py`.

## Frontend Fixes
- Fixed upload form reset timing and improved error display.
- Ensured safer DOM text insertion (avoid injection into HTML).
- Why: Improve UX reliability and reduce client-side pitfalls.
- Files: `server/src/static/documents.html`.

## Infrastructure & Deployment
- Dockerfile: Removed `COPY flag`; rely on runtime mount.
- docker-compose: Mount `./flag` to `/app/flag:ro`; storage volume for `/app/storage`.
- `.env`: Document and provide defaults for `SECRET_KEY`, `TOKEN_TTL_SECONDS`, `STORAGE_DIR`, `ENABLE_PLUGIN_LOAD=false`.
- Why: Keep secrets out of images; consistent config.
- Files: `server/Dockerfile`, `docker-compose.yml`, `sample.env`, `.env`.

## Database Hardening
- Added unique index on `Users.login` (alongside email uniqueness).
- Added `Versions.created_at` with index `ix_Versions_created_at` for auditability and sorting.
- Widened `Versions.path` to `VARCHAR(1024)` to match `Documents.path` and avoid truncation.
- Added index `ix_documents_creation` on `Documents(creation)` for faster time-ordered queries.
- Why: Prevent duplicate usernames, improve performance, and ensure better auditability.
- Files: `db/tatou.sql` updated; apply one-time migrations on existing DBs (init SQL only runs on first boot).

## Git Hygiene
- `.gitignore` ignores `flag`. Upstream removed `server/flag` from history.
- Locally, you may keep non-committed flags; use `git update-index --skip-worktree flag` if needed.
- Why: Prevent accidental secret leaks.
- Files: `.gitignore` and local Git index state.

## Current Configuration Notes
- `.env` explicitly sets `ENABLE_PLUGIN_LOAD=false` (recommended for production):
  
  ```properties
  ENABLE_PLUGIN_LOAD=false
  ```

## Next Steps (Optional)
- Add `FLAG_PATH` environment variable support so the server can read a configurable secret path.
- Run the API smoke test suite to re-verify end-to-end behavior after changes.
- Add a `SECURITY.md` with threat model and secure development practices.

— End of summary —

## How We Did It (Step-by-step)

- Auth & Tokens
  - Implemented a `require_auth` decorator that validates a Bearer token using `itsdangerous.URLSafeTimedSerializer` with `TOKEN_TTL_SECONDS`.
  - Enforced presence of `SECRET_KEY`; app fails fast if missing to avoid running insecurely.
  - Touched routes: list/get/delete documents, list versions, create/read watermark, plugin load.

- Owner Authorization
  - Augmented SQL queries with `WHERE d.ownerid = :uid` (or equivalent join filters).
  - Removed reliance on `login` joins and ensured `uid` is sourced from the validated token.

- Safe File Handling
  - On upload: applied `secure_filename()`, created per-user directory `files/u_<uid>`, verified PDF header `%PDF-` before writing.
  - Centralized `_safe_resolve_under_storage(base=STORAGE_DIR, candidate)` to validate paths remain under storage; used before reading/sending files.

- Remove Shell Execution
  - Replaced any `subprocess` usage in watermark methods with pure Python byte operations.
  - Ensured read routines parse appended payloads safely and verify integrity (HMAC where applicable).

- Plugin Loading Controls
  - Added env gate `ENABLE_PLUGIN_LOAD=false` (default), checked early in the route.
  - Restricted load directory to `STORAGE_DIR/files/plugins` with extension allowlist (`.pkl`, `.dill`).
  - Prevented overwriting and improved error surfaces for invalid/untrusted payloads.

- Unpredictable Version Links
  - Generated random, URL-safe tokens using a cryptographic RNG instead of hashes based on document content.

- Docker & Secrets
  - Removed `COPY flag` from `server/Dockerfile`; mounted `./flag:/app/flag:ro` via `docker-compose.yml`.
  - Ensured `.env` provides `SECRET_KEY`, `TOKEN_TTL_SECONDS`, `STORAGE_DIR`, `ENABLE_PLUGIN_LOAD`.

## Per-file Changes (What and Why)

- `server/src/server.py`
  - Added `require_auth`, token verification, TTL enforcement.
  - Implemented `_safe_resolve_under_storage` for path containment.
  - Upload route: `secure_filename`, user-directory layout, PDF header check, metadata insert with parameter bindings.
  - List/Get/Delete document routes: `ownerid = :uid` guard; safe send file.
  - Versions: owner-constrained queries; random link generation.
  - Watermark create/read: owner checks; applicability validation via utils.
  - Plugin load: env-gated, path-restricted, extension-allowlisted; overwrite prevention.
  - Why: Remove IDOR, path traversal, predictable IDs, and unsafe dynamic loading.

- `server/src/unsafe_bash_bridge_append_eof.py`
  - Replaced shell append/read with pure Python append-after-EOF and read-tail logic.
  - Why: Remove command injection via shell.

- `server/src/add_after_eof.py`
  - Ensured payload HMAC + safe parse; no external processes.
  - Why: Integrity of watermark data and no shell usage.

- `server/src/static/documents.html`
  - Fixed form reference caching to avoid `currentTarget` null during async.
  - Improved error messages; escaped text content for safety.
  - Why: Reliability in UI flow and safer client output.

- `docker-compose.yml`
  - Added `ENABLE_PLUGIN_LOAD` env; mounted `./flag:/app/flag:ro`; storage volume.
  - Why: Keep plugins disabled by default; avoid secrets in images; persistent storage.

- `server/Dockerfile`
  - Removed `COPY flag`; kept editable install and source copy.
  - Why: Avoid build failures and secret leakage.

- `sample.env` and `.env`
  - Included/confirmed keys: `SECRET_KEY`, `TOKEN_TTL_SECONDS`, `STORAGE_DIR`, `ENABLE_PLUGIN_LOAD=false`.
  - Why: Clear configuration and secure defaults.

- `db/tatou.sql` (and live DB)
  - Enforced unique index on `Users.login`.
  - Added `Versions.created_at` with an index; widened `Versions.path` to 1024.
  - Added `Documents.creation` index.
  - Why: Prevent duplicates, enable better sorting/filtering, and avoid path truncation.

- `.gitignore` and Git state
  - Ensured `flag` ignored; used `skip-worktree` locally to prevent accidental commits.
  - Why: Protect secrets from version control.

## Verification & How to Reproduce

- Health check:
  - `curl http://localhost:5000/healthz`

- Create user and login:
  - POST `/api/create-user` with JSON `{login,email,password}`; then POST `/api/login` and store `token` from JSON response.

- Upload document:
  - Use Bearer token; upload a `.pdf` with `%PDF-` header; verify it appears under your user in `/api/list-documents`.

- Create/read watermark:
  - POST `/api/create-watermark` with your `document_id` and method; GET `/api/read-watermark` to verify retrieval, both requiring ownership.

- Plugin load (disabled):
  - Confirm 403/disabled unless `ENABLE_PLUGIN_LOAD=true` with valid, safe plugin files in the allowed path.

### Apply DB changes on an existing database

Use env vars, not hardcoded secrets:

```bash
# Check duplicates before adding unique login
docker compose exec db mariadb -u root -p"$MARIADB_ROOT_PASSWORD" tatou \
  -e "SELECT login, COUNT(*) AS c FROM Users GROUP BY login HAVING c>1;"

# Apply schema updates (run each as needed)
docker compose exec db mariadb -u root -p"$MARIADB_ROOT_PASSWORD" tatou \
  -e "ALTER TABLE Users ADD UNIQUE KEY uq_users_login (login);"

docker compose exec db mariadb -u root -p"$MARIADB_ROOT_PASSWORD" tatou \
  -e "ALTER TABLE Documents ADD KEY ix_documents_creation (creation);"

docker compose exec db mariadb -u root -p"$MARIADB_ROOT_PASSWORD" tatou \
  -e "ALTER TABLE Versions MODIFY COLUMN path VARCHAR(1024) NOT NULL;"

docker compose exec db mariadb -u root -p"$MARIADB_ROOT_PASSWORD" tatou \
  -e "ALTER TABLE Versions ADD COLUMN created_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6), ADD KEY ix_Versions_created_at (created_at);"
```