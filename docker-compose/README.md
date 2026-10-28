# Run the Jamf collector with Docker Compose

The scheduler polls BloodHound Enterprise (BHE) for Jamf jobs. Starting the
container waits for a job; trigger an on-demand scan or schedule a collection
in BHE. Images support Linux AMD64 and ARM64 on Docker Engine for Linux and
Docker Desktop for macOS. No inbound ports are required. Allow outbound HTTPS
to your Jamf Pro server and BHE tenant.

## Prerequisites and configuration

Install Docker with the Compose plugin. Enable OpenHound in your BHE tenant,
install the Jamf extension assets, and create a dedicated Jamf OpenHound
collector client in BHE. Each deployment needs its own BHE collector client;
a general user's API token is not a replacement.

In Jamf Pro, configure an API client and API role with read access to the
resources this collector collects (including Classic API resources), or use
an account with equivalent permissions. Check permissions for accounts,
groups, computers, policies, scripts, sites, extension attributes, users,
API integrations, API roles, and SSO. Preflight does not check server privileges.

From the repository root:

```sh
cd docker-compose
cp .env.example .env
cp .dlt/config.toml.example .dlt/config.toml
cp .dlt/secrets.toml.example .dlt/secrets.toml
```

Expected local layout:

```text
docker-compose/
├── compose.yaml
├── check_config.py
├── .env
└── .dlt/
    ├── config.toml
    └── secrets.toml
```

Replace all placeholders in `.dlt/secrets.toml`:

| Setting | Required value |
| --- | --- |
| BHE `url` | HTTPS tenant origin, e.g. `https://example.bloodhoundenterprise.io` |
| BHE `token_id`, `token_key` | This deployment's Jamf OpenHound collector client credentials |
| Jamf `host` | HTTPS Jamf Pro origin, e.g. `https://example.jamfcloud.com`, without an API path |
| Jamf `client_id`, `client_secret` | Jamf API client credentials |

For account authentication, remove both `client_id` and `client_secret`, then
set `username` and `password` as shown in the example. Configure exactly one
complete authentication method. No credential files or private keys are
required. Keep `collector_name = "jamf"`; it identifies the installed entry point.
The Compose environment sets this value explicitly.

The `.dlt` bind mount is read-only. The container runs as UID/GID `65532`, so
that user must be able to read the mounted directory and files. On Linux and
macOS, protect the host files with an owner-only parent directory while
allowing reads inside the container:

```sh
chmod 700 .
chmod 755 .dlt
chmod 644 .dlt/config.toml .dlt/secrets.toml
```

On Linux with enforcing SELinux, apply the labels required by your host
policy to both bind mounts (`.dlt` and `check_config.py`). Compose's `bind.selinux`
option accepts `Z` for a private label or `z` when sharing the files between
containers. Do not relabel system directories. On Docker Desktop, ensure
this checkout is in a directory Docker can share.

## Preflight and startup

```sh
docker compose config --quiet
docker compose pull
docker compose run --rm --entrypoint python scheduler-jamf /opt/openhound-check-config.py
docker compose up -d scheduler-jamf
docker compose logs -f scheduler-jamf
```

The one-shot root `storage-init` service creates directories and assigns them
to UID/GID `65532` before the non-root scheduler runs. Preflight prints the
installed collector version, resolves the actual Jamf credential classes,
checks required values and HTTPS URLs, and verifies writable storage. It does
not contact Jamf or BHE or authenticate credentials. Do not use `--no-deps` on
the initial preflight: storage must be initialized first.

## Versions and updates

The default image is `ghcr.io/specterops/openhound-jamf:latest`. To pin a
release, set `OPENHOUND_IMAGE=ghcr.io/specterops/openhound-jamf:<version>` in
`.env`, substituting an available package version, for example `0.1.3`.
Container publishing begins with the release that introduces this workflow;
older package releases are not automatically backfilled. Version tags omit
the Git release tag's leading `v` and match the PyPI package version.

Use the scheduler image, without a `-cli` suffix. `latest` follows the newest
semantic release; a pinned version remains fixed. A running container does
not refresh automatically when `latest` changes. To update:

```sh
docker compose pull
docker compose up -d scheduler-jamf
```

## Storage and operations

| Named volume | Contents |
| --- | --- |
| `collector-data` | Working directory and `lookup.duckdb`, DLT state and pipelines, application logs under `/var/lib/openhound` |
| `raw-data` | Raw collection output under `/tmp/openhound` |

Compose explicitly sets `DLT_PROJECT_DIR=/app`, `DLT_DATA_DIR`, `PIPELINES_DIR`,
and `RUNTIME__LOG_PATH`. Lookup data stays in the persistent working directory.
Docker's JSON logs rotate at 10 MB with three files; application logs also
use OpenHound's rotation settings.

```sh
docker compose ps -a
docker compose logs --tail 100 scheduler-jamf
docker compose stop scheduler-jamf
docker compose down
```

Wait for an active collection to complete before stopping. Compose allows
45 seconds for graceful shutdown before forcing exit. Normal `down`, stop,
and container replacement preserve volumes. `docker compose down --volumes`
**deletes persisted state, lookup data, logs, and raw collection data**.

For multiple deployments, use a distinct BHE collector client and a distinct
Compose project name. Use `docker compose -p jamf-production ...` consistently
for every command for that deployment, and a separate configuration directory
and project name for each additional deployment.

## Troubleshooting

- **Missing value or placeholder:** replace example values and provide one
  complete Jamf authentication method; do not mix both methods.
- **File permissions or storage errors:** check UID/GID `65532`, the read-only
  `.dlt` mount, SELinux labels, and the `storage-init` service logs.
- **Jamf 401:** check client credentials or username/password, that account
  authentication is permitted by your Jamf server, and that `host` is the
  server origin without `/api` or `/JSSResource`.
- **Jamf 403 or missing resources:** confirm the API role/account has access
  to the required Jamf Pro and Classic API endpoints; successful login does
  not imply sufficient collection privileges.
- **BHE authentication fails:** check the tenant URL and the matching Jamf
  collector client's token ID/key. Use a dedicated client per deployment.
- **Scheduler stays idle:** initiate a job or configure a schedule in BHE.
- **Slow collection:** inspect logs for rate limiting and allow retries to finish.

Local configuration and credential files are ignored by Git. Only the safe
`.example` files belong in a commit.
