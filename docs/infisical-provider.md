# Infisical Provider

The Infisical provider fetches secrets from an Infisical instance at
container start time. No secret values are stored on disk — only
coordinate mappings that tell PSI where to fetch the real value.

## Prerequisites

- **Infisical instance** running and accessible (e.g. `https://infisical.inf7.dev`)
- **Machine identity** configured in Infisical with access to the
  required projects and environments
- **PSI serve container** running with network access to the Infisical API

## Config

```yaml
providers:
  infisical:
    api_url: https://infisical.inf7.dev
    verify_ssl: true
    token:
      ttl: 300  # seconds to cache auth tokens
    projects:
      homelab:
        id: "4cd8d50c-a987-4f87-a001-5a1950c84397"
        environment: homelab
        auth:
          method: universal-auth
          client_id: "3f90d6e5-..."
          client_secret: "cc68176587..."

workloads:
  myapp:
    provider: infisical
    unit: myapp.container
    depends_on: [psi-secrets-setup.service]
    secrets:
      - project: homelab
        path: /myapp
```

### Authentication Methods

| Method | Config Fields | Use Case |
|---|---|---|
| `universal-auth` | `client_id`, `client_secret` | Machine identities with static credentials |
| `aws-iam` | `identity_id` | EC2/ECS/Lambda with IAM roles |
| `gcp` | `identity_id` | GCE/GKE with service accounts |
| `azure` | `identity_id` | Azure VMs with managed identity |

Auth can be set globally (covers all projects) or per-project
(project-level overrides global).

```yaml
providers:
  infisical:
    # Global auth — used by any project that doesn't define its own
    auth:
      method: aws-iam
      identity_id: "..."

    projects:
      # Uses global auth
      infra:
        id: "uuid-1"
        environment: prod

      # Overrides with its own auth
      billing:
        id: "uuid-2"
        environment: prod
        auth:
          method: universal-auth
          client_id: "..."
          client_secret: "..."
```

## PSI Serve Startup

When `psi serve` starts, the Infisical provider initializes:

1. **Config validation** — verifies every project has auth coverage
   (own or global fallback)
2. **HTTP client** — creates an httpx client for API calls
3. The provider is ready. Auth tokens are obtained lazily on first
   lookup and cached for the configured TTL.

## Setup (Secret Discovery and Registration)

Before containers can request secrets, PSI discovers what secrets exist
in Infisical and registers them with Podman:

```bash
psi setup
```

Or via the systemd oneshot unit (`psi-secrets-setup.service`).

What happens during `psi setup` for each Infisical workload:

1. **Discover** — for each secret source in the workload config, call
   the Infisical API to list secrets at that project/path
2. **Authenticate** — obtain a token (cached per auth config, refreshed
   on expiry) via the configured auth method
3. **Register** — for each discovered secret, create a Podman secret
   with the `shell` driver. The secret's content is a JSON mapping:
   ```json
   {"provider": "infisical", "project": "homelab", "path": "/myapp", "key": "DB_HOST"}
   ```
   This mapping is stored at `/var/lib/psi/{SECRET_ID}`.
4. **Generate drop-in** — write a systemd drop-in at
   `{workload}.container.d/50-secrets.conf` that maps each secret to an
   environment variable via `Secret=` directives

No secret values touch disk during setup. Only the coordinates
(project, path, key) are stored.

### Secret Naming Convention

Podman secrets are namespaced per workload:

```
{workload_name}--{secret_key}
```

For example, workload `myapp` with secret `DB_HOST` becomes Podman
secret `myapp--DB_HOST`. The drop-in maps it back:

```ini
[Container]
Secret=myapp--DB_HOST,type=env,target=DB_HOST
```

## Fetching a Secret (Lookup)

When a container starts and requests a secret via the Podman shell driver:

```
Container start
  → Podman shell driver calls:
    curl --unix-socket /run/psi/psi.sock http://localhost/lookup/{SECRET_ID}
```

What happens inside `InfisicalProvider.lookup()`:

1. Read the JSON mapping from `/var/lib/psi/{SECRET_ID}`
2. Parse the `provider` field — dispatches to Infisical
3. Extract the coordinate: `project` alias, `path`, `key`
4. Resolve the project config and auth from settings
5. Obtain an auth token (from cache if valid, or re-authenticate)
6. Call the Infisical API:
   `GET /api/v4/secrets/{key}?projectId=...&environment=...&secretPath=...`
7. Return the secret value bytes to Podman

The secret value is fetched live from Infisical on every container start.
If Infisical is down, the lookup fails and the container won't start.

## Token Caching

Auth tokens are cached per auth configuration to avoid re-authenticating
on every lookup:

- Cache file: `/var/lib/psi/.token.{hash}.json`
- Hash is derived from the auth method + identity/client ID (first 12
  chars of SHA-256)
- TTL is `min(token_expires_in, config.token.ttl)` — defaults to 300s
- Expired tokens are re-authenticated automatically

## TLS Certificate Management

The Infisical provider includes optional TLS certificate lifecycle
management via Infisical PKI:

```yaml
providers:
  infisical:
    # ... auth and projects ...
    tls:
      certificates:
        web:
          project: homelab
          profile_id: "profile-uuid"
          common_name: "web.example.com"
          ttl: "90d"
          renew_before: "30d"
          output:
            cert: /etc/pki/tls/certs/web.pem
            key: /etc/pki/tls/private/web.key
            chain: /etc/pki/tls/certs/web-chain.pem
          hooks:
            - "systemctl reload traefik.service"
```

```bash
psi infisical tls issue    # Issue all configured certificates
psi infisical tls renew    # Renew certificates approaching expiry
psi infisical tls status   # Show certificate status
```

A daily timer (`psi-tls-renew.timer`) handles automatic renewal.

## Import

Migrate existing secrets into Infisical from external sources:

```bash
# From a .env file
psi infisical import env-file .env --project homelab --path /myapp

# From existing Podman secrets
psi infisical import podman-secret --all --project homelab --path /myapp

# From quadlet .container files
psi infisical import quadlet myapp.container --project homelab --path /myapp
```

## CLI Commands

```bash
# Test auth against Infisical
psi infisical login

# Fetch secrets as environment variables
eval "$(psi infisical env --project homelab --path /myapp)"

# Fetch secrets as KEY=VALUE (for env files)
psi infisical env --project homelab --path /myapp --format env > /run/app/env

# Write a single secret to a file
psi infisical write-file DB_CERT /etc/ssl/db.pem --project homelab

# TLS management
psi infisical tls issue
psi infisical tls renew
psi infisical tls status

# Import from external sources
psi infisical import env-file .env --project homelab --path /app
psi infisical import podman-secret --all --project homelab --path /app
psi infisical import quadlet app.container --project homelab --path /app
```

## Security Model

| Component | Where | Protection |
|---|---|---|
| Secret values | Infisical server only | Never written to disk — fetched live at lookup time |
| Coordinate mappings | Disk (`/var/lib/psi/`) | Only contain project/path/key — no secret data |
| Auth credentials | Config file (`/etc/psi/config.yaml`) | `client_id`/`client_secret` or IAM role (no static creds) |
| Auth tokens | Disk (cache) | Short-lived (default 300s), per-auth keyed |

The key property: **secret values never touch the host filesystem**. They
flow from Infisical API → PSI serve process → Podman → container
environment, entirely in memory.
