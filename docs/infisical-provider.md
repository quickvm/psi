# Infisical Provider

The Infisical provider fetches secrets from an Infisical instance at
container start time. By default only coordinate mappings
(`{project, path, key}`) are stored on disk — secret values are fetched
live on each lookup.

If the [secret cache](secret-cache.md) is enabled, `psi-infisical-setup`
eagerly fetches every configured secret value during boot and stores the
encrypted bundle at `state_dir/cache.enc`. Lookups then resolve from
memory and survive provider outages. See `docs/secret-cache.md` for the
threat model and deployment walkthrough.

## Prerequisites

- **Infisical instance** running and accessible (e.g. `https://app.infisical.com` or a self-hosted URL)
- **Machine identity** configured in Infisical with access to the
  required projects and environments
- **PSI serve container** running with network access to the Infisical API

## Config

```yaml
providers:
  infisical:
    api_url: https://app.infisical.com
    verify_ssl: true
    token:
      ttl: 300  # seconds to cache auth tokens
    projects:
      myproject:
        id: "project-uuid"
        environment: prod
        auth:
          method: universal-auth
          client_id: "client-id"
          client_secret: "client-secret"

workloads:
  myapp:
    provider: infisical
    unit: myapp.container
    depends_on: [psi-infisical-setup.service]
    secrets:
      - project: myproject
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

Or via the systemd oneshot unit `psi-infisical-setup.service`.

What happens during `psi setup` for each Infisical workload:

1. **Discover** — for each secret source in the workload config, call
   the Infisical API to list secrets at that project/path
2. **Authenticate** — obtain a token (cached per auth config, refreshed
   on expiry) via the configured auth method
3. **Register** — for each discovered secret, create a Podman secret
   with the `shell` driver. The secret's content is a JSON mapping:
   ```json
   {"provider": "infisical", "project": "myproject", "path": "/myapp", "key": "DB_HOST"}
   ```
   This mapping is stored at `/var/lib/psi/{SECRET_ID}`.
4. **Generate drop-in** — write a systemd drop-in at
   `{workload}.container.d/50-secrets.conf` that maps each secret to an
   environment variable via `Secret=` directives
5. **Populate the cache** (cache enabled only) — each listed secret
   already carries its value in the API response, so setup also encrypts
   the full bundle with the configured cache backend and atomically
   writes `state_dir/cache.enc`. No extra API calls.

Only coordinates are registered with Podman. With the cache disabled, no
secret values touch disk. With the cache enabled, values are on disk but
encrypted by the TPM or HSM backend — see
[secret-cache.md](secret-cache.md) for the threat model.

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

What happens inside `_handle_lookup` in `psi/serve.py`:

1. Read the JSON mapping from `/var/lib/psi/{SECRET_ID}`
2. Parse the `provider` field
3. **If the cache is enabled and has this entry**, return the cached bytes
   immediately — no provider round trip, no crypto on the hot path. This
   is where provider-outage resilience comes from.
4. Otherwise dispatch to `InfisicalProvider.lookup()`, which resolves
   project/auth/token and calls
   `GET /api/v4/secrets/{key}?projectId=...&environment=...&secretPath=...`
5. On a cache miss that succeeded, insert the value into the in-memory
   cache and re-encrypt `cache.enc` so future lookups do not have to
   touch Infisical again.
6. Return the value bytes to Podman.

With the cache disabled, every container start is a live round trip — if
Infisical is down, the lookup fails and the container will not start.
With the cache enabled and populated, container starts continue to work
for as long as the in-memory dict has the entry, regardless of Infisical
availability.

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
          project: myproject
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

Hook entries are split into argv and executed directly without a shell. Keep
them as simple commands such as `"systemctl reload traefik.service"`; shell
operators like `&&`, `|`, or `>` are not supported.

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
psi infisical import env-file .env --project myproject --path /myapp

# From existing Podman secrets
psi infisical import podman-secret --all --project myproject --path /myapp

# From quadlet .container files
psi infisical import quadlet myapp.container --project myproject --path /myapp
```

## CLI Commands

```bash
# Test auth against Infisical
psi infisical login

# Fetch secrets as environment variables
eval "$(psi infisical env --project myproject --path /myapp)"

# Fetch secrets as KEY=VALUE (for env files)
psi infisical env --project myproject --path /myapp --format env > /run/app/env

# Write a single secret to a file
psi infisical write-file DB_CERT /etc/ssl/db.pem --project myproject

# TLS management
psi infisical tls issue
psi infisical tls renew
psi infisical tls status

# Import from external sources
psi infisical import env-file .env --project myproject --path /app
psi infisical import podman-secret --all --project myproject --path /app
psi infisical import quadlet app.container --project myproject --path /app
```

## Security Model

| Component | Where | Protection |
|---|---|---|
| Coordinate mappings | Disk (`/var/lib/psi/{SECRET_ID}`, mode `0600`) | Only contain project/path/key — no secret data |
| Auth credentials | Config file (`/etc/psi/config.yaml`) | `client_id`/`client_secret` or IAM role (no static creds) |
| Auth tokens | Disk (`/var/lib/psi/.token.{hash}.json`) | Short-lived (default 300s), per-auth keyed |
| Secret values (cache disabled) | Infisical server only, transient in `psi serve` memory during a lookup | Never written to disk |
| Secret values (cache enabled) | `state_dir/cache.enc`, encrypted by TPM or HSM backend | Opaque ciphertext — see [secret-cache.md](secret-cache.md) threat model |

With the cache disabled, secret values never touch the host filesystem —
they flow from Infisical API → PSI serve process → Podman → container
environment, entirely in memory. The trade-off is that an Infisical
outage stops every container from starting.

With the cache enabled, the plaintext trust boundary moves from
"Infisical server only" to "this host's TPM-sealed or HSM-wrapped
ciphertext on disk, plus `psi serve` process memory". See
[secret-cache.md](secret-cache.md) for a full analysis.
