# psi — Podman Secret Infisical

Fetch [Infisical](https://infisical.com) secrets into [Podman](https://podman.io) containers at
runtime via the shell secret driver, and manage TLS certificates via Infisical PKI. No secrets are
stored on disk — only coordinate mappings that tell the driver where to fetch each secret from
Infisical when a container starts.

Built for [Fedora CoreOS](https://fedoraproject.org/coreos/) but works anywhere Podman runs.

## How it works

```
Boot time: psi setup
  1. Reads /etc/psi/config.yaml
  2. Authenticates with Infisical (AWS IAM, Universal Auth, GCP, or Azure)
  3. Discovers secrets per workload from configured projects + folder paths
  4. Registers coordinate mappings with Podman (podman secret create)
  5. Generates systemd drop-in files to inject secrets into containers
  6. Reloads systemd

Container start: Podman calls psi secret lookup
  1. Reads the coordinate mapping for the requested secret
  2. Fetches the actual value from Infisical via REST API
  3. Returns it to Podman, which injects it as an env var
```

Secrets are fetched live at container start. The only thing persisted is
`project_alias:path:secret_name` — enough to know where to look, but not the value itself.

## Install

```bash
# Via uv from GitHub
uv tool install git+https://github.com/quickvm/psi.git

# Or use the container image
podman pull ghcr.io/quickvm/psi:latest
```

Requires Python 3.14+. Type checked with [ty](https://github.com/astral-sh/ty).

### Running in a container

When running psi in a container, mount the config file and state directory:

```bash
podman run --rm \
    -v /etc/psi/config.yaml:/etc/psi/config.yaml:ro \
    -v /var/lib/psi:/var/lib/psi:Z \
    ghcr.io/quickvm/psi:latest login
```

If your Infisical instance uses a private CA or self-signed certificate, mount the host CA bundle
and set `SSL_CERT_FILE`:

```bash
podman run --rm \
    -v /etc/psi/config.yaml:/etc/psi/config.yaml:ro \
    -v /var/lib/psi:/var/lib/psi:Z \
    -v /etc/ssl/certs/ca-certificates.crt:/etc/ssl/certs/ca-certificates.crt:ro \
    -e SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt \
    ghcr.io/quickvm/psi:latest login
```

For testing, you can disable TLS verification in the config (`verify_ssl: false`), but this is not
recommended for production.

## Configuration

Create `/etc/psi/config.yaml`:

```yaml
api_url: https://app.infisical.com

auth:
  method: aws-iam
  identity_id: "your-machine-identity-id"

state_dir: /var/lib/psi
systemd_dir: /etc/containers/systemd

token:
  ttl: 300

projects:
  myproject:
    id: "infisical-project-uuid"
    environment: prod

workloads:
  homeassistant:
    secrets:
      - project: myproject
        path: /homeassistant
      - project: myproject
        path: /shared
  traefik:
    secrets:
      - project: myproject
        path: /traefik
```

### Auth methods

| Method | Config fields |
|--------|---------------|
| `aws-iam` | `identity_id` |
| `universal-auth` | `client_id`, `client_secret` |
| `gcp` | `identity_id` |
| `azure` | `identity_id` |

Per-project auth overrides are supported — add an `auth` block inside any project definition.

### Multi-project support

A single host can pull secrets from multiple Infisical projects. Define each project with an alias,
then reference it in workload secret sources:

```yaml
projects:
  infra:
    id: "project-a-uuid"
    environment: prod
  certs:
    id: "project-b-uuid"
    environment: prod
    auth:
      method: universal-auth
      client_id: "..."
      client_secret: "..."

workloads:
  traefik:
    secrets:
      - project: infra
        path: /traefik
      - project: certs
        path: /
```

### Name collision handling

Different projects may have secrets with the same name (e.g., `DATABASE_HOST`). psi namespaces
Podman secret names as `{workload}--{SECRET_KEY}` and maps them back via the systemd drop-in:

```ini
[Container]
Secret=homeassistant--DATABASE_HOST,type=env,target=DATABASE_HOST
```

The container sees `DATABASE_HOST` — the namespace prefix is transparent.

## CLI

```
psi setup                   Discover secrets, register with Podman, generate drop-ins
psi secret store            Shell driver: store mapping (called by Podman)
psi secret lookup           Shell driver: fetch secret value (called by Podman)
psi secret delete           Shell driver: remove mapping (called by Podman)
psi secret list             Shell driver: list registered secrets (called by Podman)
psi secret status           Show workload secrets status (Rich table or JSON)
psi import env-file         Import from KEY=VALUE env file
psi import podman-secret    Import from Podman secret store
psi import quadlet          Import from quadlet .container files
psi import workload         Import from a workload's configured unit file
psi tls issue               Issue all configured TLS certificates
psi tls renew               Renew certificates approaching expiry
psi tls status              Show certificate status, expiry, and systemd timer info
psi write-file              Fetch a secret and write it to a file
psi login                   Test authentication
psi install                 Generate containers.conf.d/psi.conf + state directory
psi systemd install         Generate systemd units (native or container mode)
```

All commands accept `--config/-c` or the `PSI_CONFIG` env var (default: `/etc/psi/config.yaml`).

### Quick start

```bash
# 1. Install the Podman shell driver config
sudo psi install

# 2. Test authentication
psi login

# 3. Discover and register secrets
sudo psi setup

# 4. Start your containers — secrets are fetched automatically
sudo systemctl start homeassistant
```

### Writing secrets to files

For secrets that need to be files (CA certs, SSH keys, config files):

```bash
psi write-file CA_CERT /etc/ssl/ca.crt \
  --project myproject \
  --secret-path /certs \
  --base64 \
  --mode 0644
```

## Importing secrets

`psi import` writes secrets INTO Infisical from external sources. This is useful for migrating
existing secrets from Podman, env files, or quadlet configurations into Infisical.

### From an env file

```bash
# Import from a .env file
psi import env-file /path/to/.env --project myproject --path /myapp

# From stdin
cat secrets.env | psi import env-file --project myproject --path /myapp

# Preview without writing
psi import env-file .env --project myproject --path /myapp --dry-run
```

### From Podman secrets

```bash
# Import specific secrets
psi import podman-secret --name DB_PASS --name API_KEY --project myproject --path /myapp

# Import all podman secrets
psi import podman-secret --all --project myproject --path /myapp
```

### From quadlet files

```bash
# Import Environment= values from .container files
psi import quadlet /etc/containers/systemd/myapp.container --project myproject --path /myapp

# Also resolve Secret= references via podman inspect
psi import quadlet /etc/containers/systemd/*.container \
  --project myproject --path /myapp --resolve-secrets
```

### From workload config

If your workload has a `unit` field in the psi config, you can import directly from it:

```yaml
workloads:
  homeassistant:
    unit: homeassistant.container
    secrets:
      - project: myproject
        path: /homeassistant
```

```bash
# Reads the unit file and imports into the workload's configured project/path
psi import workload homeassistant

# Resolve Secret= refs too
psi import workload homeassistant --resolve-secrets
```

### Conflict handling

When a secret already exists in Infisical, the `--conflict` flag controls behavior:

| Policy | Behavior |
|--------|----------|
| `fail` (default) | Exit with error if any secret exists |
| `skip` | Keep the existing value, skip the import |
| `overwrite` | Replace the existing value |

### Environment override

By default, secrets are imported into the project's configured environment (e.g., `prod`).
Use `--environment` to override:

```bash
psi import env-file .env --project myproject --path /myapp --environment staging
```

## Permissions

psi requires an Infisical machine identity with appropriate permissions. The required permissions
depend on which features you use:

| Feature | Required Permissions |
|---------|---------------------|
| `psi setup`, `psi secret lookup` (read secrets) | `secrets.read` |
| `psi import` (create new secrets) | `secrets.read`, `secrets.create` |
| `psi import --conflict overwrite` (update existing) | `secrets.read`, `secrets.create`, `secrets.edit` |
| `psi tls issue`, `psi tls renew` | Certificate authority permissions |

For read-only operation (the default use case), a role with `secrets.read` on the relevant
environment and folder paths is sufficient. For importing, the identity also needs `secrets.create`
and optionally `secrets.edit`.

## TLS certificates

psi manages TLS certificates via Infisical's PKI API. Certificates are issued and renewed as
oneshot operations — no long-running daemon needed.

### Configuration

Add a `tls` section to your config:

```yaml
tls:
  certificates:
    traefik:
      project: myproject
      profile_id: "cert-profile-uuid"
      common_name: "traefik.example.com"
      alt_names:
        - type: dns_name
          value: "*.example.com"
      ttl: "90d"
      key_algorithm: EC_prime256v1
      output:
        cert: /etc/traefik/tls/cert.pem
        key: /etc/traefik/tls/key.pem
        chain: /etc/traefik/tls/chain.pem
        ca: /etc/traefik/tls/ca.pem
        mode: "0640"
      renew_before: "30d"
      hooks:
        - "systemctl restart traefik"
```

### Usage

```bash
# Issue certificates for the first time
sudo psi tls issue

# Check certificate status
psi tls status

# Renew certificates approaching expiry (run via systemd timer)
sudo psi tls renew
```

Certificate state (ID, serial, expiry) is tracked at `{state_dir}/tls/{name}.json` so renewals
use the Infisical renewal API directly. If state is lost, re-run `psi tls issue`.

## FCOS deployment

On Fedora CoreOS, install via Butane/Ignition and run `psi setup` as a oneshot systemd service
before your container workloads start:

```ini
[Unit]
Description=Setup Infisical secrets for Podman
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/local/bin/psi setup

[Install]
WantedBy=multi-user.target
```

For TLS certificate renewal, add a systemd timer:

```ini
# psi-tls-renew.service
[Unit]
Description=Renew TLS certificates via Infisical PKI

[Service]
Type=oneshot
ExecStart=/usr/local/bin/psi tls renew
```

```ini
# psi-tls-renew.timer
[Unit]
Description=Daily TLS certificate renewal check

[Timer]
OnCalendar=daily
Persistent=true

[Install]
WantedBy=timers.target
```

## License

MIT License - Copyright (c) 2026 QuickVM, LLC
