# psi — Podman Secret Infisical

Fetch [Infisical](https://infisical.com) secrets into [Podman](https://podman.io) containers at
runtime via the shell secret driver. No secrets are stored on disk — only coordinate mappings that
tell the driver where to fetch each secret from Infisical when a container starts.

Manage TLS certificates via Infisical PKI. Import existing secrets from Podman, env files, or
quadlet configurations into Infisical.

Built for [Fedora CoreOS](https://fedoraproject.org/coreos/) but works anywhere Podman runs.

## How it works

PSI runs a lightweight HTTP service on a Unix socket that handles secret lookups. The Podman shell
driver is configured to call this service via `curl` — no container spawned per lookup, just a fast
HTTP request to a local socket.

```
One time:
  psi install    → writes containers.conf.d/psi.conf (curl-based shell driver)

Boot time:
  psi serve      → starts the lookup service on /run/psi/psi.sock
  psi setup      → discovers secrets from Infisical, registers with Podman,
                   writes systemd drop-ins

Container start:
  Podman → Secret=atuin--DB_URI,type=env,target=DB_URI
         → shell driver calls: curl /run/psi/psi.sock/lookup/{secret_id}
         → PSI reads coordinate mapping from state_dir
         → fetches value from Infisical (token cached)
         → returns value to Podman → injected as env var
```

## Quick start (container mode on FCOS)

```bash
# 1. Create /etc/psi/config.yaml (see Configuration below)

# 2. Pull the PSI container image
sudo podman pull ghcr.io/quickvm/psi:latest

# 3. Install the shell driver config (one time)
sudo podman run --rm \
    -v /etc/psi:/etc/psi:ro \
    -v /var/lib/psi:/var/lib/psi:Z \
    -v /etc/containers/containers.conf.d:/etc/containers/containers.conf.d:Z \
    ghcr.io/quickvm/psi:latest install

# 4. Test authentication
sudo podman run --rm \
    --security-opt label=type:container_runtime_t \
    -v /etc/psi:/etc/psi:ro \
    -v /var/lib/psi:/var/lib/psi:Z \
    -v /etc/pki/tls/certs/ca-bundle.crt:/etc/ssl/certs/ca-certificates.crt:ro \
    -e SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt \
    --net=host \
    ghcr.io/quickvm/psi:latest login

# 5. Start the lookup service
sudo podman run -d --name psi-secrets \
    --security-opt label=type:container_runtime_t \
    -v /etc/psi:/etc/psi:ro \
    -v /var/lib/psi:/var/lib/psi:Z \
    -v /run/psi:/run/psi:Z \
    -v /etc/pki/tls/certs/ca-bundle.crt:/etc/ssl/certs/ca-certificates.crt:ro \
    -e SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt \
    --net=host \
    ghcr.io/quickvm/psi:latest serve

# 6. Discover and register secrets
sudo podman run --rm \
    --security-opt label=type:container_runtime_t \
    -v /etc/psi:/etc/psi:ro \
    -v /var/lib/psi:/var/lib/psi:Z \
    -v /etc/pki/tls/certs/ca-bundle.crt:/etc/ssl/certs/ca-certificates.crt:ro \
    -e SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt \
    -v /etc/containers/systemd:/etc/containers/systemd:Z \
    -v /run/podman/podman.sock:/run/podman/podman.sock:z \
    -v /run/dbus/system_bus_socket:/run/dbus/system_bus_socket \
    --net=host \
    ghcr.io/quickvm/psi:latest setup

# 7. Start your containers — secrets are fetched from Infisical
sudo systemctl start myapp-pod
```

### Quick start (native install)

```bash
# 1. Install PSI
uv tool install git+https://github.com/quickvm/psi.git

# 2. Create /etc/psi/config.yaml

# 3. Install the shell driver config
sudo psi install

# 4. Test authentication
sudo psi login

# 5. Start the lookup service and register secrets
sudo psi serve &
sudo psi setup

# 6. Start your containers
sudo systemctl start myapp-pod
```

### Quick start (rootless)

```bash
# 1. Install PSI and create ~/.config/psi/config.yaml

# 2. Install the shell driver config
psi install

# 3. Start the lookup service and register secrets
psi serve &
psi setup

# 4. Start your containers
systemctl --user start myapp-pod

# Enable lingering for headless/SSH users
loginctl enable-linger $USER
```

## Configuration

Create `/etc/psi/config.yaml` (system) or `~/.config/psi/config.yaml` (user):

```yaml
api_url: https://app.infisical.com

auth:
  method: universal-auth
  client_id: "your-client-id"
  client_secret: "your-client-secret"

projects:
  myproject:
    id: "infisical-project-uuid"
    environment: prod

workloads:
  myapp:
    unit: myapp.container
    secrets:
      - project: myproject
        path: /myapp
  myapp-database:
    unit: myapp-database.container
    secrets:
      - project: myproject
        path: /myapp
```

### Custom CA certificates

For self-hosted Infisical with a private CA, add `ca_cert` to the config:

```yaml
api_url: https://infisical.example.com
ca_cert: /etc/pki/tls/certs/ca-bundle.crt
```

When running PSI in a container, mount the CA bundle and set `SSL_CERT_FILE`:

```bash
-v /etc/pki/tls/certs/ca-bundle.crt:/etc/ssl/certs/ca-certificates.crt:ro \
-e SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt
```

For testing, you can disable TLS verification in the config (`verify_ssl: false`), but this is not
recommended for production.

### Auth methods

| Method | Config fields |
|--------|---------------|
| `universal-auth` | `client_id`, `client_secret` |
| `aws-iam` | `identity_id` |
| `gcp` | `identity_id` |
| `azure` | `identity_id` |

Per-project auth overrides are supported — add an `auth` block inside any project definition.

### Multi-project support

A single host can pull secrets from multiple Infisical projects:

```yaml
projects:
  infra:
    id: "project-a-uuid"
    environment: prod
  app:
    id: "project-b-uuid"
    environment: prod
    auth:
      method: universal-auth
      client_id: "..."
      client_secret: "..."

workloads:
  myapp:
    secrets:
      - project: infra
        path: /shared
      - project: app
        path: /myapp
```

### Name collision handling

Different projects may have secrets with the same name (e.g., `DATABASE_HOST`). PSI namespaces
Podman secret names as `{workload}--{SECRET_KEY}` and maps them back via the systemd drop-in:

```ini
[Container]
Secret=myapp--DATABASE_HOST,type=env,target=DATABASE_HOST
```

The container sees `DATABASE_HOST` — the namespace prefix is transparent.

## System vs user scope

PSI auto-detects whether to use system or user scope based on UID.

| Path | System (root) | User (non-root) |
|------|---------------|-----------------|
| Config | `/etc/psi/config.yaml` | `~/.config/psi/config.yaml` |
| State | `/var/lib/psi` | `~/.local/share/psi` |
| Socket | `/run/psi/psi.sock` | `$XDG_RUNTIME_DIR/psi/psi.sock` |
| Quadlets | `/etc/containers/systemd` | `~/.config/containers/systemd` |
| Units | `/etc/systemd/system` | `~/.config/systemd/user` |
| Driver conf | `/etc/containers/containers.conf.d` | `~/.config/containers/containers.conf.d` |

The socket is owned by root (system) or the user (rootless) with mode `0600`.

## CLI

```
psi serve                   Run the secret lookup service on a Unix socket
psi setup                   Discover secrets, register with Podman, generate drop-ins
psi install                 Generate containers.conf.d/psi.conf + state directory
psi login                   Test authentication
psi env                     Fetch secrets and print as environment variables
psi write-file              Fetch a secret and write it to a file
psi secret status           Show workload secrets status
psi import env-file         Import from KEY=VALUE env file
psi import podman-secret    Import from Podman secret store
psi import quadlet          Import from quadlet .container files
psi import workload         Import from a workload's configured unit file
psi tls issue               Issue all configured TLS certificates
psi tls renew               Renew certificates approaching expiry
psi tls status              Show certificate status and systemd timer info
psi systemd install         Generate systemd units (native or container mode)
```

All commands accept `--config/-c` or the `PSI_CONFIG` env var.

## Importing secrets

`psi import` writes secrets INTO Infisical from external sources. Use this to migrate existing
secrets from Podman, env files, or quadlet configurations.

### From quadlet files

The recommended import path — parses both `Environment=` and `Secret=` directives from `.container`
files. Use `--resolve-secrets` to resolve `Secret=` references via the Podman API and import the
actual values. Use `--emit-config` to print the workload config YAML to add to `config.yaml`.

```bash
psi import quadlet /etc/containers/systemd/myapp*.container \
  --project myproject --path /myapp --resolve-secrets --emit-config
```

When running in a container, mount the quadlet directory and the Podman socket. Use
`SecurityLabelType=container_runtime_t` for Podman socket access on SELinux systems:

```bash
sudo podman run --rm \
    --security-opt label=type:container_runtime_t \
    -v /etc/psi:/etc/psi:ro \
    -v /var/lib/psi:/var/lib/psi:Z \
    -v /etc/pki/tls/certs/ca-bundle.crt:/etc/ssl/certs/ca-certificates.crt:ro \
    -e SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt \
    -v /etc/containers/systemd:/etc/containers/systemd:ro \
    -v /run/podman/podman.sock:/run/podman/podman.sock:z \
    --net=host \
    ghcr.io/quickvm/psi:latest \
    import quadlet /etc/containers/systemd/myapp*.container \
      --project myproject --path /myapp --resolve-secrets
```

### From Podman secrets

```bash
# Import all podman secrets
psi import podman-secret --all --project myproject --path /myapp

# Import specific secrets
psi import podman-secret --name DB_PASS --name API_KEY --project myproject --path /myapp
```

### From env files

```bash
# From a file
psi import env-file /path/to/.env --project myproject --path /myapp

# From stdin
cat secrets.env | psi import env-file --project myproject --path /myapp
```

### Conflict handling

When a secret already exists in Infisical:

| Policy | Behavior |
|--------|----------|
| `fail` (default) | Exit with error |
| `skip` | Keep existing value |
| `overwrite` | Replace existing value |

Use `--dry-run` to preview what would happen — it checks existing secrets and reports "would
create", "would skip", or "would overwrite" for each secret.

## Writing secrets to files

For secrets that need to be files (CA certs, SSH keys, config files):

```bash
psi write-file CA_CERT /etc/ssl/ca.crt \
  --project myproject \
  --secret-path /certs \
  --base64 \
  --mode 0644
```

## Permissions

| Feature | Required Permissions |
|---------|---------------------|
| `psi setup`, `psi serve` (read secrets) | `secrets.read` |
| `psi import` (create new secrets) | `secrets.read`, `secrets.create` |
| `psi import --conflict overwrite` (update existing) | `secrets.read`, `secrets.create`, `secrets.edit` |
| `psi tls issue`, `psi tls renew` | Certificate authority permissions |

## TLS certificates

PSI manages TLS certificates via Infisical's PKI API. Certificates are issued and renewed as
oneshot operations.

### Configuration

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
sudo psi tls issue     # Issue certificates for the first time
psi tls status         # Check certificate status
sudo psi tls renew     # Renew certificates approaching expiry
```

Certificate state is tracked at `{state_dir}/tls/{name}.json`. If state is lost, re-run
`psi tls issue`.

## FCOS deployment

Use `psi systemd install` to generate systemd units that run PSI at boot:

```bash
# Container mode (FCOS)
sudo psi systemd install --mode container --image ghcr.io/quickvm/psi:latest --enable

# Native mode
sudo psi systemd install --mode native --enable
```

This generates:
- `psi-secrets.service` / `psi-secrets.container` — the long-running lookup service
- `psi-secrets-setup.service` / `psi-secrets-setup.container` — oneshot that runs `psi setup`
- `psi-tls-renew.service` + `psi-tls-renew.timer` — daily TLS renewal (if TLS is configured)

## License

MIT License - Copyright (c) 2026 QuickVM, LLC
