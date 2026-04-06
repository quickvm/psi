# PSI — Podman Secret Infrastructure

A universal [Podman](https://podman.io) shell secret driver with pluggable provider backends. Secrets
are fetched or decrypted at container start time — no plaintext on disk.

Built for [Fedora CoreOS](https://fedoraproject.org/coreos/) but works anywhere Podman runs.

## Providers

| Provider | How it works | Use case |
|----------|-------------|----------|
| **Infisical** | Fetches secrets from an [Infisical](https://infisical.com) instance at lookup time | Primary secret management for all services |
| **Nitrokey HSM** | Encrypts secrets at store time and decrypts via a [Nitrokey HSM](https://www.nitrokey.com/products/nitrokey-hsm-2) at lookup time | Bootstrap secrets that can't come from a secrets manager (e.g. Infisical's own credentials) |

Both providers run behind a single PSI serve process. Podman doesn't know or care which provider
handles a given secret — the JSON mapping stored in the state directory includes a `provider` field
that PSI uses to dispatch.

## How it works

PSI runs a lightweight HTTP service on a Unix socket. The Podman shell driver calls it via `curl` —
no container spawned per lookup, just a fast HTTP request to a local socket.

```
Boot time:
  psi serve                        → starts the lookup service on /run/psi/psi.sock
                                     opens all configured providers (Infisical client, HSM session)
  psi setup --provider nitrokeyhsm → registers HSM-backed workloads (instant, local-only)
  psi setup --provider infisical   → discovers secrets from Infisical, registers with Podman,
                                     writes systemd drop-ins (retries if Infisical is starting)

Container start:
  Podman → Secret=myapp--DB_HOST,type=env,target=DB_HOST
         → shell driver calls: curl /run/psi/psi.sock/lookup/{secret_id}
         → PSI reads JSON mapping from state_dir
         → dispatches to the correct provider (infisical or nitrokeyhsm)
         → returns decrypted/fetched value to Podman → injected as env var
```

## Quick start

### 1. Install

```bash
# Container mode (recommended for FCOS)
sudo podman pull ghcr.io/quickvm/psi:latest

# Native mode
uv tool install podman-secret-infrastructure
```

### 2. Configure

Create `/etc/psi/config.yaml`:

```yaml
state_dir: /var/lib/psi

providers:
  infisical:
    api_url: https://infisical.example.com
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
    provider: infisical
    unit: myapp.container
    depends_on: [psi-infisical-setup.service]
    secrets:
      - project: myproject
        path: /myapp
```

### 3. Install the shell driver

```bash
sudo psi install
```

This writes `containers.conf.d/psi.conf` which configures Podman's shell secret driver to talk to
PSI's Unix socket.

### 4. Start PSI and register secrets

```bash
# Generate and enable systemd units
sudo psi systemd install --mode container --image ghcr.io/quickvm/psi:latest --enable

# Or run manually
sudo psi serve &
sudo psi setup
```

### 5. Start your containers

```bash
sudo systemctl start myapp.service
```

Secrets are fetched from Infisical at container start time.

## Configuration

### Provider: Infisical

Fetches secrets from Infisical at lookup time. No secret values stored on disk.

```yaml
providers:
  infisical:
    api_url: https://app.infisical.com
    verify_ssl: true
    ca_cert: /etc/pki/tls/certs/ca-bundle.crt  # optional, for private CA
    token:
      ttl: 300  # auth token cache TTL in seconds
    auth:
      method: universal-auth
      client_id: "..."
      client_secret: "..."
    projects:
      myproject:
        id: "project-uuid"
        environment: prod
        auth:  # optional per-project override
          method: aws-iam
          identity_id: "..."
```

Auth methods: `universal-auth`, `aws-iam`, `gcp`, `azure`. Global auth covers all projects; per-project auth overrides it.

See the [Infisical provider reference](docs/infisical-provider.md) for the full documentation.

### Provider: Nitrokey HSM

Encrypts secrets with a Nitrokey HSM at store time. Decrypts via PKCS#11 at lookup time. Uses hybrid
encryption (AES-256-GCM + RSA-OAEP-SHA256) so secrets of any size are supported.

```yaml
providers:
  nitrokeyhsm:
    pkcs11_module: /usr/lib64/pkcs11/opensc-pkcs11.so
    slot: 0
    key_label: podman-secrets
    key_id: "02"
    pcscd_volume: pcscd-socket
    # PIN options (pick one):
    # pin: "12345678"                    # direct (dev/simple setups)
    # Or use systemd LoadCredentialEncrypted=hsm-pin for production (TPM-sealed)
    # Or set PSI_NITROKEYHSM_PIN env var
```

PIN resolution order: `$CREDENTIALS_DIRECTORY/hsm-pin` → config `pin` → `PSI_NITROKEYHSM_PIN` env var.

See the [Nitrokey HSM provider reference](docs/nitrokeyhsm-provider.md) for the full documentation.

### Workloads

Each workload specifies which provider handles its secrets:

```yaml
workloads:
  # Infisical workload — secrets discovered from Infisical API
  myapp:
    provider: infisical
    unit: myapp.container
    depends_on: [psi-infisical-setup.service]
    secrets:
      - project: myproject
        path: /myapp

  # Nitrokey HSM workload — secrets encrypted and stored via CLI
  infisical:
    provider: nitrokeyhsm
```

### Recursive secret listing

By default, each secret source only fetches secrets from its exact path. Set `recursive: true` to
include secrets from subfolders.

This matters when you use Infisical subfolders to scope secrets to different containers in the same
pod. Without the default `recursive: false`, listing `/windmill` would also return secrets from
`/windmill/server` and `/windmill/worker`, mixing secrets across containers.

```yaml
workloads:
  windmill-server:
    provider: infisical
    secrets:
      - project: homelab
        path: /windmill          # shared secrets (DB_HOST, REDIS_URL, etc.)
      - project: homelab
        path: /windmill/server   # server-specific (MODE=server)

  windmill-worker-1:
    provider: infisical
    secrets:
      - project: homelab
        path: /windmill          # same shared secrets
      - project: homelab
        path: /windmill/worker   # worker-specific (MODE=worker, NUM_WORKERS)
```

To pull an entire folder tree into a single workload:

```yaml
  myapp:
    provider: infisical
    secrets:
      - project: myproject
        path: /myapp
        recursive: true          # includes /myapp, /myapp/db, /myapp/cache, etc.
```

### Template units

Workload names ending with `@` are systemd template units. PSI registers secrets and generates a
single template-level drop-in that all instances inherit.

```yaml
workloads:
  windmill-worker@:
    provider: infisical
    depends_on: [psi-infisical-setup.service]
    secrets:
      - project: homelab
        path: /windmill
      - project: homelab
        path: /windmill/worker
```

This creates:
- Podman secrets: `windmill-worker@--DB_HOST`, `windmill-worker@--MODE`, etc.
- Drop-in: `windmill-worker@.container.d/50-secrets.conf`

All instances (`windmill-worker@1`, `windmill-worker@2`, ...) share the same secrets. Start as
many instances as needed — PSI doesn't need to know the instance names.

```bash
systemctl start windmill-worker@1.service
systemctl start windmill-worker@2.service
systemctl start windmill-worker@3.service
```

Template and regular workloads can coexist:

```yaml
workloads:
  windmill-server:
    provider: infisical
    secrets:
      - project: homelab
        path: /windmill
      - project: homelab
        path: /windmill/server

  windmill-worker@:
    provider: infisical
    secrets:
      - project: homelab
        path: /windmill
      - project: homelab
        path: /windmill/worker
```

### Workload dependencies

`depends_on` adds systemd ordering to generated drop-ins. Each entry becomes `After=` and `Wants=`
in the `[Unit]` section of `50-secrets.conf`. A common pattern:

```yaml
depends_on: [psi-infisical-setup.service]
```

### Secret naming

Podman secrets are namespaced per workload: `{workload}--{SECRET_KEY}`. The drop-in maps them back:

```ini
[Container]
Secret=myapp--DATABASE_HOST,type=env,target=DATABASE_HOST
```

The container sees `DATABASE_HOST` — the namespace prefix is transparent.

## Nitrokey HSM setup

The Nitrokey HSM provider requires a pcscd sidecar container to communicate with the USB smartcard. PSI
includes commands to set this up.

### 1. Set up pcscd sidecar

```bash
# Builds the pcscd container image and installs systemd quadlets
sudo psi nitrokeyhsm setup-pcscd

# Start it
sudo systemctl start pcscd.service
```

This builds a Fedora-based container with `pcsc-lite`, `ccid`, and `opensc`, creates a shared volume
for the pcscd socket, and installs quadlet units. Requires `setsebool -P container_use_devices=true`
on SELinux systems (the command checks and warns).

### 2. Run preflight checks

```bash
sudo psi nitrokeyhsm preflight
```

Checks: PKCS#11 module exists, pcscd socket present, PIN resolvable, HSM reachable, key exists,
state directory ready.

### 3. Initialize the public key cache

```bash
sudo psi nitrokeyhsm init
```

Extracts the RSA public key from the HSM and caches it locally for software-side encryption.

### 4. Store PIN securely (production)

```bash
# Encrypt the PIN sealed to the TPM (only decryptable on this machine)
sudo systemd-ask-password "HSM PIN:" | \
  sudo systemd-creds encrypt --with-key=tpm2 --name=hsm-pin - \
  /etc/credstore.encrypted/hsm-pin
```

Add to the PSI serve container's systemd unit:

```ini
[Service]
LoadCredentialEncrypted=hsm-pin

[Container]
Volume=/run/credentials/psi-secrets.service:/run/credentials:ro
Environment=CREDENTIALS_DIRECTORY=/run/credentials
Volume=pcscd-socket:/run/pcscd:rw
```

### 5. Encrypt secrets

```bash
echo -n "my-secret-value" | sudo podman exec -i psi-secrets psi nitrokeyhsm store MY_SECRET
```

### 6. Register with Podman

```bash
sudo podman secret create --driver shell MY_SECRET /var/lib/psi/MY_SECRET
```

The secret is now available to any container via `Secret=MY_SECRET,type=env,target=MY_SECRET`.

## System vs user scope

PSI auto-detects scope based on UID.

| Path | System (root) | User (non-root) |
|------|---------------|-----------------|
| Config | `/etc/psi/config.yaml` | `~/.config/psi/config.yaml` |
| State | `/var/lib/psi` | `~/.local/share/psi` |
| Socket | `/run/psi/psi.sock` | `$XDG_RUNTIME_DIR/psi/psi.sock` |
| Quadlets | `/etc/containers/systemd` | `~/.config/containers/systemd` |

## CLI

### Core commands

```
psi serve                         Run the secret lookup service
psi setup                         Discover secrets, register with Podman, generate drop-ins
psi setup --provider infisical    Setup only Infisical-backed workloads (with retry)
psi setup --provider nitrokeyhsm  Setup only Nitrokey HSM-backed workloads
psi install                       Generate containers.conf.d/psi.conf
psi systemd install               Generate systemd units (--mode native or container)
```

### Infisical provider

```
psi infisical login               Test authentication
psi infisical env                  Fetch secrets as environment variables
psi infisical write-file           Fetch a secret and write to a file
psi infisical tls issue            Issue TLS certificates
psi infisical tls renew            Renew certificates approaching expiry
psi infisical tls status           Show certificate status
psi infisical import env-file      Import from KEY=VALUE env file
psi infisical import podman-secret Import from Podman secret store
psi infisical import quadlet       Import from quadlet .container files
```

### Nitrokey HSM provider

```
psi nitrokeyhsm preflight            Check all prerequisites
psi nitrokeyhsm setup-pcscd          Set up the pcscd sidecar container
psi nitrokeyhsm init                 Extract and cache public key from HSM
psi nitrokeyhsm store                Encrypt a secret from stdin
psi nitrokeyhsm test-pin             Verify PIN resolution and HSM login
psi nitrokeyhsm status               Show HSM connection and key info
```

All commands accept `--config/-c` or the `PSI_CONFIG` env var.

## Importing secrets into Infisical

`psi infisical import` writes secrets INTO Infisical from external sources:

```bash
# From quadlet files (recommended)
psi infisical import quadlet /etc/containers/systemd/myapp*.container \
  --project myproject --path /myapp --resolve-secrets

# From Podman secrets
psi infisical import podman-secret --all --project myproject --path /myapp

# From env files
psi infisical import env-file .env --project myproject --path /myapp
```

Conflict handling: `--conflict fail` (default), `skip`, or `overwrite`. Use `--dry-run` to preview.

## TLS certificates

Manage TLS certificates via Infisical PKI:

```yaml
providers:
  infisical:
    # ... auth and projects ...
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
          renew_before: "30d"
          output:
            cert: /etc/traefik/tls/cert.pem
            key: /etc/traefik/tls/key.pem
            chain: /etc/traefik/tls/chain.pem
          hooks:
            - "systemctl restart traefik"
```

## FCOS deployment

```bash
# Container mode with systemd quadlets
sudo psi systemd install --mode container --image ghcr.io/quickvm/psi:latest --enable
```

Generates per-provider setup units based on configured providers:
- `psi-secrets.container` — long-running lookup service
- `psi-{provider}-setup.container` — oneshot per provider (e.g. `psi-infisical-setup`, `psi-nitrokeyhsm-setup`)
- `psi-tls-renew.timer` + service — daily TLS renewal (if configured)

The per-provider split allows independent systemd ordering. For example, Infisical
can depend on the HSM setup unit for its bootstrap secrets, while other services
depend on the Infisical setup unit:

```
pcscd.service (smartcard daemon for HSM access)
  → psi-secrets.service (opens HSM + Infisical providers)
    → psi-nitrokeyhsm-setup.service (instant, local-only)
      → infisical.service (gets HSM-decrypted bootstrap secrets)
        → psi-infisical-setup.service (queries Infisical API, retries on failure)
          → all other services
```

### pcscd sidecar in container mode

When using the Nitrokey HSM provider in container mode, pcscd must run as a
sidecar container with USB device access. PSI and pcscd communicate via a shared
Podman volume for the pcscd socket.

**Set up pcscd (one-time, on the host):**

```bash
sudo psi nitrokeyhsm setup-pcscd
sudo systemctl start pcscd.service
```

This builds a pcscd container image, creates a `pcscd-socket` volume, and
installs quadlet files (`pcscd.container`, `pcscd-socket.volume`).

**Configure PSI serve to use pcscd:**

The PSI serve container needs the pcscd socket volume and a systemd ordering
dependency:

```ini
# psi-secrets.container
[Unit]
After=network-online.target pcscd.service

[Container]
Volume=pcscd-socket:/run/pcscd:rw
```

**PIN delivery via TPM-sealed credential:**

```ini
[Service]
LoadCredentialEncrypted=hsm-pin

[Container]
Volume=/run/credentials/psi-secrets.service:/run/credentials:ro
Environment=CREDENTIALS_DIRECTORY=/run/credentials
```

See [Nitrokey HSM setup](#nitrokey-hsm-setup) for PIN encryption instructions.

**For Butane/Ignition deployments**, include the pcscd quadlet files in your
Butane config so they survive reprovision:

```yaml
- path: /etc/containers/systemd/pcscd-socket.volume
  contents:
    inline: |
      [Volume]
      VolumeName=pcscd-socket

- path: /etc/containers/systemd/pcscd.container
  contents:
    inline: |
      [Unit]
      Description=pcscd smartcard daemon for HSM access
      Before=psi-secrets.service

      [Container]
      ContainerName=pcscd
      Image=localhost/pcscd:latest
      AddDevice=/dev/bus/usb
      Volume=pcscd-socket.volume:/run/pcscd:rw

      [Service]
      Restart=on-failure

      [Install]
      WantedBy=multi-user.target
```

The pcscd container image (`localhost/pcscd:latest`) must be built on the host
before first boot via `psi nitrokeyhsm setup-pcscd`. It is not pulled from a
registry.

## License

MIT License - Copyright (c) 2026 QuickVM, LLC
