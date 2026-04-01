# PSI — Podman Secret Infrastructure

## What this project does

PSI is a universal Podman shell secret driver with pluggable provider backends. It fetches or
decrypts secrets at container start time — no plaintext on disk.

Two providers:

- **Infisical** — fetches secrets from an Infisical instance at lookup time. Stores only coordinate
  mappings on disk (`project:path:key`), never secret values.
- **Nitrokey HSM** — encrypts secrets at store time with a Nitrokey HSM via PKCS#11 and decrypts at
  lookup time. Uses hybrid encryption (AES-256-GCM + RSA-OAEP-SHA256). The HSM's private key never
  leaves the hardware.

Primary target: Fedora CoreOS with Podman Quadlet, but works anywhere Podman runs.

## Architecture

PSI runs a lightweight HTTP service on a Unix socket (`/run/psi/psi.sock`). Podman's shell secret
driver calls it via `curl` — one HTTP request per secret lookup, no container spawned per lookup.

### Provider protocol

All providers implement `open()`, `close()`, and `lookup()`. The `open()`/`close()` pair manages
long-lived resources (HTTP clients, PKCS#11 sessions). In serve mode, `open()` is called once at
startup. In one-shot mode (direct `psi secret lookup`), they bracket each operation.

`delete` and `list` are generic filesystem operations on `state_dir/{SECRET_ID}` and don't vary
by provider.

### Mapping format

Secret mappings are JSON with a `provider` discriminator:

```json
{"provider": "infisical", "project": "myproject", "path": "/app", "key": "DB_HOST"}
{"provider": "nitrokeyhsm", "blob": "<base64-encoded hybrid ciphertext>"}
```

### Data flow

```
Boot:
  psi serve      → opens all configured providers (Infisical client, HSM session)
  psi setup      → discovers Infisical secrets, registers with Podman, writes drop-ins

Container start:
  Podman → shell driver → curl /run/psi/psi.sock/lookup/{SECRET_ID}
         → PSI reads JSON mapping from state_dir
         → dispatches to correct provider based on "provider" field
         → returns plaintext to Podman → injected as env var

Nitrokey HSM store:
  echo "value" | psi nitrokeyhsm store SECRET_NAME
         → encrypts with HSM public key (software AES-GCM + RSA-OAEP wrap)
         → writes encrypted blob to state_dir
         → register with: podman secret create --driver shell SECRET_NAME /var/lib/psi/SECRET_NAME
```

### Name collision handling

Podman secret names are namespaced per workload: `{workload}--{SECRET_KEY}`. The systemd drop-in
maps it back:

```ini
Secret=myapp--DATABASE_HOST,type=env,target=DATABASE_HOST
```

## Package layout

```
psi/
├── __init__.py                          Version string
├── provider.py                          SecretProvider Protocol + registry + parse_mapping()
├── models.py                            Generic models (SystemdScope, WorkloadConfig, etc.)
├── settings.py                          PsiSettings — YAML config with providers dict
├── secret.py                            Shell driver commands (store/lookup/delete/list)
├── serve.py                             HTTP server on Unix socket — dispatches to providers
├── setup.py                             Boot-time orchestration — provider-aware
├── output.py                            TTY-aware output (Rich tables or JSON)
├── systemd.py                           Query systemd timer/unit status
├── unitgen.py                           Generators for systemd unit/quadlet file contents
├── installer.py                         Orchestrate systemd unit installation
├── cli.py                               Typer CLI — core commands + provider subcommands
│
├── providers/
│   ├── __init__.py                      Provider factory (create_provider)
│   │
│   ├── infisical/
│   │   ├── __init__.py                  InfisicalProvider class
│   │   ├── api.py                       InfisicalClient (sync httpx)
│   │   ├── auth.py                      Auth methods (universal, aws-iam, gcp, azure)
│   │   ├── token.py                     File-based token cache with per-auth keying
│   │   ├── models.py                    AuthConfig, ProjectConfig, InfisicalConfig, TLS/Import models
│   │   ├── tls.py                       TLS certificate lifecycle
│   │   ├── importer.py                  Import from env files, podman secrets, quadlets
│   │   └── cli.py                       Infisical CLI commands (login, env, write-file, tls, import)
│   │
│   └── nitrokeyhsm/
│       ├── __init__.py                  NitrokeyHSMProvider class
│       ├── crypto.py                    Hybrid encryption (AES-256-GCM + RSA-OAEP-SHA256)
│       ├── pkcs11.py                    PKCS#11 session management via PyKCS11
│       ├── pin.py                       PIN resolution ($CREDENTIALS_DIRECTORY → config → env var)
│       ├── models.py                    NitrokeyHSMConfig
│       └── cli.py                       HSM CLI (preflight, setup-pcscd, init, store, status, test-pin)
```

### Module dependencies (import direction)

```
cli.py → settings.py, setup.py, secret.py, installer.py
         providers/infisical/cli.py, providers/nitrokeyhsm/cli.py

serve.py → provider.py (open_all_providers, parse_mapping, close_all_providers)
secret.py → provider.py (get_provider, parse_mapping)
setup.py → providers/infisical/ (InfisicalProvider, InfisicalConfig, resolve_auth)
provider.py → providers/__init__.py (create_provider)

providers/infisical/__init__.py → providers/infisical/api.py, models.py
providers/infisical/api.py → providers/infisical/auth.py, token.py
providers/infisical/cli.py → providers/infisical/api.py, models.py

providers/nitrokeyhsm/__init__.py → providers/nitrokeyhsm/crypto.py, pin.py, pkcs11.py, models.py
providers/nitrokeyhsm/crypto.py → cryptography (RSA-OAEP, AES-GCM)
providers/nitrokeyhsm/pkcs11.py → PyKCS11

models.py → (no internal deps)
settings.py → models.py
```

## Config file

Default: `/etc/psi/config.yaml` (override via `--config` or `PSI_CONFIG` env var).

```yaml
state_dir: /var/lib/psi
ca_cert: /etc/pki/tls/certs/ca-bundle.crt  # optional

providers:
  infisical:
    api_url: https://app.infisical.com
    verify_ssl: true
    token:
      ttl: 300
    auth:
      method: universal-auth
      client_id: "..."
      client_secret: "..."
    projects:
      myproject:
        id: "uuid"
        environment: prod

  nitrokeyhsm:
    pkcs11_module: /usr/lib64/pkcs11/opensc-pkcs11.so
    slot: 0
    key_label: podman-secrets
    key_id: "02"
    pcscd_volume: pcscd-socket
    # pin: "12345678"  # or use systemd LoadCredentialEncrypted=hsm-pin

workloads:
  myapp:
    provider: infisical
    unit: myapp.container
    depends_on: [psi-secrets-setup.service]
    secrets:
      - project: myproject
        path: /myapp
        # recursive: true       # set to include secrets from subfolders (default: false)
  infisical:
    provider: nitrokeyhsm
```

## CLI commands

```
# Core
psi serve                              Run the secret lookup service
psi setup                              Discover secrets, register, generate drop-ins
psi install                            Generate containers.conf.d/psi.conf
psi systemd install                    Generate systemd units

# Infisical provider
psi infisical login                    Test authentication
psi infisical env                      Fetch secrets as env vars
psi infisical write-file               Fetch a secret to a file
psi infisical tls issue/renew/status   TLS certificate management
psi infisical import env-file/podman-secret/quadlet

# Nitrokey HSM provider
psi nitrokeyhsm preflight              Check all prerequisites
psi nitrokeyhsm setup-pcscd            Set up pcscd sidecar container
psi nitrokeyhsm init                   Extract and cache public key from HSM
psi nitrokeyhsm store                  Encrypt a secret from stdin
psi nitrokeyhsm test-pin               Verify PIN resolution and HSM login
psi nitrokeyhsm status                 Show HSM connection and key info
```

## Development

```bash
uv sync                    # install deps
uv run psi --help          # test CLI
uv run ruff check psi/     # lint
uv run ruff format psi/    # format
uv run ty check            # type check
uv run pytest              # tests
```

### Key conventions

- All code must pass `ruff check`, `ruff format --check`, and `ty check` with zero errors
- Sync httpx everywhere (no async)
- `from __future__ import annotations` in all modules
- Runtime vs `TYPE_CHECKING` imports separated per ruff TCH rules
- Provider-specific models live in their provider's `models.py`, generic models in `psi/models.py`
- Nitrokey HSM provider uses lazy imports for `PyKCS11` and `cryptography` in the provider
  `__init__.py` so the CLI module loads without those deps present (they're imported inside methods)
- Generated systemd drop-ins use `Wants=` (not `Requires=`) to prevent cascade failures

### Adding a new provider

1. Create `psi/providers/newprovider/` with `__init__.py`, `models.py`, `cli.py`
2. Implement a class with `name`, `open()`, `close()`, `lookup(mapping_data)` methods
3. Add to `psi/providers/__init__.py` factory
4. Register CLI subcommand in `psi/cli.py`
5. Add config section under `providers.newprovider` in settings

### Adding a new Infisical auth method

1. Add variant to `AuthMethod` enum in `providers/infisical/models.py`
2. Add validation case in `AuthConfig.validate_auth_fields`
3. Add implementation function in `providers/infisical/auth.py`
4. Add case to `authenticate()` match statement

### Container builds

The Containerfile has two targets:

- **test** — extends the builder stage with dev deps (ruff, ty, pytest). Used in CI.
- **default** — Fedora-based runtime with opensc and pcsc-lite-libs for HSM support.

The runtime uses Fedora (not Debian) because the pcscd socket protocol requires matching
pcsc-lite library versions between the pcscd sidecar and client containers.

```bash
# Build test image
podman build -t psi:test --target test -f Containerfile .

# Build production image
podman build -t psi:prod -f Containerfile .

# Run checks in test container
podman run --rm -v "$PWD:/src:z" -w /src --entrypoint bash psi:test -c \
  "ruff check psi/ tests/ && ty check && pytest -q"
```

### Nitrokey HSM testing

The HSM provider can't be unit tested without hardware. The PKCS#11 and crypto modules are tested
via integration on a live host with a Nitrokey HSM connected. The `psi nitrokeyhsm preflight`
command validates the full chain.

## Infisical API endpoints used

- Auth: `POST /api/v1/auth/{universal-auth,aws-auth,gcp-auth,azure-auth}/login`
- List secrets: `GET /api/v4/secrets` (recursive)
- Get secret: `GET /api/v4/secrets/{secretName}`
- Create/batch/update: `POST/PATCH /api/v4/secrets/...`
- Folders: `POST /api/v1/folders`
- Certificates: `POST /api/v1/cert-manager/certificates`, `.../renew`

## Podman shell driver interface

Podman calls the shell driver commands with `SECRET_ID` in the environment:

- **store**: reads mapping bytes from stdin, writes to `{state_dir}/{SECRET_ID}`
- **lookup**: reads mapping, dispatches to provider, writes plaintext to stdout
- **delete**: removes mapping file
- **list**: prints all mapping filenames (one per line)

Driver commands must not produce Rich output — pure stdin/stdout/stderr protocol.

## Planned work

See `notes/` directory:

- `error-handling-cleanup.md` — eliminate stack traces, catch all errors with user-friendly messages
- `logging-with-loguru.md` — structured audit logging for compliance, replace console.print
