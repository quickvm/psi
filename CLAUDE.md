# psi — Podman Secret Infisical

## What this project does

`psi` is a Python CLI that fetches secrets from [Infisical](https://infisical.com) and injects them
into Podman containers at runtime via the
[shell secret driver](https://docs.podman.io/en/latest/markdown/podman-secret.1.html). It also
manages TLS certificates via Infisical's PKI API. No secret values are stored on disk — only
coordinate mappings (`project_alias:path:secret_name`) that tell the driver where to fetch each
secret when a container starts.

Primary target: Fedora CoreOS with Podman Quadlet, but works anywhere Podman runs.

## Architecture

Three runtime modes drive the design:

**Setup mode** (`psi setup`): Runs once at boot as a systemd oneshot. Authenticates to Infisical,
discovers secrets per workload config, registers coordinate mappings with Podman via
`podman secret create`, and generates systemd drop-in files.

**Driver mode** (`psi secret lookup`): Called by Podman at every container start. Reads the mapping
file for `SECRET_ID`, authenticates (or uses cached token), fetches the secret value from Infisical,
and writes raw bytes to stdout. Must be fast with minimal overhead.

**TLS mode** (`psi tls issue`/`psi tls renew`): Oneshot commands for certificate lifecycle. Issues
certs via Infisical PKI API, writes PEM files to disk, tracks state for renewal, and runs
post-renewal hooks (e.g., service restarts). Driven by systemd timers, not a daemon.

### Data flow

```
psi setup (boot):
  config.yaml → authenticate → list secrets per workload → podman secret create → drop-in files

psi secret lookup (container start):
  SECRET_ID env → read mapping file → resolve project → cached token → GET /api/v4/secrets/{name} → stdout

psi tls issue (boot or on-demand):
  config.yaml[tls] → authenticate → POST /api/v1/cert-manager/certificates → write PEM files → save state → run hooks

psi tls renew (systemd timer):
  load state → check expiry vs renew_before → POST .../certificates/{id}/renew → write files → update state → hooks
```

### Name collision handling

Podman secret names are global. Two workloads needing `DATABASE_HOST` from different projects would
collide. Solution: namespace as `{workload}--{SECRET_KEY}`. The systemd drop-in maps it back:

```
Secret=homeassistant--DATABASE_HOST,type=env,target=DATABASE_HOST
```

## Package layout

```
psi/
├── __init__.py     Version string
├── models.py       Pydantic models — AuthConfig, ProjectConfig, WorkloadConfig, SecretMapping, etc.
├── settings.py     PsiSettings (pydantic-settings) — YAML config + env vars + validation
├── auth.py         Auth dispatcher + 4 implementations (Universal, AWS IAM, GCP, Azure)
├── token.py        File-based token cache with per-auth-config keying (hashed filenames)
├── api.py          InfisicalClient — sync httpx client for Infisical REST API v4
├── secret.py       Podman shell driver commands (store/lookup/delete/list) + secret status
├── setup.py        Boot-time orchestration — discovery, registration, drop-in generation
├── tls.py          TLS certificate lifecycle — issue, renew, status, file output, hooks
├── systemd.py      Query systemd timer/unit status via subprocess + systemctl show
├── output.py       TTY-aware output — Rich tables for terminals, JSON for pipes
├── unitgen.py      Pure generators for systemd unit/quadlet file contents
├── installer.py    Orchestrate systemd unit installation (native + container modes)
└── cli.py          Typer CLI — thin wrappers over the above modules
```

### Module dependencies (import direction)

```
cli.py → settings.py, setup.py, secret.py, tls.py, api.py, output.py, systemd.py, installer.py
installer.py → unitgen.py, models.py, settings.py (TYPE_CHECKING)
unitgen.py → settings.py (TYPE_CHECKING)
setup.py → api.py, models.py, settings.py (TYPE_CHECKING)
tls.py → api.py, models.py, settings.py (TYPE_CHECKING)
secret.py → api.py, models.py, settings.py (TYPE_CHECKING)
api.py → auth.py, token.py, models.py (TYPE_CHECKING)
auth.py → models.py, httpx (TYPE_CHECKING)
token.py → models.py
settings.py → models.py
models.py → (no internal deps)
```

## Config file

Default: `/etc/psi/config.yaml` (override via `--config` or `PSI_CONFIG` env var).

```yaml
api_url: https://app.infisical.com
auth:
  method: aws-iam          # aws-iam | universal-auth | gcp | azure
  identity_id: "..."
state_dir: /var/lib/psi
systemd_dir: /etc/containers/systemd
token:
  ttl: 300
projects:
  myproject:
    id: "uuid"
    environment: prod
    auth: ...              # optional per-project override
workloads:                       # optional
  mycontainer:
    secrets:
      - project: myproject
        path: /mycontainer
tls:                             # optional
  certificates:
    myservice:
      project: myproject
      profile_id: "cert-profile-uuid"
      common_name: "myservice.example.com"
      ttl: "90d"
      renew_before: "30d"
      output:
        cert: /etc/myservice/tls/cert.pem
        key: /etc/myservice/tls/key.pem
        chain: /etc/myservice/tls/chain.pem
      hooks:
        - "systemctl restart myservice"
```

## Infisical API endpoints used

- Auth: `POST /api/v1/auth/{universal-auth,aws-auth,gcp-auth,azure-auth}/login`
- List secrets: `GET /api/v4/secrets` (with `recursive=true`)
- Get secret: `GET /api/v4/secrets/{secretName}`
- Issue cert: `POST /api/v1/cert-manager/certificates`
- Renew cert: `POST /api/v1/cert-manager/certificates/{id}/renew`

All require Bearer token in Authorization header.

## Podman shell driver interface

Podman calls `psi secret {store,lookup,delete,list}` with `SECRET_ID` in the environment.

- **store**: reads mapping bytes from stdin, writes to `{state_dir}/{SECRET_ID}`
- **lookup**: reads mapping, fetches secret from Infisical, writes value to stdout (binary)
- **delete**: removes mapping file
- **list**: prints all mapping filenames (one per line)

Driver commands must not produce Rich output — pure stdin/stdout/stderr protocol.

## Development

```bash
uv sync                    # install deps
uv run psi --help          # test CLI
uv run ruff check psi/     # lint
uv run ruff format psi/    # format
uv run ty check            # type check
uv run pytest              # tests
uv build                   # build wheel
```

### Key conventions

- All code must pass `ruff check`, `ruff format --check`, and `ty check` with zero errors
- Sync httpx everywhere (no async) — driver lookup is a single HTTP call
- `from __future__ import annotations` in all modules
- Runtime imports vs `TYPE_CHECKING` imports are separated per ruff TCH rules
- Use `NoReturn` for functions that always raise (e.g., `_fail()`) so ty narrows types after guard calls
- Models in `models.py` have zero internal dependencies — everything else imports from there
- Settings validation ensures workload and TLS certificate project references exist in the projects dict
- Use `# type: ignore[rule]` with justification comment for pydantic-settings internals ty can't introspect

### Adding a new auth method

1. Add variant to `AuthMethod` enum in `models.py`
2. Add validation case in `AuthConfig.validate_auth_fields`
3. Add implementation function in `auth.py`
4. Add case to `authenticate()` match statement

### Token caching

Tokens are cached at `{state_dir}/.token.{hash}.json` where hash is derived from the auth config
(`method + identity_id + client_id`). This supports mixed auth methods across projects without
collisions. TTL is capped by `token.ttl` config (default 300s).
