# Plan: Infisical through its SDK, then each cloud's secret store

Two changes, in this order. First, PSI stops maintaining its own Infisical client and uses
Infisical's Python SDK, so Infisical keeps the API and its logins current. Second, PSI learns
each cloud's secret store, read with the server's own identity, so a server on AWS, GCP or
Azure carries no credential in its user data.

Both serve qvm. qvm builds Fedora CoreOS servers from stacks whose secrets are references
(`${{ secrets.NAME }}`) resolved from a *store*: `env` and `infisical` first, then
`aws-secrets-manager`, `aws-parameter-store`, `gcp-secret-manager` and `azure-key-vault`, each
added with qvm's support for that cloud, and later `managed`, qvm.run's own store (qvm's
`docs/PLAN.md`, Phase 1 item 8 and Phases 2 and 3). PSI is how a server reads those secrets
when its containers start: qvm's `psi` layer writes PSI's config, and each qvm store kind is
a PSI provider of the same name.

## Where PSI is today

- **Providers** implement `name`, `open()`, `close()` and `lookup(mapping) -> bytes`
  (`psi/provider.py`); `create_provider` is an if/elif over `infisical` and `nitrokeyhsm`
  (`psi/providers/__init__.py`). A provider is enabled by its key under `providers:`.
- **Mappings** are one JSON file per Podman secret, naming the provider and where the value
  lives (`{"provider": "infisical", "project": "...", "path": "/app", "key": "DB_HOST"}`).
  serve dispatches each lookup on `provider`; the cache keys values by an HMAC of the mapping,
  so it is already provider-neutral.
- **Discovery is Infisical's**: `psi setup` lists each source's secrets
  (`_setup_infisical_workload` and `_fetch_and_register_infisical` in `psi/setup.py`),
  registers one Podman secret per key and writes `Secret=` drop-ins. The Nitrokey HSM
  provider has no discovery; its secrets are stored with `psi nitrokeyhsm store`.
- **Infisical's client is PSI's own**, on httpx: logins for universal auth, AWS IAM (PSI signs
  STS `GetCallerIdentity` with botocore against the global endpoint), GCP and Azure (instance
  metadata); `GET /api/v4/secrets` and `/api/v4/secrets/{name}`; folder, create, batch and
  update calls for the importer; and certificate issue and renew for `psi infisical tls`. The
  access token is cached in `state_dir` for `min(expiresIn, token.ttl)`.
- **serve is single-threaded**, so a lookup that waits on the network holds up every other.
- **Users**: qvm's CI runner runs `psi infisical env --project buildkite --path ...` from
  `ghcr.io/quickvm/psi`, pinned by digest in qvm's `.buildkite/runner.yaml`; the homelab and
  QuickVM's deploys run `psi setup` and serve.

## Part 1: Infisical through the SDK

`infisicalsdk` 1.0.17 imports and builds a client on Python 3.14. It offers
`InfisicalSDKClient(host, token, cache_ttl)`, logins for universal auth, AWS, OIDC, LDAP and a
token, `secrets.list_secrets` / `get_secret_by_name` / `create_` / `update_` /
`delete_secret_by_name`, folders, KMS and dynamic secrets. What it does not do decides most of
the work:

| Gap in the SDK (1.0.17) | What PSI does |
| --- | --- |
| A bare `requests.Session()`: no timeout, and up to 4 retries with backoff on every call | Mount an adapter with a default timeout on `client.api.session`, and make serve threaded (below) |
| No TLS settings; requests ignores `SSL_CERT_FILE`, which PSI's `ca_cert` sets today | Set `client.api.session.verify` from `ca_cert` and `verify_ssl` (`providers.infisical.ca_cert`, documented but never read, goes) |
| No GCP or Azure login | Keep PSI's two metadata logins and hand the token to the SDK (`token_auth.login`) |
| One token per client | One client per `AuthConfig.cache_key()`, as the token cache already keys |
| Tokens in memory only | Keep PSI's token file cache, fed by the login responses' `expiresIn` |
| Its own secret cache, 60 s by default, refreshed by a background thread | `cache_ttl=None`: PSI's encrypted cache is the only copy |
| No batch create | The importer creates secrets one at a time, paced by `fetch_delay_ms` |
| No certificate calls | See certificates below |
| v3 raw endpoints, with imports returned beside the secrets | Merge imports into the listing as `includeImports` did, and test it |
| AWS login signs the regional STS endpoint (region from `AWS_REGION` or IMDSv2) | Check the existing identities accept it before release, and say so in the docs |

- **Certificates.** Recommended: drop `psi infisical tls` and issue certificates over ACME from
  Infisical's cert-manager ACME directory, which QuickVM's `lago` and `next` deploys already
  use through Traefik's `caServer`; any ACME client on the server (Caddy, Traefik, lego) then
  does it, and PSI holds no certificate code. If a server needs PSI to issue them, the two
  certificate calls stay as the only part of PSI's client until the SDK has them. Either way
  the renew units go: they run `psi tls renew`, which does not exist (the command is
  `psi infisical tls renew`), and `tests/test_unitgen.py` asserts the wrong string.
- **Errors.** Lookup and setup map the SDK's `InfisicalError` status codes and requests'
  exceptions to PSI's: 404 for a missing secret, 502 for the provider failing, and the retry
  test in setup (`_is_retryable`) on requests' errors instead of httpx's.
- **Deleted**: the httpx client in `providers/infisical/api.py` (about 170 of its 309 lines)
  and the universal-auth and AWS logins in `auth.py` (about 65 lines, PSI's SigV4 signing
  with them). **Kept**: the config models, the token file cache, the GCP and Azure logins, the
  importer's logic and the CLI. httpx stays for PSI's own calls to Podman's socket.
- **Upstream.** Offer Infisical's SDK a timeout, a session or `verify` argument, GCP and Azure
  logins and certificates. Each one that lands deletes PSI's workaround for it.
- **Tests.** The Infisical tests patch httpx with `MagicMock` today. They move to a stand-in
  Infisical server on loopback (login, the secret list and get, folders, create), so they run
  the real SDK and its retries, and fail if a new SDK release changes what PSI relies on.
- **Docs.** `docs/infisical-provider.md`, the endpoint list and conventions in `CLAUDE.md`
  ("Sync httpx everywhere" becomes httpx for PSI's own calls and each vendor's SDK for its
  provider), and the README.
- **Release.** A new image, then a qvm pull request that moves the runner's pin to it once
  `psi infisical env` has fetched the pipeline's folder from the real instance; the homelab
  and QuickVM's deploys follow.

*Done when* every Infisical call goes through the SDK except the GCP and Azure logins (and the
certificate calls, if kept), the Infisical tests run against the stand-in server, and qvm's
runner fetches its pipeline secrets with the new image.

## Part 2: each cloud's secret store

1. **Discovery moves into the providers.** The protocol gains `discover(source)`, which lists
   a source's secrets as (name, mapping, value); setup's Infisical fetch path moves into the
   Infisical provider, and setup itself becomes generic: discover, register the Podman
   secrets, write the drop-ins, fill the cache. The Nitrokey HSM provider's discover finds
   nothing, as setup does for it today. `create_provider` becomes a registry, and a provider
   whose config fails to load is reported instead of stopping serve (today it is built
   outside the `try` in `open_all_providers`).
2. **A source per kind.** A workload's `secrets` take the shape of its provider's source:

   | Kind | Source | Name in the store |
   | --- | --- | --- |
   | `infisical` | project, path, `recursive`, `expand_references`, `include_imports` (as today) | the key |
   | `aws-secrets-manager` | region (default: the instance's), a name prefix (`qvm/web/`) or names | the part after the prefix |
   | `aws-parameter-store` | region, a path, read recursively, `SecureString` decrypted | the last path segment |
   | `gcp-secret-manager` | project, names or a label, version `latest` | the secret ID |
   | `azure-key-vault` | vault URL, names or a tag | the secret name, `-` read as `_` |

   Azure Key Vault names allow only letters, digits and dashes and ignore case, so
   `DB_PASSWORD` is stored as `DB-PASSWORD`. qvm's names never contain a dash, so the
   translation is one-to-one, and qvm uses the same rule.
3. **The server's own identity.** Each kind reads with its SDK's default credentials on the
   instance: boto3 with the instance profile (IMDSv2), google-auth with the metadata server,
   azure-identity's `ManagedIdentityCredential`. PSI's config holds no credential for these
   kinds; the role, service account or managed identity that qvm's IAM onboarding creates is
   what grants each server its own secrets and nothing else. Reading a cloud's store from
   outside that cloud is not a goal: a server off-cloud reads Infisical.
4. **Dependencies.** boto3 (already present through the Infisical SDK),
   `google-cloud-secret-manager` (with gRPC and protobuf) and `azure-keyvault-secrets` with
   `azure-identity`, each imported only inside its provider, as the HSM provider imports
   PyKCS11. The image ships all of them; check each on Python 3.14, measure the image, and
   split it per cloud only if its size hurts.
5. **Plumbing that is Infisical's alone today** becomes per provider: the refresh timer
   (`_REFRESHABLE_PROVIDERS` in `psi/unitgen.py`), `network-online.target` for setup units,
   and the CLI's `env` and `write-file`, which every network provider can offer.
6. **serve.** A lookup that misses the cache calls a store over the network, so serve's
   `_UnixHTTPServer` gains `socketserver.ThreadingMixIn` and each lookup a deadline: one slow
   store must not stop another workload's container from starting.
7. **Tests.** AWS through moto's in-process Secrets Manager and SSM; GCP and Azure through
   stand-ins at their clients' boundary. Each provider is tested on discovery, lookup, a
   missing secret, a denied read and an unreachable store. qvm's boot suite boots a server
   with the `psi` layer against a stand-in store.
8. **Order.** The protocol change first, with the Infisical provider moved onto it; then AWS,
   GCP and Azure, each landing with qvm's support for that cloud, so a provider is built when
   a server can use it. `managed` follows qvm.run.

*Done when* a server on each cloud starts its containers with secrets from that cloud's store,
read with its own identity, and its user data holds none.

## Open

- Certificates: ACME from Infisical's cert-manager (recommended), or PSI keeps its two
  certificate calls.
- Whether the cloud kinds read one key out of a JSON secret (an AWS Secrets Manager secret
  holding several values), or one secret per value only.
- The open bugs in `notes/` that this work touches: GCP and Azure metadata errors are not
  caught (`gcp-azure-metadata-http-error-uncaught.md`), and listing without `recursive`
  leaves drop-ins out of date (`list-secrets-non-recursive-drop-in-drift.md`). Fix them where
  the code moves.
