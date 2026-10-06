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

## Part 1: Infisical through the SDK (done, #41)

PSI talks to Infisical through `infisicalsdk` 1.0.17. `InfisicalClient` kept its interface, each
call taking a token from PSI's token file cache, so setup, the CLI, the importer and the
certificate code call it as before. What the SDK does not do decided the rest:

| Gap in the SDK (1.0.17) | What PSI does |
| --- | --- |
| A bare `requests.Session()`: no timeout, and up to 4 retries with backoff on every call | An adapter on the SDK's session gives every request a 30 s timeout; serve's threading is Part 2's |
| No TLS settings; requests ignores `SSL_CERT_FILE`, which PSI's container units set | The session verifies with `ca_cert` (documented before, now read), else `SSL_CERT_FILE`, else requests' own bundle; `verify_ssl: false` turns it off |
| No GCP or Azure login | PSI fetches the metadata token with httpx and posts it to Infisical's login through the SDK's request layer (`InfisicalSDKClient.api`) |
| No batch create, no certificate calls | Through the SDK's request layer too, so every call to Infisical shares one session |
| Tokens in memory only | PSI's token file cache, set on the client before each call |
| Its own secret cache, refreshed by a background thread | `cache_ttl=0`: PSI's encrypted cache is the only copy |
| v3 raw endpoints, with imports returned beside the secrets | PSI reads the folder's own secrets, as it did from v4 (it never merged imports) |
| AWS login signs the regional STS endpoint | Documented: an AWS identity in Infisical names its region's endpoint |

- **Errors** are `InfisicalAPIError`, a `ProviderError` with the HTTP status (None when
  Infisical could not be reached); lookup, setup's retries and the importer read the status.
- **Found in the SDK**: with no AWS credentials, its AWS login raises botocore's
  `NoCredentialsError` with a message it does not take, so the caller sees a `TypeError`; PSI
  checks for credentials first, as its own code did. (qvm found a second: an import's secrets
  are typed `BaseSecret` but arrive as dicts.) Both go upstream with a timeout, a `verify`
  argument, GCP and Azure logins and certificates; each that lands deletes PSI's workaround.
- **Found on the way**: the certificate renewal units ran `psi tls renew`, which does not
  exist, so renewals always failed; they run `psi infisical tls renew`, and a test runs each
  unit's command through psi's CLI. PyKCS11 1.5.18 does not build on Python 3.14, which had
  broken every build since CI's cached layers expired; PSI moved to 1.5.20.
- **Tests** run the real SDK against a stand-in Infisical where the adapter hands a request
  to the network, `psi infisical env` as qvm's CI runner runs it included.
- **Left**: qvm's runner moves its PSI pin to the new image once `psi infisical env` has
  fetched the pipeline's folder from the real instance; the homelab and QuickVM's deploys
  follow.

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

- Certificates: PSI keeps issuing them (through the SDK's request layer); ACME from
  Infisical's cert-manager would let any ACME client on the server do it instead.
- Whether the cloud kinds read one key out of a JSON secret (an AWS Secrets Manager secret
  holding several values), or one secret per value only.
- The open bug in `notes/` that Part 2 touches: listing without `recursive` leaves drop-ins out
  of date (`list-secrets-non-recursive-drop-in-drift.md`). (GCP and Azure metadata errors are
  caught since #41.)
