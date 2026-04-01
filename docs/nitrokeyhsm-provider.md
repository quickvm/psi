# Nitrokey HSM Provider

The Nitrokey HSM provider encrypts secrets at store time and decrypts them at
container start using a Nitrokey HSM via PKCS#11. Secrets are stored as
encrypted blobs on disk — the plaintext never touches the filesystem.

## Prerequisites

- **Nitrokey HSM** plugged into host USB
- **pcscd container** running with USB access, sharing its socket via a
  named volume (e.g. `pcscd-socket` mounted at `/run/pcscd`)
- **RSA-2048 key pair** generated on the HSM (e.g. label `podman-secrets`,
  id `02`)
- **HSM PIN** stored securely — either in config, an env var, or encrypted
  with `systemd-creds` sealed to a TPM

### PIN Storage Options

| Method | Config | Security |
|---|---|---|
| systemd credential (TPM) | `LoadCredentialEncrypted=hsm-pin` on the service unit | PIN sealed to vTPM, only decryptable on this VM |
| Config file | `pin: "12345678"` in `providers.nitrokeyhsm` | Plaintext in config — acceptable for dev/isolated setups |
| Environment variable | `PSI_NITROKEYHSM_PIN=12345678` | Passed at runtime |

Resolution order: systemd credential → config → env var.

### Production PIN Setup (systemd-creds + TPM)

Encrypt the PIN once on the target host:

```bash
sudo systemd-ask-password "Enter HSM PIN:" | \
  sudo systemd-creds encrypt --with-key=tpm2 --name=hsm-pin - \
  /etc/credstore.encrypted/hsm-pin
```

The encrypted credential is only decryptable on this specific machine's TPM.

## Config

```yaml
providers:
  nitrokeyhsm:
    pkcs11_module: /usr/lib64/pkcs11/opensc-pkcs11.so
    slot: 0
    key_label: podman-secrets
    key_id: "02"
    # For dev/simple setups, set the PIN directly:
    # pin: "12345678"
```

## PSI Serve Startup

When `psi serve` starts, the Nitrokey HSM provider initializes:

1. **PIN resolution** — reads `$CREDENTIALS_DIRECTORY/hsm-pin` (set by
   systemd from `LoadCredentialEncrypted`), falls back to config `pin`
   field, then `PSI_NITROKEYHSM_PIN` env var
2. **PKCS#11 session** — loads the OpenSC module, opens a session on the
   configured slot via the pcscd socket, and logs in with the PIN
3. **Public key cache** — extracts the RSA public key from the HSM (or
   reads from a cached DER file) for software-side encryption
4. The session stays open for the lifetime of the serve process

### Serve Container Quadlet

The PSI serve container needs the pcscd socket volume and the systemd
credential:

```ini
[Container]
Image=ghcr.io/quickvm/psi:dev
Exec=serve
Volume=pcscd-socket:/run/pcscd:rw
Volume=/run/credentials/psi-secrets.service:/run/credentials:ro
Environment=CREDENTIALS_DIRECTORY=/run/credentials

[Service]
LoadCredentialEncrypted=hsm-pin
```

## Encrypting a Secret (Store)

```bash
echo -n "my-secret-value" | podman exec -i psi-secrets psi nitrokeyhsm store SECRET_NAME
```

What happens inside `Nitrokey HSMProvider.store()`:

1. Generate a random 32-byte AES-256 key
2. Generate a random 12-byte nonce
3. AES-256-GCM encrypt the plaintext → ciphertext + 16-byte auth tag
4. RSA-OAEP-SHA256 encrypt the AES key with the HSM's public key
   (software operation — no HSM round-trip needed)
5. Pack the envelope:
   `key_len(2B) || encrypted_aes_key(256B) || nonce(12B) || ciphertext || tag(16B)`
6. Base64-encode the envelope
7. Write a JSON mapping to `/var/lib/psi/SECRET_NAME`:
   ```json
   {"provider": "nitrokeyhsm", "blob": "<base64 envelope>"}
   ```
8. Set file permissions to `0600`

The plaintext is never written to disk. The encrypted blob is useless
without the HSM's private key.

## Decrypting a Secret (Lookup)

When a container starts and requests a secret via the podman shell driver:

```
Container start
  → Podman shell driver calls:
    curl --unix-socket /run/psi/psi.sock http://localhost/lookup/SECRET_NAME
```

What happens inside `Nitrokey HSMProvider.lookup()`:

1. Read the JSON mapping from `/var/lib/psi/SECRET_NAME`
2. Parse the `provider` field — dispatches to Nitrokey HSM
3. Base64-decode the blob
4. Unpack the envelope: extract `encrypted_aes_key`, `nonce`,
   `ciphertext+tag`
5. Send `encrypted_aes_key` to the HSM via PKCS#11 `C_Decrypt` with
   RSA-OAEP-SHA256 — the HSM's private key (which never leaves the
   hardware) decrypts the AES key on-chip
6. AES-256-GCM decrypt the ciphertext in software using the recovered
   AES key and nonce
7. Return plaintext bytes to Podman, which injects them into the
   container as an environment variable or file

## Security Model

| Component | Where | Protection |
|---|---|---|
| Encrypted blob | Disk (`/var/lib/psi/`) | Useless without HSM private key |
| RSA private key | Nitrokey HSM hardware | Never extractable, decrypts on-chip |
| RSA public key | Disk (cache) | Public — only enables encryption, not decryption |
| HSM PIN | TPM-sealed credential | Only decryptable on this specific VM's vTPM |

An attacker needs **all three** to recover a secret:

- The encrypted blob (disk access)
- The Nitrokey HSM (physical USB device)
- The PIN (sealed to this VM's TPM)

## CLI Commands

```bash
# Extract public key from HSM and cache locally
psi nitrokeyhsm init

# Encrypt a secret from stdin
echo -n "value" | podman exec -i psi-secrets psi nitrokeyhsm store SECRET_NAME

# Verify PIN resolution and HSM connectivity
psi nitrokeyhsm test-pin

# Show provider status (HSM connection, key info, cache)
psi nitrokeyhsm status
```

## Hybrid Encryption Rationale

RSA-2048 with OAEP-SHA256 can only encrypt up to 190 bytes directly.
Most secrets fit, but the hybrid scheme (RSA wraps an AES key, AES-GCM
encrypts the data) handles secrets of any length with no size limit.

The AES key is unique per secret — compromising one secret's envelope
does not help decrypt others.
