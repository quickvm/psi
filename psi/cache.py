"""In-memory secret cache with a single encrypted backing file.

Design:

- One file (``cache.enc``) holds the entire cache as an opaque blob.
- Decrypted at service startup, held as ``dict[str, bytes]`` in RAM for the
  lifetime of ``psi serve``. No crypto on the lookup hot path.
- Mutations (``set``, ``invalidate``) re-encrypt the full dict and atomically
  replace the file via :func:`psi.files.write_bytes_secure`.
- A :class:`threading.Lock` serializes concurrent writers; reads are lock-free
  under CPython's GIL.

Cache keys are HMAC-SHA256 of the secret's mapping JSON bytes, using a random
32-byte key generated once on first save and preserved across loads. Keying on
the mapping (provider coordinates) instead of Podman's hex secret ID means the
cache survives Podman's delete+create churn during setup runs — the same
mapping always produces the same cache key, regardless of which hex ID Podman
currently associates with it.

Serve checks the file mtime on each lookup and reloads in place when setup has
written a fresh version. No forced restart required after rotations.

On-disk envelope:

::

    magic       (4 bytes)    b"PSIC"
    version     (1 byte)     0x01
    backend_tag (1 byte)     0x01 = TPM, 0x02 = HSM
    payload     (variable)   backend-specific

Inside the decrypted payload is a JSON object::

    {"version": 2, "written_at": <unix_ts>,
     "hmac_key": "<base64 32 bytes>",
     "entries": {"<hmac-hex>": "<base64_value>"}}

Payload version 1 (legacy, keyed by Podman hex IDs) is accepted on load but
discarded — the next save writes version 2 with a freshly generated HMAC key.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
import secrets
import struct
import threading
import time
from typing import TYPE_CHECKING

from loguru import logger

from psi.errors import ProviderError
from psi.files import write_bytes_secure

if TYPE_CHECKING:
    from pathlib import Path

    from psi.cache_backends import CacheBackend

MAGIC = b"PSIC"
VERSION = 0x01
_HEADER_FMT = ">4sBB"
_HEADER_SIZE = struct.calcsize(_HEADER_FMT)
_PAYLOAD_VERSION = 2
_HMAC_KEY_BYTES = 32


class CacheError(ProviderError):
    """Raised when the cache file is malformed, tampered, or unreadable."""

    def __init__(self, message: str) -> None:
        super().__init__(message, provider_name="cache")


def read_header(path: Path) -> tuple[int, int]:
    """Read the envelope header without decrypting the payload.

    Used by ``psi cache status`` to report the on-disk version and backend tag
    without opening an HSM session or reading the TPM credential. Fast path —
    no crypto, no provider interaction.

    Returns:
        ``(version, backend_tag)`` as read from the file.

    Raises:
        CacheError: If the file is too short or has bad magic.
    """
    with path.open("rb") as f:
        raw = f.read(_HEADER_SIZE)
    if len(raw) < _HEADER_SIZE:
        msg = f"Cache file {path} is too short to contain a header"
        raise CacheError(msg)
    magic, version, backend_tag = struct.unpack(_HEADER_FMT, raw)
    if magic != MAGIC:
        msg = f"Cache file {path} has bad magic {magic!r}, expected {MAGIC!r}"
        raise CacheError(msg)
    return version, backend_tag


class Cache:
    """Single-file encrypted cache of secret values.

    The backend (TPM or HSM) is injected so the cache code is agnostic to how
    the key is protected. Tests use a ``FakeBackend`` with a fixed key.
    """

    def __init__(self, path: Path, backend: CacheBackend) -> None:
        self._path = path
        self._backend = backend
        self._entries: dict[str, bytes] = {}
        self._hmac_key: bytes = secrets.token_bytes(_HMAC_KEY_BYTES)
        self._lock = threading.Lock()
        self._loaded = False
        self._mtime_ns: int = 0

    @property
    def path(self) -> Path:
        """The backing file path."""
        return self._path

    @property
    def backend_tag(self) -> int:
        """The backend discriminator byte used in the envelope header."""
        return self._backend.tag

    def cache_key(self, mapping_bytes: bytes) -> str:
        """Compute the stable cache key for a secret's mapping JSON.

        HMAC-SHA256 over the raw mapping bytes with the cache's HMAC key. Two
        callers (setup writer, serve reader) that see the same mapping bytes
        produce identical cache keys, so the cache survives Podman's hex ID
        churn. The HMAC key is per-host (never leaves the cache file) so
        mapping hashes cannot be correlated across deployments.
        """
        return hmac.new(self._hmac_key, mapping_bytes, hashlib.sha256).hexdigest()

    def load(self) -> None:
        """Decrypt the backing file into memory.

        If the file is missing, start with an empty cache — ``save()`` will
        create it on the next mutation. If the file exists but is malformed or
        was written by a different backend, raise :class:`CacheError`.

        Legacy v1 payloads (hex-ID keyed) are silently discarded — the next
        save writes v2 with a freshly generated HMAC key. A legacy cache is
        indistinguishable from no cache at all; container startups during the
        transition fall through to the provider.
        """
        if not self._path.exists():
            logger.info("Cache file not found at {}, starting empty", self._path)
            self._entries = {}
            self._loaded = True
            return

        raw = self._path.read_bytes()
        self._mtime_ns = self._path.stat().st_mtime_ns
        if len(raw) < _HEADER_SIZE:
            msg = f"Cache file {self._path} is too short to contain a header"
            raise CacheError(msg)

        magic, version, backend_tag = struct.unpack(_HEADER_FMT, raw[:_HEADER_SIZE])
        if magic != MAGIC:
            msg = f"Cache file {self._path} has bad magic {magic!r}, expected {MAGIC!r}"
            raise CacheError(msg)
        if version != VERSION:
            msg = f"Cache file {self._path} uses unsupported version {version}"
            raise CacheError(msg)
        if backend_tag != self._backend.tag:
            msg = (
                f"Cache file {self._path} was written by backend tag {backend_tag:#x}, "
                f"but current backend is {self._backend.tag:#x}. "
                "Re-run 'psi cache init' with the correct backend or restore the key."
            )
            raise CacheError(msg)

        plaintext = self._backend.decrypt(raw[_HEADER_SIZE:])
        parsed = _parse_payload(plaintext)
        self._hmac_key = parsed.hmac_key
        self._entries = parsed.entries
        self._loaded = True
        logger.info("Loaded {} cache entries from {}", len(self._entries), self._path)

    def maybe_reload(self) -> bool:
        """Reload from disk if the backing file's mtime has changed.

        Called from the lookup hot path so serve picks up fresh entries
        written by setup without needing a process restart. A ``stat`` call
        is ~1μs on modern kernels; actual reload happens only when setup
        has finished a write.

        Returns:
            True if a reload happened, False otherwise.
        """
        try:
            current_mtime = self._path.stat().st_mtime_ns
        except FileNotFoundError:
            return False
        if current_mtime == self._mtime_ns:
            return False
        self.load()
        return True

    def save(self) -> None:
        """Encrypt the in-memory dict and atomically replace the backing file."""
        with self._lock:
            plaintext = _serialize_payload(self._entries, self._hmac_key)
            payload = self._backend.encrypt(plaintext)
            header = struct.pack(_HEADER_FMT, MAGIC, VERSION, self._backend.tag)
            write_bytes_secure(self._path, header + payload)
            self._mtime_ns = self._path.stat().st_mtime_ns

    def get(self, key: str) -> bytes | None:
        """Return the cached value for ``key``, or ``None`` on miss."""
        return self._entries.get(key)

    def set(self, key: str, value: bytes) -> None:
        """Insert or update ``key``. Does not persist; call :meth:`save`."""
        with self._lock:
            self._entries[key] = value

    def bulk_set(self, entries: dict[str, bytes]) -> None:
        """Replace all entries atomically. Does not persist; call :meth:`save`."""
        with self._lock:
            self._entries = dict(entries)

    def invalidate(self, key: str) -> bool:
        """Drop ``key`` from the cache. Returns True if it was present."""
        with self._lock:
            return self._entries.pop(key, None) is not None

    def clear(self) -> None:
        """Drop all entries. Does not persist; call :meth:`save`."""
        with self._lock:
            self._entries = {}

    def __contains__(self, key: object) -> bool:
        return key in self._entries

    def __len__(self) -> int:
        return len(self._entries)

    def entry_ids(self) -> list[str]:
        """Return a sorted snapshot of current entry IDs."""
        return sorted(self._entries)

    def close(self) -> None:
        """Release backend resources. The in-memory dict is left intact."""
        self._backend.close()


class _ParsedPayload:
    """Deserialized cache payload: the HMAC key and the entry dict."""

    __slots__ = ("entries", "hmac_key")

    def __init__(self, hmac_key: bytes, entries: dict[str, bytes]) -> None:
        self.hmac_key = hmac_key
        self.entries = entries


def _serialize_payload(entries: dict[str, bytes], hmac_key: bytes) -> bytes:
    payload = {
        "version": _PAYLOAD_VERSION,
        "written_at": int(time.time()),
        "hmac_key": base64.b64encode(hmac_key).decode("ascii"),
        "entries": {k: base64.b64encode(v).decode("ascii") for k, v in entries.items()},
    }
    return json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")


def _parse_payload(plaintext: bytes) -> _ParsedPayload:
    try:
        payload = json.loads(plaintext.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as e:
        msg = f"Cache payload is not valid UTF-8 JSON: {e}"
        raise CacheError(msg) from e

    if not isinstance(payload, dict):
        msg = "Cache payload must be a JSON object"
        raise CacheError(msg)

    version = payload.get("version")
    if version == 1:
        logger.info(
            "Cache payload is legacy v1 (hex-ID keyed) — discarding. "
            "Next setup run will repopulate with HMAC-keyed v2."
        )
        return _ParsedPayload(secrets.token_bytes(_HMAC_KEY_BYTES), {})
    if version != _PAYLOAD_VERSION:
        msg = f"Cache payload version {version} is unsupported (expected {_PAYLOAD_VERSION})"
        raise CacheError(msg)

    raw_hmac_key = payload.get("hmac_key")
    if not isinstance(raw_hmac_key, str):
        msg = "Cache payload 'hmac_key' must be a base64 string"
        raise CacheError(msg)
    try:
        hmac_key = base64.b64decode(raw_hmac_key, validate=True)
    except (ValueError, binascii.Error) as e:
        msg = f"Cache 'hmac_key' is not valid base64: {e}"
        raise CacheError(msg) from e
    if len(hmac_key) != _HMAC_KEY_BYTES:
        msg = f"Cache 'hmac_key' must be {_HMAC_KEY_BYTES} bytes, got {len(hmac_key)}"
        raise CacheError(msg)

    raw_entries = payload.get("entries")
    if not isinstance(raw_entries, dict):
        msg = "Cache payload 'entries' must be a JSON object"
        raise CacheError(msg)

    entries: dict[str, bytes] = {}
    for key, encoded in raw_entries.items():
        if not isinstance(key, str) or not isinstance(encoded, str):
            msg = "Cache entry keys and values must be strings"
            raise CacheError(msg)
        try:
            entries[key] = base64.b64decode(encoded, validate=True)
        except (ValueError, binascii.Error) as e:
            msg = f"Cache entry {key!r} has invalid base64: {e}"
            raise CacheError(msg) from e
    return _ParsedPayload(hmac_key, entries)
