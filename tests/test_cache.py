"""Unit tests for the single-file encrypted secret cache."""

from __future__ import annotations

import os
import struct
import threading
from typing import TYPE_CHECKING

import pytest
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from psi.cache import MAGIC, VERSION, Cache, CacheError
from psi.cache_backends import HSM_BACKEND_TAG, TPM_BACKEND_TAG

if TYPE_CHECKING:
    from pathlib import Path

_FIXED_KEY = bytes(range(32))
_FIXED_NONCE = b"\x00" * 12


class FakeBackend:
    """Deterministic AES-256-GCM backend for tests (no TPM, no HSM)."""

    def __init__(self, tag: int = TPM_BACKEND_TAG, key: bytes = _FIXED_KEY) -> None:
        self.tag = tag
        self._key = key
        self.close_calls = 0

    def encrypt(self, plaintext: bytes) -> bytes:
        nonce = os.urandom(12)
        return nonce + AESGCM(self._key).encrypt(nonce, plaintext, None)

    def decrypt(self, payload: bytes) -> bytes:
        nonce, ciphertext = payload[:12], payload[12:]
        return AESGCM(self._key).decrypt(nonce, ciphertext, None)

    def close(self) -> None:
        self.close_calls += 1


@pytest.fixture
def backend() -> FakeBackend:
    return FakeBackend()


@pytest.fixture
def cache(tmp_path: Path, backend: FakeBackend) -> Cache:
    return Cache(tmp_path / "cache.enc", backend)


class TestLoadAndSave:
    def test_load_missing_file_starts_empty(self, cache: Cache) -> None:
        cache.load()
        assert len(cache) == 0

    def test_save_creates_file_with_restrictive_mode(self, cache: Cache) -> None:
        cache.set("db_password", b"hunter2")
        cache.save()
        assert cache.path.exists()
        assert oct(cache.path.stat().st_mode & 0o777) == "0o600"

    def test_roundtrip(self, tmp_path: Path) -> None:
        backend = FakeBackend()
        cache = Cache(tmp_path / "cache.enc", backend)
        cache.set("a", b"value-a")
        cache.set("b", b"\x00\x01\x02")
        cache.save()

        reloaded = Cache(tmp_path / "cache.enc", FakeBackend())
        reloaded.load()
        assert reloaded.get("a") == b"value-a"
        assert reloaded.get("b") == b"\x00\x01\x02"
        assert len(reloaded) == 2

    def test_empty_cache_roundtrip(self, tmp_path: Path) -> None:
        cache = Cache(tmp_path / "cache.enc", FakeBackend())
        cache.save()
        reloaded = Cache(tmp_path / "cache.enc", FakeBackend())
        reloaded.load()
        assert len(reloaded) == 0

    def test_large_payload(self, cache: Cache) -> None:
        big = os.urandom(128 * 1024)
        cache.set("big", big)
        cache.save()
        reloaded = Cache(cache.path, FakeBackend())
        reloaded.load()
        assert reloaded.get("big") == big


class TestCorruption:
    def test_truncated_header(self, cache: Cache) -> None:
        cache.path.write_bytes(b"PSI")
        with pytest.raises(CacheError, match="too short"):
            cache.load()

    def test_bad_magic(self, cache: Cache) -> None:
        cache.path.write_bytes(b"XXXX" + bytes([VERSION, TPM_BACKEND_TAG]) + b"\x00" * 40)
        with pytest.raises(CacheError, match="bad magic"):
            cache.load()

    def test_version_mismatch(self, cache: Cache) -> None:
        cache.path.write_bytes(MAGIC + bytes([0xFF, TPM_BACKEND_TAG]) + b"\x00" * 40)
        with pytest.raises(CacheError, match="unsupported version"):
            cache.load()

    def test_backend_tag_mismatch(self, tmp_path: Path) -> None:
        tpm_cache = Cache(tmp_path / "cache.enc", FakeBackend(tag=TPM_BACKEND_TAG))
        tpm_cache.set("k", b"v")
        tpm_cache.save()

        hsm_cache = Cache(tmp_path / "cache.enc", FakeBackend(tag=HSM_BACKEND_TAG))
        with pytest.raises(CacheError, match="backend tag"):
            hsm_cache.load()

    def test_wrong_key_fails(self, tmp_path: Path) -> None:
        cache = Cache(tmp_path / "cache.enc", FakeBackend(key=_FIXED_KEY))
        cache.set("k", b"v")
        cache.save()

        wrong_key = bytes(range(32, 64))
        other = Cache(tmp_path / "cache.enc", FakeBackend(key=wrong_key))
        with pytest.raises(Exception):  # noqa: B017 — InvalidTag bubbles up
            other.load()

    def test_mangled_payload_json(self, tmp_path: Path) -> None:
        backend = FakeBackend()
        header = struct.pack(">4sBB", MAGIC, VERSION, TPM_BACKEND_TAG)
        bogus = backend.encrypt(b"not json at all")
        (tmp_path / "cache.enc").write_bytes(header + bogus)
        cache = Cache(tmp_path / "cache.enc", backend)
        with pytest.raises(CacheError, match="JSON"):
            cache.load()


class TestMutation:
    def test_set_and_get(self, cache: Cache) -> None:
        cache.set("db_password", b"hunter2")
        assert cache.get("db_password") == b"hunter2"
        assert "db_password" in cache

    def test_get_missing_returns_none(self, cache: Cache) -> None:
        assert cache.get("nope") is None

    def test_invalidate_present(self, cache: Cache) -> None:
        cache.set("k", b"v")
        assert cache.invalidate("k") is True
        assert cache.get("k") is None

    def test_invalidate_absent(self, cache: Cache) -> None:
        assert cache.invalidate("nope") is False

    def test_bulk_set_replaces_all(self, cache: Cache) -> None:
        cache.set("old", b"x")
        cache.bulk_set({"a": b"1", "b": b"2"})
        assert cache.get("old") is None
        assert cache.get("a") == b"1"
        assert cache.get("b") == b"2"

    def test_clear(self, cache: Cache) -> None:
        cache.set("a", b"1")
        cache.clear()
        assert len(cache) == 0

    def test_entry_ids_sorted(self, cache: Cache) -> None:
        cache.set("b", b"2")
        cache.set("a", b"1")
        assert cache.entry_ids() == ["a", "b"]


class TestConcurrency:
    def test_concurrent_writers_serialize(self, cache: Cache) -> None:
        cache.save()  # create initial file

        def worker(idx: int) -> None:
            for i in range(20):
                cache.set(f"k{idx}_{i}", f"v{idx}_{i}".encode())
                cache.save()

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        reloaded = Cache(cache.path, FakeBackend())
        reloaded.load()
        # Every thread's final value must be present
        for idx in range(5):
            assert reloaded.get(f"k{idx}_19") == f"v{idx}_19".encode()


class TestClose:
    def test_close_delegates_to_backend(self, cache: Cache, backend: FakeBackend) -> None:
        cache.close()
        assert backend.close_calls == 1


class TestCacheKey:
    def test_same_mapping_bytes_produce_same_key(self, cache: Cache) -> None:
        mapping = b'{"provider":"infisical","project":"p","path":"/","key":"K"}'
        assert cache.cache_key(mapping) == cache.cache_key(mapping)

    def test_different_mappings_produce_different_keys(self, cache: Cache) -> None:
        a = b'{"provider":"infisical","project":"p","path":"/","key":"A"}'
        b = b'{"provider":"infisical","project":"p","path":"/","key":"B"}'
        assert cache.cache_key(a) != cache.cache_key(b)

    def test_key_is_stable_across_save_and_load(self, cache: Cache) -> None:
        mapping = b'{"provider":"infisical","project":"p","path":"/","key":"K"}'
        key_before = cache.cache_key(mapping)
        cache.set(key_before, b"value")
        cache.save()

        reloaded = Cache(cache.path, FakeBackend())
        reloaded.load()
        assert reloaded.cache_key(mapping) == key_before
        assert reloaded.get(key_before) == b"value"

    def test_hmac_key_is_per_host_random(self, tmp_path: Path) -> None:
        """Two freshly-initialized caches produce different keys for same input.

        The HMAC key is random on init; only load() imports one from an
        existing file. Cross-host correlation of cache contents is impossible.
        """
        mapping = b'{"provider":"infisical","project":"p","path":"/","key":"K"}'
        a = Cache(tmp_path / "a.enc", FakeBackend())
        b = Cache(tmp_path / "b.enc", FakeBackend())
        assert a.cache_key(mapping) != b.cache_key(mapping)


class TestMaybeReload:
    def test_no_reload_when_mtime_unchanged(self, cache: Cache) -> None:
        cache.set("k", b"v")
        cache.save()
        assert cache.maybe_reload() is False

    def test_reloads_when_file_is_rewritten_by_another_writer(self, cache: Cache) -> None:
        """Setup writes; serve (running in another process) picks up changes."""
        # Initial state: serve sees "old"
        cache.set("k", b"old")
        cache.save()

        # Simulate setup's writer: new Cache instance, writes new value
        other = Cache(cache.path, FakeBackend())
        other.load()
        other.set("k", b"new")
        # Force a distinct mtime even on fast filesystems
        import os as _os
        import time as _time

        stat_before = _os.stat(cache.path)
        while True:
            other.save()
            if _os.stat(cache.path).st_mtime_ns != stat_before.st_mtime_ns:
                break
            _time.sleep(0.01)

        assert cache.maybe_reload() is True
        assert cache.get("k") == b"new"

    def test_missing_file_returns_false_no_crash(
        self, tmp_path: Path, backend: FakeBackend
    ) -> None:
        cache = Cache(tmp_path / "does-not-exist.enc", backend)
        assert cache.maybe_reload() is False


class TestLegacyV1PayloadDiscarded:
    def test_v1_payload_is_treated_as_empty_with_fresh_hmac_key(
        self, cache: Cache, backend: FakeBackend
    ) -> None:
        """A v1 cache file (hex-ID keyed) is ignored on load."""
        import base64
        import json
        import time

        legacy_payload = {
            "version": 1,
            "written_at": int(time.time()),
            "entries": {
                "abc123hex": base64.b64encode(b"stale").decode(),
            },
        }
        plaintext = json.dumps(legacy_payload, separators=(",", ":")).encode()
        encrypted = backend.encrypt(plaintext)
        header = struct.pack(">4sBB", MAGIC, VERSION, backend.tag)
        cache.path.write_bytes(header + encrypted)

        fresh = Cache(cache.path, backend)
        fresh.load()
        assert len(fresh) == 0
        assert fresh.get("abc123hex") is None
