#!/usr/bin/env python3
"""
Shared hashing utilities for fors33-scanner.

Supports SHA-256 (default), SHA-512, MD5, SHA-1, and optional BLAKE3 with
streaming, chunk-based hashing suitable for large files.
"""
from __future__ import annotations

import os
import mmap
from typing import Callable, Iterable, Optional

import hashlib
DEFAULT_MMAP_MIN_MB = 500
DEFAULT_MMAP_MAX_MB = 4000


def _env_int(name: str, default: int) -> int:
    raw = os.environ.get(name)
    if raw is None or raw.strip() == "":
        return default
    try:
        value = int(raw.strip())
        return value if value > 0 else default
    except ValueError:
        return default


def _mmap_window_bytes() -> tuple[int, int]:
    min_mb = _env_int("FORS33_MMAP_MIN_MB", DEFAULT_MMAP_MIN_MB)
    max_mb = _env_int("FORS33_MMAP_MAX_MB", DEFAULT_MMAP_MAX_MB)
    if max_mb < min_mb:
        max_mb = min_mb
    return (min_mb * 1024 * 1024, max_mb * 1024 * 1024)


try:
    import blake3  # type: ignore[attr-defined]
except Exception:  # pragma: no cover - optional
    blake3 = None  # type: ignore[assignment]


def _get_hasher(algo: str):
    algo_lower = algo.lower()
    if algo_lower == "sha256":
        return hashlib.sha256()
    if algo_lower == "sha512":
        return hashlib.sha512()
    if algo_lower == "md5":
        return hashlib.md5()
    if algo_lower in ("sha1", "sha-1"):
        return hashlib.sha1()
    if algo_lower == "blake3":
        if blake3 is None:
            raise RuntimeError("blake3 is not available in this environment")
        return blake3.blake3()
    raise ValueError(f"Unsupported hash algorithm: {algo}")


def path_for_kernel(path: str) -> str:
    """On Windows, normalize absolute path for kernel calls (stat, open)."""
    if os.name != "nt":
        return path
    if not os.path.isabs(path):
        return path
    path = path.replace("/", "\\")
    if path.startswith("\\\\") and not path.startswith("\\\\?\\"):
        return "\\\\?\\UNC\\" + path[2:]
    if len(path) >= 2 and path[1] == ":":
        return "\\\\?\\" + path
    return path


def path_from_kernel(path: str) -> str:
    """Strip Windows long-path prefix for relpath/comparison with non-prefixed paths."""
    if os.name != "nt":
        return path
    if path.startswith("\\\\?\\UNC\\"):
        return "\\\\" + path[7:]
    if path.startswith("\\\\?\\"):
        return path[4:]
    return path


def infer_algo_from_digest(hex_str: str) -> Optional[str]:
    """Infer hash algorithm from hex digest length, when possible."""
    length = len(hex_str)
    if length == 32:
        return "md5"
    if length == 40:
        return "sha1"
    if length == 64:
        return "sha256"
    if length == 128:
        return "sha512"
    return None


def hash_file(
    path: str,
    algo: str = "sha256",
    start: int = 0,
    end: Optional[int] = None,
    chunk_size: int = 4194304,
    progress_callback: Optional[Callable[[int, int], None]] = None,
) -> str:
    """Hash a file (or byte range) using streaming chunks.
    If progress_callback is set, it is called with (bytes_read, total_bytes) per chunk.
    total_bytes is -1 when unknown.
    """
    hasher = _get_hasher(algo)
    total_bytes = -1
    remaining: Optional[int] = None
    if end is not None:
        remaining = max(0, end - start)
        total_bytes = remaining
    else:
        try:
            total_bytes = os.path.getsize(path_for_kernel(path)) - start
        except OSError:
            pass
    bytes_read = 0
    buffer = bytearray(chunk_size)
    with open(path_for_kernel(path), "rb") as f:
        f.seek(start)
        mmap_min, mmap_max = _mmap_window_bytes()
        can_try_mmap = (
            remaining is None
            and start == 0
            and total_bytes >= mmap_min
            and total_bytes <= mmap_max
        )
        if can_try_mmap:
            try:
                with mmap.mmap(f.fileno(), length=0, access=mmap.ACCESS_READ) as mm:
                    hasher.update(mm)
                    bytes_read = total_bytes if total_bytes >= 0 else len(mm)
                    if progress_callback:
                        progress_callback(bytes_read, total_bytes)
                    return hasher.hexdigest()
            except (OSError, ValueError, BufferError):
                # Fall back to bounded chunked hashing for mmap-incompatible filesystems/files.
                f.seek(start)
        if remaining is not None:
            while remaining > 0:
                to_read = min(remaining, chunk_size)
                n = f.readinto(memoryview(buffer)[:to_read])
                if n <= 0:
                    break
                hasher.update(memoryview(buffer)[:n])
                remaining -= n
                bytes_read += n
                if progress_callback:
                    progress_callback(bytes_read, total_bytes)
        else:
            while True:
                n = f.readinto(buffer)
                if n <= 0:
                    break
                hasher.update(memoryview(buffer)[:n])
                bytes_read += n
                if progress_callback:
                    progress_callback(bytes_read, total_bytes if total_bytes >= 0 else -1)
    return hasher.hexdigest()


def hash_stream(
    chunks: Iterable[bytes],
    algo: str = "sha256",
) -> str:
    """Hash an arbitrary stream of byte chunks."""
    hasher = _get_hasher(algo)
    for chunk in chunks:
        if chunk:
            hasher.update(chunk)
    return hasher.hexdigest()

