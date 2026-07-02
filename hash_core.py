#!/usr/bin/env python3
"""
Shared hashing utilities for scanner and verifier.

Supports SHA-256 (default), SHA-512, MD5, SHA-1, and optional BLAKE3 with
streaming, chunk-based hashing suitable for large files.
"""
from __future__ import annotations

import hashlib
import mmap
import os
import re
import sys
import threading
import time
from typing import Callable, Iterable, Optional

# Large background hashing: worker pools (scan_dpk / verify_dpk) plus this module's
# token-bucket reader keep the extension UI responsive; no published MB/s SLA.

# Global read-rate limit (bytes/sec) for chunked reads; None disables throttling.
_io_bucket_lock = threading.Lock()
_io_bps: Optional[float] = None
_tb_tokens: float = 0.0
_tb_last: float = 0.0


def set_global_read_bytes_per_second(bps: Optional[float]) -> None:
    """Configure daemon-wide disk read throttle (None = unlimited)."""
    global _io_bps, _tb_tokens, _tb_last
    with _io_bucket_lock:
        _io_bps = None if bps is None or bps <= 0 else float(bps)
        _tb_tokens = 0.0
        _tb_last = time.monotonic()


def _throttle_before_read(num_bytes: int) -> None:
    """Block until token bucket allows reading num_bytes (coarse global cap)."""
    global _tb_tokens, _tb_last
    if num_bytes <= 0:
        return
    while True:
        sleep_s = 0.0
        with _io_bucket_lock:
            bps = _io_bps
            if bps is None:
                return
            now = time.monotonic()
            elapsed = now - _tb_last
            _tb_last = now
            _tb_tokens = min(bps * 2.0, _tb_tokens + elapsed * bps)
            if _tb_tokens >= num_bytes:
                _tb_tokens -= float(num_bytes)
                return
            deficit = float(num_bytes) - _tb_tokens
            sleep_s = min(0.25, max(0.001, deficit / bps))
        time.sleep(sleep_s)

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


def _read_first_line_int_bytes(path: str) -> Optional[int]:
    """Read a single cgroup limit file; return positive bytes or None if max/unlimited/unreadable."""
    try:
        with open(path, encoding="ascii", errors="replace") as f:
            raw = f.read().strip()
    except OSError:
        return None
    if not raw or raw.lower() == "max":
        return None
    try:
        v = int(raw, 10)
    except ValueError:
        return None
    return v if v > 0 else None


def _linux_cgroup_v2_rel_path() -> Optional[str]:
    if not sys.platform.startswith("linux"):
        return None
    try:
        with open("/proc/self/cgroup", encoding="ascii", errors="replace") as f:
            for line in f:
                line = line.strip()
                if line.startswith("0::"):
                    tail = line[3:].strip()
                    if not tail or tail == "/":
                        return "/"
                    return tail if tail.startswith("/") else "/" + tail
    except OSError:
        return None
    return None


def _cgroup_v2_dir() -> Optional[str]:
    rel = _linux_cgroup_v2_rel_path()
    if rel is None:
        return None
    base = "/sys/fs/cgroup"
    if rel in ("/", ""):
        return base
    return os.path.normpath(base + rel)


def _memory_ceiling_bytes_linux() -> Optional[int]:
    """
    Host/container memory ceiling (fallback chain):
    cgroup v2 memory.max, else cgroup v1 memory.limit_in_bytes, else visible RAM.
    """
    cg2 = _cgroup_v2_dir()
    if cg2:
        v = _read_first_line_int_bytes(os.path.join(cg2, "memory.max"))
        if v is not None:
            return v
    try:
        with open("/proc/self/cgroup", encoding="ascii", errors="replace") as f:
            lines = f.readlines()
    except OSError:
        lines = []
    mem_rel: Optional[str] = None
    for line in lines:
        parts = line.strip().split(":")
        if len(parts) >= 3 and "memory" in parts[1].split(","):
            mem_rel = parts[2]
            break
    if mem_rel:
        v1_path = os.path.normpath("/sys/fs/cgroup/memory" + (mem_rel if mem_rel.startswith("/") else "/" + mem_rel))
        lim = _read_first_line_int_bytes(os.path.join(v1_path, "memory.limit_in_bytes"))
        if lim is not None:
            huge = 1 << 60
            if lim < huge:
                return lim
    try:
        pages = int(os.sysconf("SC_PHYS_PAGES"))
        psize = int(os.sysconf("SC_PAGE_SIZE"))
        if pages > 0 and psize > 0:
            return pages * psize
    except (ValueError, OSError, AttributeError, TypeError):
        pass
    return None


def _memory_ceiling_bytes() -> Optional[int]:
    if sys.platform.startswith("linux"):
        return _memory_ceiling_bytes_linux()
    if os.name != "nt":
        try:
            pages = int(os.sysconf("SC_PHYS_PAGES"))
            psize = int(os.sysconf("SC_PAGE_SIZE"))
            if pages > 0 and psize > 0:
                return pages * psize
        except (ValueError, OSError, AttributeError, TypeError):
            pass
    return None


def _cgroup_v2_memory_pressure_some_avg10() -> Optional[float]:
    """Parse memory.pressure 'some' line avg10 for this process cgroup; None if missing or unusable."""
    cg2 = _cgroup_v2_dir()
    if not cg2:
        return None
    path = os.path.join(cg2, "memory.pressure")
    try:
        with open(path, encoding="ascii", errors="replace") as f:
            text = f.read()
    except OSError:
        return None
    for line in text.splitlines():
        line = line.strip()
        if not line.startswith("some"):
            continue
        m = re.search(r"avg10=([0-9.]+)", line)
        if not m:
            return None
        try:
            return float(m.group(1))
        except ValueError:
            return None
    return None


def _mmap_psi_disables_mmap() -> bool:
    raw = os.environ.get("FORS33_MMAP_PSI_SOME_AVG10_MAX", "").strip()
    if not raw:
        return False
    try:
        cap = float(raw)
    except ValueError:
        return False
    if cap < 0.0:
        return False
    avg10 = _cgroup_v2_memory_pressure_some_avg10()
    if avg10 is None:
        return False
    return avg10 > cap


def runtime_pids_headroom() -> tuple[int | None, int | None]:
    """Return (pids.current, pids.max) for this process cgroup; None when unreadable."""
    cg2 = _cgroup_v2_dir()
    if not cg2:
        return None, None
    cur = _read_first_line_int_bytes(os.path.join(cg2, "pids.current"))
    mx = _read_first_line_int_bytes(os.path.join(cg2, "pids.max"))
    return cur, mx


def runtime_memory_pressure_some_avg10() -> float | None:
    return _cgroup_v2_memory_pressure_some_avg10()


def t3thr_spawn_headroom_ok(
    pending_spawns: int = 1,
    *,
    spawn_reserve_pids: int = 4,
) -> tuple[bool, str | None]:
    """
    Return (ok, binding_reason) when the VM can admit ``pending_spawns`` more t3thr children.
    binding_reason is ``pids`` or ``memory_pressure`` when ok is False.
    """
    need = max(1, int(pending_spawns))
    if not sys.platform.startswith("linux"):
        return True, None
    cur, mx = runtime_pids_headroom()
    reserve = 48
    if cur is not None and mx is not None and mx > 0:
        headroom = mx - cur - reserve
        if headroom < spawn_reserve_pids * need:
            return False, "pids"
    psi_raw = os.environ.get("FORS33_STREAM_PSI_SOME_AVG10_MAX", "30").strip()
    try:
        psi_limit = float(psi_raw)
    except ValueError:
        psi_limit = 30.0
    avg10 = runtime_memory_pressure_some_avg10()
    if avg10 is not None and avg10 > psi_limit:
        return False, "memory_pressure"
    return True, None


def effective_live_stream_max(
    license_max: int,
    active_non_file: int,
    *,
    spawn_reserve_pids: int = 4,
) -> tuple[int, str | None]:
    """
    Total concurrent non-file live jobs allowed (min of license and VM headroom).
    Returns (effective_max, vm_binding_reason) where reason is pids or memory_pressure.
    """
    lic_cap = max(0, int(license_max))
    active = max(0, int(active_non_file))
    if not sys.platform.startswith("linux"):
        return lic_cap, None
    effective = lic_cap
    binding: str | None = None
    cur, mx = runtime_pids_headroom()
    reserve = 48
    if cur is not None and mx is not None and mx > 0:
        headroom = mx - cur - reserve
        if headroom < spawn_reserve_pids:
            if active < effective:
                effective = active
                binding = "pids"
        else:
            pid_slots = max(0, headroom // spawn_reserve_pids)
            vm_cap = active + pid_slots
            if vm_cap < effective:
                effective = vm_cap
                binding = "pids"
    psi_raw = os.environ.get("FORS33_STREAM_PSI_SOME_AVG10_MAX", "30").strip()
    try:
        psi_limit = float(psi_raw)
    except ValueError:
        psi_limit = 30.0
    avg10 = runtime_memory_pressure_some_avg10()
    if avg10 is not None and avg10 > psi_limit and effective > active:
        effective = active
        binding = "memory_pressure"
    return max(active, min(lic_cap, effective)), binding


def soft_max_concurrent_file_jobs() -> int:
    """Daemon-side file job ceiling under VM pressure (file bypasses license live cap)."""
    base = 8
    raw = os.environ.get("FORS33_SOFT_MAX_FILE_JOBS", "").strip()
    if raw:
        try:
            base = max(1, int(raw))
        except ValueError:
            pass
    if not sys.platform.startswith("linux"):
        return base
    avg10 = runtime_memory_pressure_some_avg10()
    psi_raw = os.environ.get("FORS33_STREAM_PSI_SOME_AVG10_MAX", "30").strip()
    try:
        psi_limit = float(psi_raw)
    except ValueError:
        psi_limit = 30.0
    if avg10 is not None and avg10 > psi_limit:
        return min(base, 2)
    cur, mx = runtime_pids_headroom()
    if cur is not None and mx is not None and mx > 0 and (mx - cur) < 64:
        return min(base, 2)
    return base


def _effective_mmap_bounds_bytes() -> tuple[int, int]:
    """
    Return (mmap_min_bytes, mmap_max_bytes) after cgroup/RAM ceiling and env overrides.

    Order: cgroup v2 max, v1 limit, RAM for ceiling; then clamp user FORS33_MMAP_MAX_MB
    to ceiling; FORS33_MMAP_MIN_MB / defaults applied last.
    """
    mmap_min_mb = int(os.environ.get("FORS33_MMAP_MIN_MB", "500"))
    mmap_max_mb = int(os.environ.get("FORS33_MMAP_MAX_MB", "4000"))
    mmap_min_b = max(0, mmap_min_mb) * 1024 * 1024
    mmap_max_b = max(0, mmap_max_mb) * 1024 * 1024
    ceiling = _memory_ceiling_bytes()
    if ceiling is not None:
        reserve = 64 * 1024 * 1024
        cap_b = max(0, ceiling - reserve)
        if mmap_max_b > 0:
            mmap_max_b = min(mmap_max_b, cap_b)
        else:
            mmap_max_b = cap_b
    if mmap_max_b > 0 and mmap_min_b > mmap_max_b:
        mmap_min_b = mmap_max_b
    return mmap_min_b, mmap_max_b


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

    # Bounded mmap fast path:
    # - whole-file only (start == 0, end is None)
    # - total_bytes must be known and within cgroup/RAM-clamped bounds
    # - optional PSI avg10 may disable mmap (FORS33_MMAP_PSI_SOME_AVG10_MAX)
    # - on any mmap failure, fall back to the chunked reader below
    mmap_min, mmap_max = _effective_mmap_bounds_bytes()
    psi_mmap_off = _mmap_psi_disables_mmap()
    can_try_mmap = (
        not psi_mmap_off
        and remaining is None
        and end is None
        and start == 0
        and mmap_max > 0
        and total_bytes >= mmap_min
        and total_bytes <= mmap_max
    )
    bytes_read = 0
    buffer = bytearray(chunk_size)
    with open(path_for_kernel(path), "rb") as f:
        if can_try_mmap:
            try:
                with mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as mm:
                    hasher.update(mm)
                    if progress_callback:
                        progress_callback(total_bytes, total_bytes)
                return hasher.hexdigest()
            except Exception:
                # Fall through to chunked reading.
                pass
        f.seek(start)
        if remaining is not None:
            while remaining > 0:
                to_read = min(remaining, chunk_size)
                _throttle_before_read(to_read)
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
                _throttle_before_read(chunk_size)
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


def default_dpk_worker_count() -> int:
    """Shared worker cap for scan_dpk and verify_dpk (FORS33_DPK_MAX_WORKERS clamps cpu-based default)."""
    n = os.cpu_count() or 1
    w = min(32, max(1, n))
    cap = os.environ.get("FORS33_DPK_MAX_WORKERS", "").strip()
    if cap:
        try:
            c = int(cap, 10)
            if c >= 1:
                w = min(w, c)
        except ValueError:
            pass
    return w


# Epoch upload bundle companions (S3 PutObject basenames + dated live-root variants).
# Not fors33-manifest sealed entries; epoch upload companion basenames (metrics-template.json,
# matches ws_metrics_template.METRICS_TEMPLATE_FILENAME.
_EPOCH_UPLOAD_COMPANION_EXACT: frozenset[str] = frozenset(
    {
        "metrics-template.json",
        "integrity_provenance.json",
        "epoch_attestation.json",
        "epoch_attestation.sig",
        "epoch_attestation_public.pem",
    }
)


def is_epoch_upload_companion_basename(name: str) -> bool:
    """True when basename is a non-sealed epoch bundle companion (observability or audit adjunct)."""
    base = os.path.basename(str(name or "").strip())
    if not base:
        return False
    if base in _EPOCH_UPLOAD_COMPANION_EXACT:
        return True
    if base.startswith("integrity_provenance_") and base.endswith(".json"):
        return True
    if base.startswith("epoch_attestation_") and (
        base.endswith(".json") or base.endswith(".sig") or base.endswith("_public.pem")
    ):
        return True
    return False


def compute_baseline_merkle_root(records: list[dict], algo: str = "sha256") -> str:
    """
    Deterministic Merkle root over sorted scan baseline rows (path + digest leaves).
    Returns empty string when records is empty.
    """
    if not records:
        return ""
    algo_norm = str(algo or "sha256").strip().lower() or "sha256"
    leaves: list[str] = []
    for rec in sorted(records, key=lambda r: str(r.get("path") or "")):
        path = str(rec.get("path") or "")
        digest = str(rec.get("digest") or "")
        leaf_preimage = f"{algo_norm}:{path}:{digest}".encode("utf-8")
        leaves.append(hashlib.sha256(leaf_preimage).hexdigest())
    level = leaves
    while len(level) > 1:
        nxt: list[str] = []
        for i in range(0, len(level), 2):
            left = level[i]
            right = level[i + 1] if i + 1 < len(level) else left
            nxt.append(hashlib.sha256(f"{left}{right}".encode("ascii")).hexdigest())
        level = nxt
    return level[0]
