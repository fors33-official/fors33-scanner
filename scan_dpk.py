#!/usr/bin/env python3
"""
FORS33 Liability Scanner (open source)

High-speed, read-only scanner that walks one or more roots using os.scandir,
measures "data gravity" (bytes) for large files, and classifies them as
attested or unattested based on presence of a sibling .f33 sidecar.

This module is standalone: no network calls, no telemetry. Designed for
enterprise environments and CI pipelines.

Large-tree runs rely on default_dpk_worker_count plus hash_core token-bucket
throttling so the Docker extension UI stays responsive during background hashing.
"""
from __future__ import annotations

import argparse
import csv
import fnmatch
import json
import os
import sys
import time
from datetime import datetime, timezone
from dataclasses import dataclass, asdict, field
from typing import Callable, Dict, Iterable, List, Set

try:
    from .hash_core import (
        default_dpk_worker_count,
        hash_file,
        is_epoch_upload_companion_basename,
        path_for_kernel,
        path_from_kernel,
    )
    from .manifest_core import (
        bagit_payload_relpaths,
        discover_bagit_layout,
        is_bagit_tag_basename,
    )
except ImportError:  # pragma: no cover - flat layout
    from hash_core import (
        default_dpk_worker_count,
        hash_file,
        is_epoch_upload_companion_basename,
        path_for_kernel,
        path_from_kernel,
    )
    from manifest_core import (
        bagit_payload_relpaths,
        discover_bagit_layout,
        is_bagit_tag_basename,
    )



def _env_bool(key: str) -> bool:
    """Strict string-to-bool: True only for 1, true, yes, y; False otherwise."""
    v = os.environ.get(key, "").strip().lower()
    return v in ("1", "true", "yes", "y")


def resolve_dpk_worker_count(cli_workers: int | None) -> int:
    """
    Thread pool size: positive --workers wins; else positive FORS33_WORKERS;
    else default_dpk_worker_count() (FORS33_DPK_MAX_WORKERS applied inside that).
    """
    if cli_workers is not None and cli_workers > 0:
        return min(64, int(cli_workers))
    env_raw = os.environ.get("FORS33_WORKERS", "").strip()
    if env_raw:
        try:
            ev = int(env_raw, 10)
        except ValueError:
            raise ValueError("FORS33_WORKERS must be an integer") from None
        if ev > 0:
            return min(64, ev)
    return default_dpk_worker_count()


def _default_worker_count() -> int:
    return default_dpk_worker_count()


_EXCLUDE_DIRS: Set[str] = {
    ".git",
    "node_modules",
    "venv",
    ".venv",
    "__pycache__",
    ".idea",
    ".vscode",
}

# Recognized attestation sidecar extensions. .f33 is the deterministic Fors33
# standard; the others are external/legacy formats we respect for coverage.
_F33_EXT = ".f33"
_BLAKE3_EXT = ".blake3"
_CORE_ATT_EXTS = (
    _F33_EXT,
    ".sig",
    ".asc",
    ".sha256",
    ".sha512",
    ".md5",
    ".pem",
)
_ATT_EXTS = _CORE_ATT_EXTS + (_BLAKE3_EXT,)
_EXTERNAL_EXTS = tuple(ext for ext in _ATT_EXTS if ext != _F33_EXT)


def _sidecar_suffix_tuples(
    recognize_blake3_sidecar: bool = True,
) -> tuple[tuple[str, ...], tuple[str, ...]]:
    """Return (skip_exts, external_attestation_exts) for directory/single-file walks."""
    skip_exts = _CORE_ATT_EXTS + (_BLAKE3_EXT,)
    external_exts = tuple(ext for ext in _CORE_ATT_EXTS if ext != _F33_EXT)
    if recognize_blake3_sidecar:
        external_exts = external_exts + (_BLAKE3_EXT,)
    return skip_exts, external_exts


def _resolve_scanner_compat_kwargs(
    *,
    legacy_scanner_stats: bool = False,
    below_threshold_single_file_counts_skipped: bool = False,
    recognize_blake3_sidecar: bool = True,
) -> dict[str, bool]:
    """Apply legacy bundle and env overrides for pre-0.8.0 scanner accounting."""
    if legacy_scanner_stats or _env_bool("FORS33_SCANNER_LEGACY_STATS"):
        below_threshold_single_file_counts_skipped = True
        recognize_blake3_sidecar = False
    return {
        "below_threshold_single_file_counts_skipped": below_threshold_single_file_counts_skipped,
        "recognize_blake3_sidecar": recognize_blake3_sidecar,
    }

LEGAL_BANNER_LINES = (
    "[LEGAL]  Fors33 Liability Scanner",
    "[LEGAL]  This scanner quantifies attestation coverage only.",
    "[LEGAL]  Verify results in your chain-of-custody workflow.",
    "[LEGAL]  Do not treat summary output as cryptographic proof.",
    "[LEGAL]  Unauthorized use is prohibited.",
)


def _depth_from_root(root_path: str, current_path: str) -> int:
    """
    Compute traversal depth where:
      - depth(root) == 0
      - depth(root/child) == 1
    Normalizes both paths to make dot-slash and slash/backslash cases stable.
    """
    root_np = os.path.normpath(os.path.abspath(path_from_kernel(root_path)))
    cur_np = os.path.normpath(os.path.abspath(path_from_kernel(current_path)))
    rel = os.path.relpath(cur_np, root_np)
    rel_norm = rel.replace("\\", "/")
    if rel_norm == ".":
        return 0
    return len(rel_norm.split("/"))


class StrictAuditFatal(Exception):
    """Raised when strict_audit_mode is on and a path is inaccessible (permissions or lock)."""


def _is_strict_audit_io_error(exc: BaseException) -> bool:
    if isinstance(exc, PermissionError):
        return True
    if isinstance(exc, OSError):
        if getattr(exc, "errno", None) in (1, 13):
            return True
        if getattr(exc, "winerror", None) in (5, 32, 33):
            return True
    return False


@dataclass
class BaselineRecord:
    """Unified record shape for L3dgr UI: path, digest, algo, bytes, mtime, status."""

    path: str
    digest: str
    algo: str
    bytes: int
    mtime: int | float
    status: str = "baseline"


@dataclass
class ScanStats:
    roots: List[str]
    files_scanned: int = 0
    candidate_files: int = 0
    attested_files: int = 0
    unattested_files: int = 0
    total_bytes: int = 0
    attested_bytes: int = 0
    unattested_bytes: int = 0
    # Stratified attestation breakdown
    attested_f33_files: int = 0
    attested_external_files: int = 0
    attested_f33_bytes: int = 0
    attested_external_bytes: int = 0
    elapsed_seconds: float = 0.0
    skipped_files: int = 0
    mutated_during_scan: int = 0
    unverified_paths_sample: List[Dict[str, str]] = field(default_factory=list)

    def add_unverified_sample(
        self,
        rel_path: str,
        status: str = "UNSEALED",
        *,
        has_sidecar: bool = False,
    ) -> None:
        if len(self.unverified_paths_sample) >= 300:
            return
        # Wave 3B: ``has_sidecar`` lets the UI flag a re-seal candidate so the
        # operator gets the 21 CFR §11.10(e) reason-for-change prompt before
        # the seal request goes out. ``str("true")`` keeps the dict shape
        # consistent with the existing ``path`` / ``status`` strings.
        self.unverified_paths_sample.append(
            {
                "path": rel_path.replace("\\", "/"),
                "status": status,
                "has_sidecar": "true" if has_sidecar else "false",
            }
        )

    @property
    def exposure_ratio(self) -> float:
        if self.total_bytes == 0:
            return 0.0
        return self.unattested_bytes / self.total_bytes

    @property
    def risk_level(self) -> str:
        r = self.exposure_ratio
        if self.total_bytes == 0:
            return "INFO"
        if r >= 0.8:
            return "CRITICAL"
        if r >= 0.2:
            return "WARNING"
        return "INFO"


def _load_f33ignore_patterns(root: str) -> List[str]:
    patterns: List[str] = []
    ignore_path = os.path.join(root, ".f33ignore")
    if not os.path.isfile(ignore_path):
        return patterns
    try:
        with open(ignore_path, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                patterns.append(line)
    except OSError:
        # Ignore failures to read ignore file; scanner should remain best-effort.
        return patterns
    return patterns


def _strip_mount_prefix(path: str, prefix: str) -> str:
    """Strip Docker host-mount prefix from path for stored/logged/JSON output."""
    if not prefix:
        return path
    norm_path = os.path.normpath(path)
    norm_prefix = os.path.normpath(prefix).rstrip(os.sep)
    if not norm_prefix:
        return path
    if norm_path == norm_prefix:
        return "."
    sep = os.sep
    if norm_path.startswith(norm_prefix + sep):
        stripped = norm_path[len(norm_prefix) + len(sep) :]
        return stripped if stripped else "."
    return path


def _matches_ignore(rel_path: str, patterns: List[str]) -> bool:
    if not patterns:
        return False
    # Normalize to forward slashes for pattern matching.
    rel_norm = rel_path.replace("\\", "/")
    for pat in patterns:
        if fnmatch.fnmatch(rel_norm, pat):
            return True
    return False


def _bagit_attested_relpaths_for_root(root: str) -> Set[str] | None:
    layout = discover_bagit_layout(root)
    if not layout:
        return None
    return bagit_payload_relpaths(layout)


def _bagit_context_for_file(file_path: str) -> tuple[Set[str] | None, str | None]:
    """When file_path is inside a bag payload, return attested paths and bag root."""
    abs_file = os.path.abspath(file_path)
    probe = os.path.dirname(abs_file)
    for _ in range(4):
        layout = discover_bagit_layout(probe)
        if layout:
            rel = os.path.relpath(abs_file, layout.bag_root).replace("\\", "/")
            paths = bagit_payload_relpaths(layout)
            if rel in paths:
                return paths, layout.bag_root
        parent = os.path.dirname(probe)
        if parent == probe:
            break
        probe = parent
    return None, None


def _scan_dir(
    path: str,
    root: str,
    threshold_bytes: int,
    stats: ScanStats,
    ignore_patterns: List[str],
    extra_exclude_dirs: Set[str],
    follow_symlinks: bool,
    visited_dirs: Set[tuple[int, int]],
    visited_files: Set[tuple[int, int]] | None = None,
    strict_audit: bool = False,
    max_depth: int | None = None,
    bagit_attested_relpaths: Set[str] | None = None,
    recognize_blake3_sidecar: bool = True,
) -> None:
    skip_exts, external_exts = _sidecar_suffix_tuples(recognize_blake3_sidecar)
    try:
        st_dir = os.stat(path_for_kernel(path), follow_symlinks=False)
    except OSError as e:
        if strict_audit and _is_strict_audit_io_error(e):
            raise StrictAuditFatal(f"Inaccessible directory (strict audit): {path}: {e}") from e
        return

    key = (st_dir.st_dev, st_dir.st_ino)
    if key in visited_dirs:
        # Prevent infinite recursion when following symlinks.
        return
    visited_dirs.add(key)
    try:
        with os.scandir(path_for_kernel(path)) as it:
            entries = list(it)
    except (PermissionError, FileNotFoundError, NotADirectoryError, OSError) as e:
        if strict_audit and _is_strict_audit_io_error(e):
            raise StrictAuditFatal(f"Inaccessible directory (strict audit): {path}: {e}") from e
        return

    # Build an in-memory set of filenames in this directory so we can check for
    # potential sidecars in O(1) without extra disk I/O.
    filenames = {
        entry.name for entry in entries if entry.is_file(follow_symlinks=follow_symlinks)
    }

    for entry in entries:
        name = entry.name
        entry_path = entry.path
        if entry.is_dir(follow_symlinks=follow_symlinks):
            if name in _EXCLUDE_DIRS or name in extra_exclude_dirs:
                continue
            rel_dir = os.path.relpath(path_from_kernel(entry_path), path_from_kernel(root))
            if _matches_ignore(rel_dir, ignore_patterns):
                continue
            if max_depth is not None and _depth_from_root(root, entry_path) > max_depth:
                continue
            _scan_dir(
                entry_path,
                root,
                threshold_bytes,
                stats,
                ignore_patterns,
                extra_exclude_dirs,
                follow_symlinks,
                visited_dirs,
                visited_files,
                strict_audit=strict_audit,
                max_depth=max_depth,
                bagit_attested_relpaths=bagit_attested_relpaths,
                recognize_blake3_sidecar=recognize_blake3_sidecar,
            )
        elif entry.is_file(follow_symlinks=follow_symlinks):
            stats.files_scanned += 1
            # Skip sidecar files themselves; we classify their parents.
            if any(name.endswith(ext) for ext in skip_exts):
                continue
            if is_epoch_upload_companion_basename(name):
                continue
            if bagit_attested_relpaths is not None and is_bagit_tag_basename(name):
                continue
            if (
                name.startswith("fors33-manifest")
                and name.endswith(".json")
                and not name.endswith(".lock")
            ):
                continue
            rel_path = os.path.relpath(path_from_kernel(entry_path), path_from_kernel(root))
            norm_rel = rel_path.replace("\\", "/")
            if _matches_ignore(rel_path, ignore_patterns):
                continue
            try:
                st = entry.stat(follow_symlinks=follow_symlinks)
            except OSError as e:
                if strict_audit and _is_strict_audit_io_error(e):
                    raise StrictAuditFatal(
                        f"Inaccessible file (strict audit): {entry_path}: {e}"
                    ) from e
                stats.skipped_files += 1
                continue
            if follow_symlinks and visited_files is not None and st.st_ino != 0:
                file_key = (st.st_dev, st.st_ino)
                if file_key in visited_files:
                    continue
                visited_files.add(file_key)
            size = st.st_size
            if size < threshold_bytes:
                continue

            stats.candidate_files += 1
            stats.total_bytes += size

            has_f33 = f"{name}{_F33_EXT}" in filenames
            has_external = False
            if not has_f33:
                for ext in external_exts:
                    if f"{name}{ext}" in filenames:
                        has_external = True
                        break

            if bagit_attested_relpaths is not None and norm_rel in bagit_attested_relpaths:
                stats.attested_files += 1
                stats.attested_bytes += size
                stats.attested_external_files += 1
                stats.attested_external_bytes += size
            elif has_f33:
                stats.attested_files += 1
                stats.attested_bytes += size
                stats.attested_f33_files += 1
                stats.attested_f33_bytes += size
            elif has_external:
                stats.attested_files += 1
                stats.attested_bytes += size
                stats.attested_external_files += 1
                stats.attested_external_bytes += size
            else:
                stats.unattested_files += 1
                stats.unattested_bytes += size
                stats.add_unverified_sample(rel_path, "UNSEALED")


def _scan_single_file(
    file_path: str,
    root: str,
    threshold_bytes: int,
    stats: ScanStats,
    ignore_patterns: List[str],
    strict_audit: bool = False,
    *,
    below_threshold_single_file_counts_skipped: bool = False,
    recognize_blake3_sidecar: bool = True,
    baseline_candidate_out: List[tuple[str, str, int, float]] | None = None,
) -> None:
    """Scan a single file (not a directory)."""
    skip_exts, external_exts = _sidecar_suffix_tuples(recognize_blake3_sidecar)
    try:
        st = os.stat(path_for_kernel(file_path), follow_symlinks=False)
    except OSError as e:
        if strict_audit and _is_strict_audit_io_error(e):
            raise StrictAuditFatal(f"Inaccessible file (strict audit): {file_path}: {e}") from e
        stats.skipped_files += 1
        return

    stats.files_scanned += 1
    
    # Skip sidecar files themselves; we classify their parents.
    name = os.path.basename(file_path)
    if any(name.endswith(ext) for ext in skip_exts):
        return
    if is_epoch_upload_companion_basename(name):
        return
    if name.startswith("fors33-manifest") and name.endswith(".json") and not name.endswith(".lock"):
        return

    rel_path = os.path.relpath(path_from_kernel(file_path), path_from_kernel(root))
    # Same file as scan root: relpath is "."; evidence UI needs a stable display name.
    if rel_path in (".", os.curdir) or rel_path == "":
        rel_path = name.replace("\\", "/")
    bagit_paths, bag_root = _bagit_context_for_file(file_path)
    if bag_root:
        rel_path = os.path.relpath(path_from_kernel(file_path), path_from_kernel(bag_root)).replace(
            "\\", "/"
        )
    norm_rel = rel_path.replace("\\", "/")
    if _matches_ignore(rel_path, ignore_patterns):
        return
    
    size = st.st_size
    if size < threshold_bytes:
        if below_threshold_single_file_counts_skipped:
            stats.skipped_files += 1
        return

    stats.candidate_files += 1
    stats.total_bytes += size
    if baseline_candidate_out is not None:
        baseline_candidate_out.append((norm_rel, file_path, size, st.st_mtime))

    # For single file, check for sidecar in same directory
    dir_path = os.path.dirname(file_path)
    try:
        with os.scandir(path_for_kernel(dir_path)) as it:
            entries = list(it)
    except (PermissionError, FileNotFoundError, NotADirectoryError, OSError) as e:
        if strict_audit and _is_strict_audit_io_error(e):
            raise StrictAuditFatal(f"Inaccessible directory (strict audit): {dir_path}: {e}") from e
        return

    filenames = {
        entry.name for entry in entries if entry.is_file(follow_symlinks=False)
    }

    has_f33 = f"{name}{_F33_EXT}" in filenames
    has_external = False
    if not has_f33:
        for ext in external_exts:
            if f"{name}{ext}" in filenames:
                has_external = True
                break

    if bagit_paths is not None and norm_rel in bagit_paths:
        stats.attested_files += 1
        stats.attested_bytes += size
        stats.attested_external_files += 1
        stats.attested_external_bytes += size
    elif has_f33:
        stats.attested_files += 1
        stats.attested_bytes += size
        stats.attested_f33_files += 1
        stats.attested_f33_bytes += size
    elif has_external:
        stats.attested_files += 1
        stats.attested_bytes += size
        stats.attested_external_files += 1
        stats.attested_external_bytes += size
    else:
        stats.unattested_files += 1
        stats.unattested_bytes += size
        stats.add_unverified_sample(rel_path, "UNSEALED")


def scan_roots(
    roots: Iterable[str],
    threshold_mb: float,
    ignore_patterns: List[str] | None = None,
    exclude_dirs: List[str] | None = None,
    follow_symlinks: bool = False,
    strict_audit: bool = False,
    max_depth: int | None = None,
    *,
    legacy_scanner_stats: bool = False,
    below_threshold_single_file_counts_skipped: bool = False,
    recognize_blake3_sidecar: bool = True,
) -> ScanStats:
    compat = _resolve_scanner_compat_kwargs(
        legacy_scanner_stats=legacy_scanner_stats,
        below_threshold_single_file_counts_skipped=below_threshold_single_file_counts_skipped,
        recognize_blake3_sidecar=recognize_blake3_sidecar,
    )
    below_skip = compat["below_threshold_single_file_counts_skipped"]
    recognize_blake3 = compat["recognize_blake3_sidecar"]
    norm_roots = [os.path.abspath(r) for r in (list(roots) or [os.getcwd()])]
    stats = ScanStats(roots=norm_roots)
    threshold_bytes = int(threshold_mb * 1024 * 1024)
    start = time.time()

    extra_exclude_dirs: Set[str] = set(exclude_dirs or [])
    base_ignore_patterns: List[str] = list(ignore_patterns or [])

    for root in norm_roots:
        root_patterns = base_ignore_patterns + _load_f33ignore_patterns(root)
        visited_dirs: Set[tuple[int, int]] = set()
        
        # Check if root is a file or directory
        if os.path.isfile(path_for_kernel(root)):
            # Handle single file case
            _scan_single_file(
                root,
                root,
                threshold_bytes,
                stats,
                root_patterns,
                strict_audit=strict_audit,
                below_threshold_single_file_counts_skipped=below_skip,
                recognize_blake3_sidecar=recognize_blake3,
            )
        else:
            # Handle directory case
            bagit_paths = _bagit_attested_relpaths_for_root(root)
            _scan_dir(
                root,
                root,
                threshold_bytes,
                stats,
                root_patterns,
                extra_exclude_dirs,
                follow_symlinks,
                visited_dirs,
                set() if follow_symlinks else None,
                strict_audit=strict_audit,
                max_depth=max_depth,
                bagit_attested_relpaths=bagit_paths,
                recognize_blake3_sidecar=recognize_blake3,
            )

    stats.elapsed_seconds = time.time() - start
    return stats


def _walk_and_collect(
    root: str,
    threshold_bytes: int,
    ignore_patterns: List[str],
    exclude_dirs: Set[str],
    follow_symlinks: bool,
    strict_audit: bool = False,
    max_depth: int | None = None,
    *,
    recognize_blake3_sidecar: bool = True,
) -> tuple[ScanStats, List[tuple[str, str, int, float]]]:
    """
    Single directory walk that collects scan stats and candidate files for baseline.
    Returns (stats, candidates). No second os.walk; skipped_files counted once.
    """
    skip_exts, external_exts = _sidecar_suffix_tuples(recognize_blake3_sidecar)
    from concurrent.futures import ThreadPoolExecutor

    root_abs = os.path.abspath(root)
    stats = ScanStats(roots=[root_abs])
    bagit_attested_relpaths = _bagit_attested_relpaths_for_root(root_abs)
    visited_dirs: Set[tuple[int, int]] = set()
    visited_files: Set[tuple[int, int]] = set()
    candidates: List[tuple[str, str, int, float]] = []
    start = time.time()
    walk_root = path_for_kernel(root_abs)

    for dirpath, dirnames, filenames in os.walk(walk_root, followlinks=follow_symlinks):
        try:
            st_dir = os.stat(path_for_kernel(dirpath), follow_symlinks=False)
        except OSError as e:
            if strict_audit and _is_strict_audit_io_error(e):
                raise StrictAuditFatal(
                    f"Inaccessible directory (strict audit): {dirpath}: {e}"
                ) from e
            continue
        key = (st_dir.st_dev, st_dir.st_ino)
        if key in visited_dirs:
            continue
        visited_dirs.add(key)
        dirnames[:] = [
            d for d in dirnames if d not in _EXCLUDE_DIRS and d not in exclude_dirs
        ]
        if max_depth is not None:
            current_depth = _depth_from_root(root_abs, dirpath)
            if current_depth > max_depth:
                dirnames[:] = []
                continue
            if current_depth >= max_depth:
                # Do not descend further, but still process this directory's files.
                dirnames[:] = []
        filenames_set = set(filenames)
        for name in filenames:
            if any(name.endswith(ext) for ext in skip_exts):
                continue
            if is_epoch_upload_companion_basename(name):
                continue
            if bagit_attested_relpaths is not None and is_bagit_tag_basename(name):
                continue
            if (
                name.startswith("fors33-manifest")
                and name.endswith(".json")
                and not name.endswith(".lock")
            ):
                continue
            full_path = os.path.join(dirpath, name)
            rel_path = os.path.relpath(path_from_kernel(full_path), path_from_kernel(root_abs))
            norm_rel = rel_path.replace("\\", "/")
            if ignore_patterns and _matches_ignore(norm_rel, ignore_patterns):
                continue
            stats.files_scanned += 1
            try:
                st = os.stat(path_for_kernel(full_path), follow_symlinks=follow_symlinks)
            except OSError as e:
                if strict_audit and _is_strict_audit_io_error(e):
                    raise StrictAuditFatal(
                        f"Inaccessible file (strict audit): {full_path}: {e}"
                    ) from e
                stats.skipped_files += 1
                continue
            if follow_symlinks and st.st_ino != 0:
                file_key = (st.st_dev, st.st_ino)
                if file_key in visited_files:
                    continue
                visited_files.add(file_key)
            size = st.st_size
            if size < threshold_bytes:
                continue
            stats.candidate_files += 1
            stats.total_bytes += size
            has_f33 = f"{name}{_F33_EXT}" in filenames_set
            has_external = not has_f33 and any(
                f"{name}{ext}" in filenames_set for ext in external_exts
            )
            if bagit_attested_relpaths is not None and norm_rel in bagit_attested_relpaths:
                stats.attested_external_files += 1
                stats.attested_external_bytes += size
                stats.attested_files += 1
                stats.attested_bytes += size
            elif has_f33:
                stats.attested_f33_files += 1
                stats.attested_f33_bytes += size
                stats.attested_files += 1
                stats.attested_bytes += size
            elif has_external:
                stats.attested_external_files += 1
                stats.attested_external_bytes += size
                stats.attested_files += 1
                stats.attested_bytes += size
            else:
                stats.unattested_files += 1
                stats.unattested_bytes += size
                stats.add_unverified_sample(norm_rel, "UNSEALED")
            candidates.append((norm_rel, full_path, size, st.st_mtime))

    stats.elapsed_seconds = time.time() - start
    return stats, candidates


def _hash_candidates(
    candidates: List[tuple[str, str, int, float]],
    algo: str,
    follow_symlinks: bool,
    stats: ScanStats,
    progress_event_callback: Callable[[dict], None] | None = None,
) -> List[Dict[str, object]]:
    """Hash candidate files (single root) and return baseline records."""
    root_indexed = [(0, rel, fp, sz, mt) for rel, fp, sz, mt in candidates]
    return _hash_candidates_multi(
        root_indexed, algo, follow_symlinks, stats, progress_event_callback
    )


def _hash_candidates_multi(
    candidates: List[tuple[int, str, str, int, float]],
    algo: str,
    follow_symlinks: bool,
    stats: ScanStats,
    progress_event_callback: Callable[[dict], None] | None = None,
    max_workers: int | None = None,
) -> List[Dict[str, object]]:
    """Hash candidate files (multi-root) and return baseline records; update stats.skipped_files and mutated_during_scan."""
    from concurrent.futures import ThreadPoolExecutor

    records: List[Dict[str, object]] = []
    effective_workers = resolve_dpk_worker_count(max_workers)

    def _worker(item: tuple[int, str, str, int, float]):
        root_idx, rel, full_path, size, _mtime = item
        try:
            st_before = os.stat(path_for_kernel(full_path), follow_symlinks=follow_symlinks)
            before_key: int | tuple[int, int] = (
                (st_before.st_dev, st_before.st_ino)
                if st_before.st_ino != 0
                else int(st_before.st_mtime)
            )
            progress_cb = None
            if progress_event_callback is not None:
                def _progress_headless(br: int, tb: int) -> None:
                    if tb > 0:
                        pct = min(100, int(br * 100 / tb))
                        progress_event_callback(
                            {"event": "progress", "file": rel, "pct": pct}
                        )

                progress_cb = _progress_headless
            elif size >= 500 * 1024 * 1024 and sys.stderr.isatty():
                last_pct = [0]

                def _progress(br: int, tb: int) -> None:
                    if tb > 0:
                        pct = min(100, int(br * 100 / tb))
                        if pct != last_pct[0] and (pct % 5 == 0 or pct == 100):
                            last_pct[0] = pct
                            print(f"\r\033[K[SCAN] Hashing {rel}: {pct}%", end="", file=sys.stderr)

                progress_cb = _progress
            digest = hash_file(full_path, algo=algo, progress_callback=progress_cb)
            if progress_cb and sys.stderr.isatty():
                print(file=sys.stderr)
            st_after = os.stat(path_for_kernel(full_path), follow_symlinks=follow_symlinks)
            after_key: int | tuple[int, int] = (
                (st_after.st_dev, st_after.st_ino)
                if st_after.st_ino != 0
                else int(st_after.st_mtime)
            )
            mutated = before_key != after_key
            mtime_final = st_after.st_mtime
        except Exception as e:
            print(f"[ERROR] Unhandled worker exception: {e}", file=sys.stderr)
            return (root_idx, rel, size, 0.0, None, True, False)
        return (root_idx, rel, size, mtime_final, digest, False, mutated)

    executor = ThreadPoolExecutor(max_workers=effective_workers)
    try:
        for root_idx, rel, size, mtime_final, digest, skipped, mutated in executor.map(
            _worker, candidates
        ):
            if skipped:
                stats.skipped_files += 1
                continue
            if mutated:
                stats.mutated_during_scan += 1
                continue
            records.append(
                {
                    "path": rel,
                    "algo": algo,
                    "digest": digest.lower(),
                    "bytes": size,
                    "mtime": int(mtime_final),
                    "root_index": root_idx,
                    "status": "baseline",
                }
            )
    except KeyboardInterrupt:
        executor.shutdown(wait=False, cancel_futures=True)
        sys.exit(130)
    finally:
        executor.shutdown(wait=True)
    return records


def _compute_baseline(
    root: str,
    threshold_bytes: int,
    algo: str,
    follow_symlinks: bool,
    stats: ScanStats | None = None,
    ignore_patterns: List[str] | None = None,
    exclude_dirs: Set[str] | None = None,
    *,
    recognize_blake3_sidecar: bool = True,
    below_threshold_single_file_counts_skipped: bool = False,
    strict_audit: bool = False,
) -> List[Dict[str, object]]:
    """
    Walk a single root and compute baseline records for all candidate files.
    Uses single walk when stats provided (no second os.walk).
    """
    extra_exclude = exclude_dirs or set()
    ignore_list = ignore_patterns or []
    root_abs = os.path.abspath(root)

    def _merge_walk_stats(target: ScanStats, walk_stats: ScanStats) -> None:
        target.files_scanned = walk_stats.files_scanned
        target.candidate_files = walk_stats.candidate_files
        target.total_bytes = walk_stats.total_bytes
        target.attested_files = walk_stats.attested_files
        target.attested_bytes = walk_stats.attested_bytes
        target.unattested_files = walk_stats.unattested_files
        target.unattested_bytes = walk_stats.unattested_bytes
        target.attested_f33_files = walk_stats.attested_f33_files
        target.attested_f33_bytes = walk_stats.attested_f33_bytes
        target.attested_external_files = walk_stats.attested_external_files
        target.attested_external_bytes = walk_stats.attested_external_bytes
        target.skipped_files = walk_stats.skipped_files
        target.elapsed_seconds = walk_stats.elapsed_seconds

    if os.path.isfile(path_for_kernel(root_abs)):
        walk_stats = ScanStats(roots=[root_abs])
        file_candidates: List[tuple[str, str, int, float]] = []
        _scan_single_file(
            root_abs,
            root_abs,
            threshold_bytes,
            walk_stats,
            ignore_list,
            strict_audit=strict_audit,
            below_threshold_single_file_counts_skipped=below_threshold_single_file_counts_skipped,
            recognize_blake3_sidecar=recognize_blake3_sidecar,
            baseline_candidate_out=file_candidates,
        )
        candidates = file_candidates
    else:
        walk_stats, candidates = _walk_and_collect(
            root_abs,
            threshold_bytes,
            ignore_list,
            extra_exclude,
            follow_symlinks,
            strict_audit=strict_audit,
            recognize_blake3_sidecar=recognize_blake3_sidecar,
        )

    if stats is not None:
        _merge_walk_stats(stats, walk_stats)
        return _hash_candidates(
            candidates, algo, follow_symlinks, stats, progress_event_callback=None
        )
    stats_placeholder = ScanStats(roots=[root_abs])
    _merge_walk_stats(stats_placeholder, walk_stats)
    return _hash_candidates(
        candidates, algo, follow_symlinks, stats_placeholder, progress_event_callback=None
    )


def execute_scan(
    roots: List[str],
    threshold_mb: float = 1.0,
    ignore_patterns: List[str] | None = None,
    exclude_dirs: List[str] | None = None,
    follow_symlinks: bool = False,
    algo: str = "sha256",
    wants_baseline: bool = False,
    progress_event_callback: Callable[[dict], None] | None = None,
    strip_mount_prefix: str = "",
    strict_audit: bool = False,
    max_depth: int | None = None,
    max_workers: int | None = None,
    *,
    legacy_scanner_stats: bool = False,
    below_threshold_single_file_counts_skipped: bool = False,
    recognize_blake3_sidecar: bool = True,
) -> tuple[ScanStats, List[Dict[str, object]]]:
    """
    Library entry point: scan roots and optionally compute baseline.

    Returns (ScanStats, records). Records are baseline entries when wants_baseline
    is True; otherwise empty. When progress_event_callback is set, emits JSON
    progress events like {"event":"progress","file":"rel/path","pct":45} for
    headless/WebSocket streaming.
    """
    roots_abs = [os.path.abspath(r) for r in roots]
    threshold_bytes = int(threshold_mb * 1024 * 1024)
    base_ignore = list(ignore_patterns or [])
    exclude_set = set(exclude_dirs or [])
    compat = _resolve_scanner_compat_kwargs(
        legacy_scanner_stats=legacy_scanner_stats,
        below_threshold_single_file_counts_skipped=below_threshold_single_file_counts_skipped,
        recognize_blake3_sidecar=recognize_blake3_sidecar,
    )
    recognize_blake3 = compat["recognize_blake3_sidecar"]
    below_skip = compat["below_threshold_single_file_counts_skipped"]

    if wants_baseline:
        all_candidates: List[tuple[int, str, str, int, float]] = []
        stats = ScanStats(roots=roots_abs)
        baseline_start = time.time()
        for root_idx, root in enumerate(roots_abs):
            root_ignore = base_ignore + _load_f33ignore_patterns(root)
            if os.path.isfile(path_for_kernel(root)):
                walk_stats = ScanStats(roots=[root])
                file_candidates: List[tuple[str, str, int, float]] = []
                _scan_single_file(
                    root,
                    root,
                    threshold_bytes,
                    walk_stats,
                    root_ignore,
                    strict_audit=strict_audit,
                    below_threshold_single_file_counts_skipped=below_skip,
                    recognize_blake3_sidecar=recognize_blake3,
                    baseline_candidate_out=file_candidates,
                )
                candidates = file_candidates
            else:
                walk_stats, candidates = _walk_and_collect(
                    root,
                    threshold_bytes,
                    root_ignore,
                    exclude_set,
                    follow_symlinks,
                    strict_audit=strict_audit,
                    max_depth=max_depth,
                    recognize_blake3_sidecar=recognize_blake3,
                )
            stats.files_scanned += walk_stats.files_scanned
            stats.candidate_files += walk_stats.candidate_files
            stats.total_bytes += walk_stats.total_bytes
            stats.attested_files += walk_stats.attested_files
            stats.attested_bytes += walk_stats.attested_bytes
            stats.unattested_files += walk_stats.unattested_files
            stats.unattested_bytes += walk_stats.unattested_bytes
            stats.attested_f33_files += walk_stats.attested_f33_files
            stats.attested_f33_bytes += walk_stats.attested_f33_bytes
            stats.attested_external_files += walk_stats.attested_external_files
            stats.attested_external_bytes += walk_stats.attested_external_bytes
            stats.skipped_files += walk_stats.skipped_files
            for row in walk_stats.unverified_paths_sample:
                stats.add_unverified_sample(row["path"], row.get("status", "UNSEALED"))
            for norm_rel, full_path, size, mtime in candidates:
                all_candidates.append((root_idx, norm_rel, full_path, size, mtime))
        stats.elapsed_seconds = time.time() - baseline_start
        records = _hash_candidates_multi(
            all_candidates,
            algo,
            follow_symlinks,
            stats,
            progress_event_callback,
            max_workers=max_workers,
        )
    else:
        stats = scan_roots(
            roots_abs,
            threshold_mb,
            ignore_patterns=base_ignore,
            exclude_dirs=exclude_set,
            follow_symlinks=follow_symlinks,
            strict_audit=strict_audit,
            max_depth=max_depth,
            legacy_scanner_stats=legacy_scanner_stats,
            below_threshold_single_file_counts_skipped=compat[
                "below_threshold_single_file_counts_skipped"
            ],
            recognize_blake3_sidecar=recognize_blake3,
        )
        records = []
    return stats, records


def _write_checksums(records: List[Dict[str, object]], dest) -> None:
    """Write Hash Filename format (standard checksum text): digest  path."""
    for rec in records:
        dest.write(f"{rec['digest']}  {rec['path']}\n")


def _write_csv(records: List[Dict[str, object]], dest) -> None:
    writer = csv.writer(dest)
    writer.writerow(["path", "algo", "digest", "bytes", "last_modified"])
    for rec in records:
        writer.writerow(
            [
                rec["path"],
                rec["algo"],
                rec["digest"],
                rec["bytes"],
                rec["mtime"],
            ]
        )


def _write_json_baseline(
    records: List[Dict[str, object]],
    roots: List[str],
    algo: str,
    dest,
    stats: ScanStats | None = None,
    strip_mount_prefix: str = "",
) -> None:
    file_count = len(records)
    total_bytes = sum(r.get("bytes", 0) for r in records)
    roots_abs = [os.path.abspath(r) for r in roots]
    if strip_mount_prefix:
        roots_abs = [_strip_mount_prefix(r, strip_mount_prefix) for r in roots_abs]
    if len(roots_abs) == 1:
        payload = {"schema_version": "0.2", "root": roots_abs[0], "algo": algo}
    else:
        payload = {"schema_version": "0.2", "roots": roots_abs, "algo": algo}
    payload["files"] = records
    payload["summary"] = {
        "file_count": file_count,
        "total_bytes": total_bytes,
        "skipped_files": (stats.skipped_files if stats else 0),
        "mutated_during_scan": (stats.mutated_during_scan if stats else 0),
    }
    json.dump(payload, dest)


def _format_bytes(num_bytes: int) -> str:
    units = ["B", "KB", "MB", "GB", "TB"]
    value = float(num_bytes)
    for unit in units:
        if value < 1024.0 or unit == units[-1]:
            return f"{value:.1f} {unit}"
        value /= 1024.0
    return f"{value:.1f} TB"


def print_human_report(stats: ScanStats, compliance_report: bool = False) -> None:
    files = stats.files_scanned
    secs = stats.elapsed_seconds or 0.0
    data_total = _format_bytes(stats.total_bytes)
    data_attested = _format_bytes(stats.attested_bytes)
    data_unattested = _format_bytes(stats.unattested_bytes)

    print(f"[FILE COUNT]    : {files:,}")
    print(f"[TOTAL BYTES]   : {data_total}")
    print(f"[ATTESTED]      : {stats.attested_files:,} files, {data_attested}")
    print(f"[UNATTESTED]    : {stats.unattested_files:,} files, {data_unattested}")
    print(f"[ELAPSED]       : {secs:.2f}s")

    if not compliance_report:
        return

    exposure_pct = stats.exposure_ratio * 100.0 if stats.total_bytes > 0 else 0.0
    risk = stats.risk_level

    print()
    print(f"[EXPOSURE RISK] : {exposure_pct:.1f}% volume exposed to silent mutation")
    print(f"[SEVERITY]      : {risk}")
    print(
        "[COMPLIANCE]    : High exposure; map results to your retention and chain-of-custody policy"
    )
    print(
        "[REMEDIATION]   : Enforce deterministic attestation on exposed directories."
    )
    print(
        "[REFERENCE]     : fors33.com | GitHub Marketplace: Fors33"
    )


def main() -> None:
    for line in LEGAL_BANNER_LINES:
        print(line, file=sys.stderr)
    parser = argparse.ArgumentParser(
        description=(
            "FORS33 Liability Scanner: quantify attested vs unattested data bytes "
            "using .f33 sidecars."
        )
    )
    parser.add_argument(
        "--root",
        action="append",
        default=None,
        help="Root directory to scan (can be specified multiple times). Defaults to CWD.",
    )
    parser.add_argument(
        "--threshold-mb",
        type=float,
        default=1.0,
        help=(
            "Minimum file size (in MB) to include in liability accounting. "
            "Default: 1.0"
        ),
    )
    parser.add_argument(
        "--max-exposure",
        type=float,
        help="Exit 1 if exposure ratio exceeds threshold (0.0 to 1.0).",
    )
    parser.add_argument(
        "--workers",
        type=int,
        help="Override default thread worker count (hard capped at 64).",
    )
    parser.add_argument(
        "--emit-jsonl",
        metavar="PATH",
        dest="emit_jsonl_path",
        help="Emit SIEM-ready JSONL stream. Use '-' for stdout.",
    )
    parser.add_argument(
        "--max-depth",
        type=int,
        help="Limit traversal depth (0=root, 1=root+children).",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Emit JSON summary to stdout instead of human-readable report.",
    )
    parser.add_argument(
        "--compliance-report",
        action="store_true",
        help="Include exposure, severity tier, and remediation hints in human-readable output.",
    )
    parser.add_argument(
        "--emit-checksums",
        metavar="PATH",
        dest="emit_checksums_path",
        help=(
            "Write checksum baseline (Hash Filename format) for all candidate files. "
            "Supports sha256, sha512, blake3 per --algo. Use '-' to write to stdout."
        ),
    )
    parser.add_argument(
        "--emit-sha256sum",
        metavar="PATH",
        dest="emit_checksums_path",
        help=argparse.SUPPRESS,
    )
    parser.add_argument(
        "--emit-csv",
        metavar="PATH",
        help="Write CSV baseline (path,algo,digest,bytes,last_modified). Use '-' for stdout.",
    )
    parser.add_argument(
        "--emit-json",
        metavar="PATH",
        dest="emit_json_path",
        help=(
            "Write JSON baseline manifest (schema_version/files) compatible with the verifier. "
            "Use '-' to write to stdout."
        ),
    )
    parser.add_argument(
        "--ignore-pattern",
        action="append",
        default=[],
        help="Glob pattern to ignore paths during scans (can be specified multiple times).",
    )
    parser.add_argument(
        "--exclude-dir",
        action="append",
        default=[],
        help="Directory name to exclude from scans in addition to built-in excludes.",
    )
    parser.add_argument(
        "--follow-symlinks",
        action="store_true",
        help="Follow directory symlinks during scans with basic loop detection.",
    )
    parser.add_argument(
        "--legacy-scanner-stats",
        action="store_true",
        help=(
            "Restore pre-0.8.0 accounting: below-threshold single-file roots count as "
            "skipped_files; .blake3 siblings do not confer external attestation."
        ),
    )
    parser.add_argument(
        "--algo",
        choices=["sha256", "sha512", "blake3", "md5", "sha1"],
        default="sha256",
        help="Hash algorithm to use when generating baselines. Default: sha256.",
    )
    parser.add_argument(
        "--strip-mount-prefix",
        metavar="PREFIX",
        default="",
        help="Strip this prefix from roots and paths in stored/logged/JSON output (e.g. Docker host-mount).",
    )
    parser.add_argument(
        "--tsa-url",
        default=None,
        metavar="URL",
        help="RFC 3161 TSA endpoint; sets FORS33_TSA_URL for seal-sidecar timestamp requests.",
    )
    args = parser.parse_args()

    if getattr(args, "tsa_url", None) and str(args.tsa_url).strip():
        os.environ["FORS33_TSA_URL"] = str(args.tsa_url).strip()

    # Environment overrides (FORS33_*)
    if os.environ.get("FORS33_ALGO"):
        args.algo = os.environ["FORS33_ALGO"].strip().lower()
    if os.environ.get("FORS33_THRESHOLD_MB"):
        try:
            args.threshold_mb = float(os.environ["FORS33_THRESHOLD_MB"].strip())
        except ValueError:
            pass
    if os.environ.get("FORS33_MAX_EXPOSURE"):
        try:
            args.max_exposure = float(os.environ["FORS33_MAX_EXPOSURE"].strip())
        except ValueError:
            pass
    if os.environ.get("FORS33_MAX_DEPTH"):
        try:
            args.max_depth = int(os.environ["FORS33_MAX_DEPTH"].strip())
        except ValueError:
            pass
    if os.environ.get("FORS33_ROOT"):
        args.root = [os.environ["FORS33_ROOT"].strip()] if not args.root else args.root
    if _env_bool("FORS33_FOLLOW_SYMLINKS"):
        args.follow_symlinks = True
    if os.environ.get("FORS33_IGNORE_PATTERN"):
        pats = [p.strip() for p in os.environ["FORS33_IGNORE_PATTERN"].split(",") if p.strip()]
        args.ignore_pattern = list(args.ignore_pattern or []) + pats
    if os.environ.get("FORS33_EXCLUDE_DIR"):
        dirs = [d.strip() for d in os.environ["FORS33_EXCLUDE_DIR"].split(",") if d.strip()]
        args.exclude_dir = list(args.exclude_dir or []) + dirs

    roots = args.root or [os.getcwd()]
    emit_checksums_path = args.emit_checksums_path
    emit_csv = args.emit_csv
    emit_json_path = args.emit_json_path
    emit_jsonl_path = args.emit_jsonl_path
    wants_baseline = bool(emit_checksums_path or emit_csv or emit_json_path or emit_jsonl_path)

    try:
        effective_workers = resolve_dpk_worker_count(args.workers)
    except ValueError as e:
        print(f"[ERROR] {e}", file=sys.stderr)
        return

    if args.algo == "blake3":
        try:
            import blake3  # noqa: F401
        except ImportError:
            print("[ERROR] --algo blake3 requires the blake3 package. pip install blake3", file=sys.stderr)
            return

    if args.algo in ("md5", "sha1") and wants_baseline:
        print(
            "[WARNING] Generating baseline with deprecated cryptographic algorithm.",
            file=sys.stderr,
        )

    if wants_baseline and len(roots) > 1 and (emit_checksums_path or emit_csv):
        print(
            "[ERROR] --emit-checksums and --emit-csv support a single --root only.",
            file=sys.stderr,
        )
        return

    stats, records = execute_scan(
        roots=roots,
        threshold_mb=args.threshold_mb,
        ignore_patterns=args.ignore_pattern,
        exclude_dirs=args.exclude_dir,
        follow_symlinks=args.follow_symlinks,
        algo=args.algo,
        wants_baseline=wants_baseline,
        progress_event_callback=None,
        strip_mount_prefix=args.strip_mount_prefix or "",
        max_depth=args.max_depth,
        max_workers=effective_workers,
        legacy_scanner_stats=args.legacy_scanner_stats,
    )
    roots_abs = stats.roots

    stdout_is_payload = any(
        p == "-"
        for p in (emit_checksums_path, emit_csv, emit_json_path, emit_jsonl_path)
        if p is not None
    )

    # JSONL output: SIEM-ready stream with per-file scan_record and terminal scan_summary.
    if emit_jsonl_path:
        dest = sys.stdout if emit_jsonl_path == "-" else open(
            emit_jsonl_path, "w", encoding="utf-8"
        )
        try:
            for rec in records:
                ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
                root_idx = int(rec.get("root_index", 0))
                root_path_raw = roots_abs[root_idx] if 0 <= root_idx < len(roots_abs) else roots_abs[0]
                dest.write(
                    json.dumps(
                        {
                            "timestamp": ts,
                            "event_type": "scan_record",
                            "path": rec["path"],
                            "algo": rec["algo"],
                            "digest": rec["digest"],
                            "bytes": rec["bytes"],
                            "mtime": rec["mtime"],
                            "status": rec.get("status", "baseline"),
                            "root_index": root_idx,
                            "root_path": _strip_mount_prefix(
                                root_path_raw, args.strip_mount_prefix or ""
                            ),
                        }
                    )
                    + "\n"
                )

            ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
            summary = {
                "timestamp": ts,
                "event_type": "scan_summary",
                "files_scanned": stats.files_scanned,
                "candidate_files": stats.candidate_files,
                "attested_files": stats.attested_files,
                "unattested_files": stats.unattested_files,
                "total_bytes": stats.total_bytes,
                "attested_bytes": stats.attested_bytes,
                "unattested_bytes": stats.unattested_bytes,
                "attested_f33_files": stats.attested_f33_files,
                "attested_external_files": stats.attested_external_files,
                "attested_f33_bytes": stats.attested_f33_bytes,
                "attested_external_bytes": stats.attested_external_bytes,
                "skipped_files": stats.skipped_files,
                "mutated_during_scan": stats.mutated_during_scan,
                "exposure_ratio": stats.exposure_ratio,
                "risk_level": stats.risk_level,
                "threshold_mb": args.threshold_mb,
                "algo": args.algo,
                "workers": effective_workers,
                "max_depth": args.max_depth,
            }
            dest.write(json.dumps(summary) + "\n")
        finally:
            if dest is not sys.stdout:
                dest.close()

    # Exit code contract: mutated forces exit 1; max-exposure breach forces exit 1.
    exit_code = 1 if stats.mutated_during_scan > 0 else 0
    if (
        args.max_exposure is not None
        and stats.total_bytes > 0
        and stats.exposure_ratio > args.max_exposure
    ):
        print(
            f"[ERROR] Exposure ratio {stats.exposure_ratio:.3f} exceeds maximum threshold of {args.max_exposure}",
            file=sys.stderr,
        )
        exit_code = 1

    if wants_baseline:

        if emit_checksums_path:
            if emit_checksums_path == "-":
                _write_checksums(records, sys.stdout)
            else:
                with open(emit_checksums_path, "w", encoding="utf-8") as f:
                    _write_checksums(records, f)

        if emit_csv:
            if emit_csv == "-":
                _write_csv(records, sys.stdout)
            else:
                with open(emit_csv, "w", newline="", encoding="utf-8") as f:
                    _write_csv(records, f)

        if emit_json_path:
            if emit_json_path == "-":
                _write_json_baseline(
                    records, roots_abs, args.algo, sys.stdout,
                    stats=stats, strip_mount_prefix=args.strip_mount_prefix or "",
                )
            else:
                with open(emit_json_path, "w", encoding="utf-8") as f:
                    _write_json_baseline(
                        records, roots_abs, args.algo, f,
                        stats=stats, strip_mount_prefix=args.strip_mount_prefix or "",
                    )

    # Summary output: respect existing --json behavior, but avoid polluting stdout when
    # it has been used for baseline payloads.
    if args.json and not stdout_is_payload:
        payload = asdict(stats)
        payload.update(
            {
                "exposure_ratio": stats.exposure_ratio,
                "risk_level": stats.risk_level,
            }
        )
        print(json.dumps(payload))
    elif not args.json and not stdout_is_payload:
        print_human_report(stats, compliance_report=args.compliance_report)

    sys.exit(exit_code)


if __name__ == "__main__":
    main()

