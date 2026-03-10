#!/usr/bin/env python3
"""
FORS33 Liability Scanner (open source)

High-speed, read-only scanner that walks one or more roots using os.scandir,
measures "data gravity" (bytes) for large files, and classifies them as
attested or unattested based on presence of a sibling .f33 sidecar.

This module is standalone: no network calls, no telemetry. Designed for
enterprise environments and CI pipelines.
"""
from __future__ import annotations

import argparse
import csv
import fnmatch
import json
import os
import sys
import time
from dataclasses import dataclass, asdict
from typing import Dict, Iterable, List, Set

try:
    from .hash_core import hash_file
except ImportError:  # pragma: no cover - flat layout
    from hash_core import hash_file


_EXCLUDE_DIRS: Set[str] = {
    ".git",
    "node_modules",
    "venv",
    ".venv",
    "__pycache__",
    ".idea",
    ".vscode",
}

# Recognized attestation sidecar extensions. .f33 is the deterministic FΦRS33
# standard; the others are external/legacy formats we respect for coverage.
_F33_EXT = ".f33"
_ATT_EXTS = (
    _F33_EXT,
    ".sig",
    ".asc",
    ".sha256",
    ".sha512",
    ".md5",
    ".pem",
)
_EXTERNAL_EXTS = tuple(ext for ext in _ATT_EXTS if ext != _F33_EXT)


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


def _matches_ignore(rel_path: str, patterns: List[str]) -> bool:
    if not patterns:
        return False
    # Normalize to forward slashes for pattern matching.
    rel_norm = rel_path.replace("\\", "/")
    for pat in patterns:
        if fnmatch.fnmatch(rel_norm, pat):
            return True
    return False


def _scan_dir(
    path: str,
    root: str,
    threshold_bytes: int,
    stats: ScanStats,
    ignore_patterns: List[str],
    extra_exclude_dirs: Set[str],
    follow_symlinks: bool,
    visited_dirs: Set[tuple[int, int]],
) -> None:
    try:
        st_dir = os.stat(path, follow_symlinks=False)
    except OSError:
        return

    key = (st_dir.st_dev, st_dir.st_ino)
    if key in visited_dirs:
        # Prevent infinite recursion when following symlinks.
        return
    visited_dirs.add(key)
    try:
        with os.scandir(path) as it:
            entries = list(it)
    except (PermissionError, FileNotFoundError, NotADirectoryError, OSError):
        # Entire directory is unreadable; treat contents as skipped.
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
            rel_dir = os.path.relpath(entry_path, root)
            if _matches_ignore(rel_dir, ignore_patterns):
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
            )
        elif entry.is_file(follow_symlinks=follow_symlinks):
            stats.files_scanned += 1
            # Skip sidecar files themselves; we classify their parents.
            if any(name.endswith(ext) for ext in _ATT_EXTS):
                continue
            rel_path = os.path.relpath(entry_path, root)
            if _matches_ignore(rel_path, ignore_patterns):
                continue
            try:
                st = entry.stat(follow_symlinks=follow_symlinks)
            except OSError:
                stats.skipped_files += 1
                continue
            size = st.st_size
            if size < threshold_bytes:
                continue

            stats.candidate_files += 1
            stats.total_bytes += size

            has_f33 = f"{name}{_F33_EXT}" in filenames
            has_external = False
            if not has_f33:
                for ext in _EXTERNAL_EXTS:
                    if f"{name}{ext}" in filenames:
                        has_external = True
                        break

            if has_f33:
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


def scan_roots(
    roots: Iterable[str],
    threshold_mb: float,
    ignore_patterns: List[str] | None = None,
    exclude_dirs: List[str] | None = None,
    follow_symlinks: bool = False,
) -> ScanStats:
    norm_roots = [os.path.abspath(r) for r in (list(roots) or [os.getcwd()])]
    stats = ScanStats(roots=norm_roots)
    threshold_bytes = int(threshold_mb * 1024 * 1024)
    start = time.time()

    extra_exclude_dirs: Set[str] = set(exclude_dirs or [])
    base_ignore_patterns: List[str] = list(ignore_patterns or [])

    for root in norm_roots:
        root_patterns = base_ignore_patterns + _load_f33ignore_patterns(root)
        visited_dirs: Set[tuple[int, int]] = set()
        _scan_dir(
            root,
            root,
            threshold_bytes,
            stats,
            root_patterns,
            extra_exclude_dirs,
            follow_symlinks,
            visited_dirs,
        )

    stats.elapsed_seconds = time.time() - start
    return stats


def _walk_and_collect(
    root: str,
    threshold_bytes: int,
    ignore_patterns: List[str],
    exclude_dirs: Set[str],
    follow_symlinks: bool,
) -> tuple[ScanStats, List[tuple[str, str, int, float]]]:
    """
    Single directory walk that collects scan stats and candidate files for baseline.
    Returns (stats, candidates). No second os.walk; skipped_files counted once.
    """
    from concurrent.futures import ThreadPoolExecutor

    root_abs = os.path.abspath(root)
    stats = ScanStats(roots=[root_abs])
    visited_dirs: Set[tuple[int, int]] = set()
    candidates: List[tuple[str, str, int, float]] = []
    start = time.time()

    for dirpath, dirnames, filenames in os.walk(root_abs, followlinks=follow_symlinks):
        try:
            st_dir = os.stat(dirpath, follow_symlinks=False)
        except OSError:
            continue
        key = (st_dir.st_dev, st_dir.st_ino)
        if key in visited_dirs:
            continue
        visited_dirs.add(key)
        dirnames[:] = [
            d for d in dirnames if d not in _EXCLUDE_DIRS and d not in exclude_dirs
        ]
        filenames_set = set(filenames)
        for name in filenames:
            if any(name.endswith(ext) for ext in _ATT_EXTS):
                continue
            full_path = os.path.join(dirpath, name)
            rel_path = os.path.relpath(full_path, root_abs)
            norm_rel = rel_path.replace("\\", "/")
            if ignore_patterns and _matches_ignore(norm_rel, ignore_patterns):
                continue
            stats.files_scanned += 1
            try:
                st = os.stat(full_path, follow_symlinks=follow_symlinks)
            except OSError:
                stats.skipped_files += 1
                continue
            size = st.st_size
            if size < threshold_bytes:
                continue
            stats.candidate_files += 1
            stats.total_bytes += size
            has_f33 = f"{name}{_F33_EXT}" in filenames_set
            has_external = not has_f33 and any(
                f"{name}{ext}" in filenames_set for ext in _EXTERNAL_EXTS
            )
            if has_f33:
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
            candidates.append((norm_rel, full_path, size, st.st_mtime))

    stats.elapsed_seconds = time.time() - start
    return stats, candidates


def _hash_candidates(
    candidates: List[tuple[str, str, int, float]],
    algo: str,
    follow_symlinks: bool,
    stats: ScanStats,
) -> List[Dict[str, object]]:
    """Hash candidate files and return baseline records; update stats.skipped_files and mutated_during_scan."""
    from concurrent.futures import ThreadPoolExecutor

    records: List[Dict[str, object]] = []
    max_workers = min(32, (os.cpu_count() or 1) + 4)

    def _worker(item: tuple[str, str, int, float]):
        rel, full_path, size, mtime_before = item
        try:
            progress_cb = None
            if size >= 500 * 1024 * 1024 and sys.stderr.isatty():
                last_pct = [0]

                def _progress(br: int, tb: int) -> None:
                    if tb > 0:
                        pct = min(100, int(br * 100 / tb))
                        if pct != last_pct[0] and (pct % 5 == 0 or pct == 100):
                            last_pct[0] = pct
                            print(f"\r[SCAN] Hashing {rel}: {pct}%", end="", file=sys.stderr)

                progress_cb = _progress
            digest = hash_file(full_path, algo=algo, progress_callback=progress_cb)
            if progress_cb and sys.stderr.isatty():
                print(file=sys.stderr)
            mtime_after = os.stat(full_path, follow_symlinks=follow_symlinks).st_mtime
        except Exception as e:
            print(f"[ERROR] Unhandled worker exception: {e}", file=sys.stderr)
            return (rel, size, mtime_before, None, True, False)
        mutated = mtime_before != mtime_after
        return (rel, size, mtime_after, digest, False, mutated)

    for rel, size, mtime_final, digest, skipped, mutated in ThreadPoolExecutor(
        max_workers=max_workers
    ).map(_worker, candidates):
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
            }
        )
    return records


def _compute_baseline(
    root: str,
    threshold_bytes: int,
    algo: str,
    follow_symlinks: bool,
    stats: ScanStats | None = None,
    ignore_patterns: List[str] | None = None,
    exclude_dirs: Set[str] | None = None,
) -> List[Dict[str, object]]:
    """
    Walk a single root and compute baseline records for all candidate files.
    Uses single walk when stats provided (no second os.walk).
    """
    extra_exclude = exclude_dirs or set()
    ignore_list = ignore_patterns or []
    if stats is not None:
        walk_stats, candidates = _walk_and_collect(
            root, threshold_bytes, ignore_list, extra_exclude, follow_symlinks
        )
        stats.files_scanned = walk_stats.files_scanned
        stats.candidate_files = walk_stats.candidate_files
        stats.total_bytes = walk_stats.total_bytes
        stats.attested_files = walk_stats.attested_files
        stats.attested_bytes = walk_stats.attested_bytes
        stats.unattested_files = walk_stats.unattested_files
        stats.unattested_bytes = walk_stats.unattested_bytes
        stats.attested_f33_files = walk_stats.attested_f33_files
        stats.attested_f33_bytes = walk_stats.attested_f33_bytes
        stats.attested_external_files = walk_stats.attested_external_files
        stats.attested_external_bytes = walk_stats.attested_external_bytes
        stats.skipped_files = walk_stats.skipped_files
        stats.elapsed_seconds = walk_stats.elapsed_seconds
        return _hash_candidates(candidates, algo, follow_symlinks, stats)
    stats_placeholder = ScanStats(roots=[os.path.abspath(root)])
    _, candidates = _walk_and_collect(
        root, threshold_bytes, ignore_list, extra_exclude, follow_symlinks
    )
    return _hash_candidates(candidates, algo, follow_symlinks, stats_placeholder)


def _write_shasum(records: List[Dict[str, object]], dest) -> None:
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
    root: str,
    algo: str,
    dest,
    stats: ScanStats | None = None,
) -> None:
    file_count = len(records)
    total_bytes = sum(r.get("bytes", 0) for r in records)
    payload = {
        "schema_version": "0.2",
        "root": os.path.abspath(root),
        "algo": algo,
        "files": records,
        "summary": {
            "file_count": file_count,
            "total_bytes": total_bytes,
            "skipped_files": (stats.skipped_files if stats else 0),
            "mutated_during_scan": (stats.mutated_during_scan if stats else 0),
        },
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


def print_human_report(stats: ScanStats) -> None:
    files = stats.files_scanned
    secs = stats.elapsed_seconds or 0.0
    data_external = _format_bytes(stats.attested_external_bytes)
    data_f33 = _format_bytes(stats.attested_f33_bytes)
    data_unattested = _format_bytes(stats.unattested_bytes)

    exposure_pct = stats.exposure_ratio * 100.0 if stats.total_bytes > 0 else 0.0
    risk = stats.risk_level

    print(f"[TOOLCHAIN]     : FORS33 Data Provenance Kit (DPK)")
    print(f"[SCAN SUMMARY]  : Evaluated {files:,} files in {secs:.2f}s")
    print(
        "[ATTESTED]      : "
        f"{data_external} (External: .sig, .asc, .sha256, .sha512, .md5, .pem)"
    )
    print(
        f"[ATTESTED]      : {data_f33} (FΦRS33 Deterministic Sidecars)"
    )
    print(f"[UNATTESTED]    : {data_unattested} (Signatures missing)")
    print()
    print(f"[EXPOSURE RISK] : {exposure_pct:.1f}% volume exposed to silent mutation")
    print(f"[SEVERITY]      : {risk}")
    print(
        "[COMPLIANCE]    : Fails SEC 17a-4 (WORM) and ESIC chain-of-custody controls"
    )
    print(
        "[REMEDIATION]   : Enforce deterministic attestation on exposed directories."
    )
    print(
        "[REFERENCE]     : fors33.com | GitHub Marketplace: FORS33"
    )


def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "FORS33 Liability Scanner — quantify attested vs unattested data bytes "
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
        "--json",
        action="store_true",
        help="Emit JSON summary to stdout instead of human-readable report.",
    )
    parser.add_argument(
        "--emit-sha256sum",
        metavar="PATH",
        help=(
            "Write a sha256sum-style baseline for all candidate files. "
            "Use '-' to write to stdout."
        ),
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
        "--algo",
        choices=["sha256", "sha512", "blake3"],
        default="sha256",
        help="Hash algorithm to use when generating baselines. Default: sha256.",
    )
    args = parser.parse_args()

    roots = args.root or [os.getcwd()]
    emit_shasum = args.emit_sha256sum
    emit_csv = args.emit_csv
    emit_json_path = args.emit_json_path
    wants_baseline = bool(emit_shasum or emit_csv or emit_json_path)

    if wants_baseline and len(roots) != 1:
        print(
            "[ERROR] Baseline generation (--emit-*) currently supports a single --root only.",
            file=sys.stderr,
        )
        return

    # Single walk when baseline needed: collect stats + candidates in one pass.
    if wants_baseline:
        root = roots[0]
        threshold_bytes = int(args.threshold_mb * 1024 * 1024)
        base_ignore = list(args.ignore_pattern or []) + _load_f33ignore_patterns(root)
        stats, candidates = _walk_and_collect(
            root,
            threshold_bytes,
            base_ignore,
            set(args.exclude_dir or []),
            args.follow_symlinks,
        )
        records = _hash_candidates(
            candidates, args.algo, args.follow_symlinks, stats
        )
    else:
        stats = scan_roots(
            roots,
            args.threshold_mb,
            ignore_patterns=args.ignore_pattern,
            exclude_dirs=args.exclude_dir,
            follow_symlinks=args.follow_symlinks,
        )
        records = []

    stdout_is_payload = any(
        p == "-"
        for p in (emit_shasum, emit_csv, emit_json_path)
        if p is not None
    )

    if emit_shasum and args.algo != "sha256":
        print(
            "[ERROR] --emit-sha256sum requires --algo sha256 (sha256sum format).",
            file=sys.stderr,
        )
        return

    if wants_baseline:

        if emit_shasum:
            if emit_shasum == "-":
                _write_shasum(records, sys.stdout)
            else:
                with open(emit_shasum, "w", encoding="utf-8") as f:
                    _write_shasum(records, f)

        if emit_csv:
            if emit_csv == "-":
                _write_csv(records, sys.stdout)
            else:
                with open(emit_csv, "w", newline="", encoding="utf-8") as f:
                    _write_csv(records, f)

        if emit_json_path:
            if emit_json_path == "-":
                _write_json_baseline(records, root, args.algo, sys.stdout, stats=stats)
            else:
                with open(emit_json_path, "w", encoding="utf-8") as f:
                    _write_json_baseline(records, root, args.algo, f, stats=stats)

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
        return

    if not args.json and not stdout_is_payload:
        print_human_report(stats)


if __name__ == "__main__":
    main()

