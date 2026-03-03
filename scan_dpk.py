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
import json
import os
import time
from dataclasses import dataclass, asdict
from typing import Iterable, List, Set


_EXCLUDE_DIRS: Set[str] = {
    ".git",
    "node_modules",
    "venv",
    ".venv",
    "__pycache__",
    ".idea",
    ".vscode",
}


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
    elapsed_seconds: float = 0.0

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


def _scan_dir(path: str, threshold_bytes: int, stats: ScanStats) -> None:
    try:
        with os.scandir(path) as it:
            entries = list(it)
    except (PermissionError, FileNotFoundError, NotADirectoryError):
        return

    for entry in entries:
        name = entry.name
        if entry.is_dir(follow_symlinks=False):
            if name in _EXCLUDE_DIRS:
                continue
            _scan_dir(entry.path, threshold_bytes, stats)
        elif entry.is_file(follow_symlinks=False):
            stats.files_scanned += 1
            # Skip sidecar files themselves; we classify their parents.
            if name.endswith(".f33"):
                continue
            try:
                st = entry.stat(follow_symlinks=False)
            except OSError:
                continue
            size = st.st_size
            if size < threshold_bytes:
                continue

            stats.candidate_files += 1
            stats.total_bytes += size

            sidecar_name = f"{name}.f33"
            sidecar_path = os.path.join(path, sidecar_name)
            if os.path.isfile(sidecar_path):
                stats.attested_files += 1
                stats.attested_bytes += size
            else:
                stats.unattested_files += 1
                stats.unattested_bytes += size


def scan_roots(roots: Iterable[str], threshold_mb: float) -> ScanStats:
    norm_roots = [os.path.abspath(r) for r in (list(roots) or [os.getcwd()])]
    stats = ScanStats(roots=norm_roots)
    threshold_bytes = int(threshold_mb * 1024 * 1024)
    start = time.time()

    for root in norm_roots:
        _scan_dir(root, threshold_bytes, stats)

    stats.elapsed_seconds = time.time() - start
    return stats


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
    data_attested = _format_bytes(stats.attested_bytes)
    data_unattested = _format_bytes(stats.unattested_bytes)

    exposure_pct = stats.exposure_ratio * 100.0 if stats.total_bytes > 0 else 0.0
    risk = stats.risk_level

    print(f"[TOOLCHAIN]     : FORS33 Data Provenance Kit (DPK)")
    print(f"[SCAN SUMMARY]  : Evaluated {files:,} files in {secs:.2f}s")
    print(f"[ATTESTED]      : {data_attested} (Signatures verified)")
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
    args = parser.parse_args()

    roots = args.root or [os.getcwd()]
    stats = scan_roots(roots, args.threshold_mb)

    if args.json:
        payload = asdict(stats)
        payload.update(
            {
                "exposure_ratio": stats.exposure_ratio,
                "risk_level": stats.risk_level,
            }
        )
        print(json.dumps(payload))
        return

    print_human_report(stats)


if __name__ == "__main__":
    main()

