# Changelog

All notable changes to fors33-scanner are documented here.

## [0.2.0] - 2026-03-02

### Added

- **Baseline generation**: `--emit-sha256sum`, `--emit-csv`, `--emit-json` for sha256sum-style, CSV, and JSON baselines.
- **PATH=-**: Emit baselines to stdout (e.g. `--emit-json -`) for piping.
- **Ignore patterns**: Root-level `.f33ignore` plus CLI `--ignore-pattern` / `--exclude-dir`.
- **Symlinks**: `--follow-symlinks` to traverse symlinked directories.
- **Progress indicator**: In-place progress for large files (≥500MB) when stderr is a TTY.
- **Bounded concurrency**: ThreadPoolExecutor with configurable worker count.
- **Summary object**: JSON baseline includes nested `summary` with high-level stats (no concatenated top-level objects).
- **Standardized stderr**: `[WARNING]` / `[ERROR]` prefixes; machine-readable output on stdout only.
- **Counters**: `skipped_files` and `mutated_during_scan` for audit.

### Changed

- Chunk size fixed at 4MB for hashing.
- Single directory walk for scan + baseline (no second os.walk).
- Locked/permission-denied files counted once in `skipped_files` (no double-counting).

### Dependencies

- Standard library only for scan-only use. Optional `blake3` for baseline generation.

### Support matrix

- Python 3.9, 3.10, 3.11, 3.12
- Linux, macOS, Windows
