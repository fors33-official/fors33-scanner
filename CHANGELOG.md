# Changelog

All notable changes to fors33-scanner are documented here.

## [0.3.0] - 2026-03-10

### Added

- **--compliance-report**: SEC/ESIC exposure text behind flag; default human output strictly mathematical (File Count, Total Bytes, Attested/Unattested, Elapsed).
- **--emit-checksums**: Renamed from --emit-sha256sum; supports sha256, sha512, blake3 in Hash Filename format. --emit-sha256sum retained as deprecated alias.
- **Multi-root baselines**: JSON schema supports `roots` and per-file `root_index`; backward compatible with single-root `root`.
- **Environment variables**: FORS33_ALGO, FORS33_THRESHOLD_MB, FORS33_ROOT, FORS33_FOLLOW_SYMLINKS, FORS33_IGNORE_PATTERN, FORS33_EXCLUDE_DIR with strict boolean parser.
- **Blake3 fail-fast**: Exit with clear error if --algo blake3 requested but blake3 not installed.
- **Ctrl+C handling**: ThreadPoolExecutor wrapped for responsive KeyboardInterrupt (exit 130).

### Changed

- Default human output: File Count, Total Bytes, Attested/Unattested files and bytes, Elapsed only.
- Progress bar: `\r\033[K[SCAN] Hashing {rel}: {pct}%` for glitch-free display.
- Scanner repositioned as high-speed universal file-integrity tool in README/LLM_CONTEXT.
- Entrypoint simplified to `set -e` and `exec fors33-scanner "$@"`.

### Security

- Scanner warns when generating baselines with md5/sha1; verifier rejects weak algos by default (--force-insecure override).

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
