# Changelog

All notable changes to fors33-scanner are documented here.

## [0.6.0] - 2026-04-16

### Added

- **`hash_core`**: cgroup v2/v1 + visible RAM mmap ceiling, `FORS33_MMAP_MIN_MB` / `FORS33_MMAP_MAX_MB` clamp, optional `FORS33_MMAP_PSI_SOME_AVG10_MAX`, whole-file mmap gating, `default_dpk_worker_count()` with `FORS33_DPK_MAX_WORKERS` (no read-throttle API in scanner).

### Changed

- **Workers**: positive `--workers` wins; else positive `FORS33_WORKERS`; else `default_dpk_worker_count()`; cap **64**; removed **`FORS33_EXTENSION_MODE`**; `FORS33_WORKERS` no longer overrides a positive CLI value.

## [0.5.0] - 2026-03-31

### Added

- **`_default_worker_count()`** and **`FORS33_EXTENSION_MODE`**: extension profile uses 4 workers; otherwise `min(32, cpu+4)`.
- **`--strict-audit`**: raises `StrictAuditFatal` (exit **2**) on permission/locking I/O errors instead of skipping.
- **`unverified_paths_sample`**: up to **300** sample paths for unattested candidates (walk + scandir paths).
- **`--tsa-url`**: sets `FORS33_TSA_URL` after parse for downstream seal tooling.
- **Reference-aligned legal banner** lines on stderr at startup.

### Changed

- **Dockerfile / `Dockerfile.ci`**: Alpine cache cleanup (`rm -rf /var/cache/apk/*`) after upgrade, matching fors33-verifier hardening; multi-stage layout documented in-file.
- **Worker resolution**: `max_workers` / `execute_scan`; `<= 0` or unset uses default; positive values capped at **64**; `FORS33_WORKERS` overwrites `--workers` after parse.
- **Depth semantics**: aligned with reference (`_depth_from_root(root, path)`; walk collects files at `max_depth` without descending further).
- **JSONL `scan_summary`**: includes stratified attested f33/external counts and bytes; `workers` reports **effective** thread count.

## [0.4.0] - 2026-03-24

### Added

- **`--max-exposure` gate**: CI/CD threshold enforcement with exit code `1` when exposure exceeds configured percentage.
- **`--workers` control**: explicit hashing worker override with hard ceiling (`MAX_WORKERS=64`) for safe shared-runner behavior.
- **`--emit-jsonl` stream**: SIEM-ready JSON Lines output with per-record events and final `scan_summary`.
- **Multi-root JSONL metadata**: each `scan_record` includes `root_index` and `root_path`.
- **`--max-depth` traversal limit**: find-style depth semantics (`0=root`, `1=root+children`) for bounded scans.
- **Mmap env controls**: `FORS33_MMAP_MIN_MB` and `FORS33_MMAP_MAX_MB` (defaults `500` and `4000`) for bounded large-file mmap hashing.
- **`DISCLAIMER.md`**: enterprise legal/regulatory boundary documentation in repository root.
- **Scanner `.dockerignore`**: hardened build context hygiene aligned with verifier patterns.

### Changed

- Exit-code contract is explicit and stable:
  - `0` success / threshold not breached
  - `1` exposure threshold breach
  - `2` parameter misuse
  - `130` user interrupt
- Legal startup notice now prints to `stderr` to keep `stdout` machine-readable.
- When both `--emit-jsonl -` and `--json` are requested, JSONL stream takes precedence on `stdout`.
- Depth calculation uses normalized cross-platform path handling for Windows/POSIX consistency.
- Docker build flows moved to hardened multi-stage `python:3.13-alpine` model with pinned build tooling.
- Publish workflow is manual `workflow_dispatch` only with explicit `version` and `push_latest` inputs.

## [0.3.0] - 2026-03-10

### Added

- **--compliance-report**: SEC/ESMA exposure text behind flag; default human output strictly mathematical (File Count, Total Bytes, Attested/Unattested, Elapsed).
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
