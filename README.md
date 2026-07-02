# fors33-scanner

[![CI](https://img.shields.io/github/actions/workflow/status/fors33-official/fors33-scanner/publish-fors33-scanner.yml?branch=main&style=flat-square)](https://github.com/fors33-official/fors33-scanner/actions)
[![Release](https://img.shields.io/badge/release-v0.8.4-blue?style=flat-square)](https://pypi.org/project/fors33-scanner/)
[![PyPI](https://img.shields.io/pypi/v/fors33-scanner?style=flat-square)](https://pypi.org/project/fors33-scanner/)
[![Docker Tag](https://img.shields.io/badge/docker-v0.8.4%20%7C%20latest-2496ED?style=flat-square&logo=docker&logoColor=white)](https://hub.docker.com/r/fors33/fors33-scanner)
[![Docker Pulls](https://img.shields.io/docker/pulls/fors33/fors33-scanner?style=flat-square)](https://hub.docker.com/r/fors33/fors33-scanner)
[![License](https://img.shields.io/github/license/fors33-official/fors33-scanner?style=flat-square)](https://github.com/fors33-official/fors33-scanner/blob/main/LICENSE)

High-speed file integrity and baseline scanner. Walks one or more roots, measures data gravity (bytes), and classifies large files as attested or unattested based on sibling sidecar presence (.f33, .sig, .asc, .sha256, .sha512, .blake3, .md5, .pem). Emits checksum baselines (Hash Filename format), CSV, or JSON for use with fors33-verifier.

**Trust model:** The scanner is an O(1) discovery and liability mapping tool based on sidecar presence only. It does not validate Ed25519 signatures or cryptographic proof of baselines. For full cryptographic verification, use fors33-verifier.

For machine parsing, see [LLM_CONTEXT.md](LLM_CONTEXT.md).

<details>
<summary><strong>Release notes &amp; version history</strong></summary>

### v0.8.4 (2026-07-02)

- **Baseline single-file roots**: `execute_scan(..., wants_baseline=True)` on a file path now emits baseline records (previously returned zero candidates).

### v0.8.3 (2026-07-02)

- **Unified release semver**: Git tags, PyPI, `workflow_dispatch` `version`, and Docker images all use `vX.Y.Z` (e.g. `v0.8.3`, `:v0.8.3`).

### v0.8.2 (2026-07-02)

- **BagIt scan alignment** with L3dgr extension: shared `manifest_core` helpers; payload members under BagIt `data/` count as attested during directory walks.
- **`is_epoch_upload_companion_basename`** in `hash_core` (epoch bundle companion skips).

### 0.8.1 (2026-05-10)

- **Backward-compatible stats (pre-0.8.0 accounting)**: **`--legacy-scanner-stats`** or **`FORS33_SCANNER_LEGACY_STATS=1`** restores single-file below-threshold **`skipped_files`** counting and treats **`.blake3`** siblings as **not** conferring external attestation coverage (library: **`legacy_scanner_stats`** bundles both; **`below_threshold_single_file_counts_skipped`** and **`recognize_blake3_sidecar`** remain available separately on **`scan_roots`** / **`execute_scan`**).

### 0.8.0 (2026-05-10)

- **Single-file parity** with the Docker extension: `_scan_single_file` uses **`stat(..., follow_symlinks=False)`**, **`os.scandir`** sibling discovery with **`is_file(follow_symlinks=False)`**, skips when the **root basename** is itself a recognized sidecar suffix, and applies to **`scan_roots`** as well as **`execute_scan`**.
- **`.blake3`** is part of **`_ATT_EXTS`** so BLAKE3 companions classify as external attestation coverage.
- Below-threshold single-file paths no longer bump **`skipped_files`** (silent skip, extension-style).

### 0.7.1 (2026-05-10)

- **`has_sidecar` on unverified samples**: `ScanStats.add_unverified_sample(..., *, has_sidecar=False)` records `"has_sidecar": "true"` or `"false"` on each sampled unattested path (same shape as the L3dgr extension) for downstream re-seal UX.
- **Supply chain**: Docker images from `publish-fors33-scanner` attach **SBOM** and **SLSA provenance** (`sbom: true`, `provenance: mode=max`). Pin by digest for regulated deployments.

### 0.7.0 (2026-05-01)

- Single-file scanning roots, sidecar parity (`.f33`, `.sig`, `.asc`, checksum sidecars, etc.), baseline/JSON/JSONL on single-file paths, stricter `--strict-audit` and zero-byte threshold behavior.

### 0.6.0 (2026-04-16)

- `hash_core` mmap ceilings, cgroup alignment, worker cap **64**, `default_dpk_worker_count()` / `FORS33_DPK_MAX_WORKERS`.

### 0.5.0 and 0.4.0

- `--strict-audit`, `unverified_paths_sample`, `--tsa-url`, JSONL multi-root metadata, `--max-exposure`, `--emit-jsonl`, `--max-depth`. Full text: [CHANGELOG.md](CHANGELOG.md).

### Release model

- Docker publish is **manual** via GitHub Actions **`workflow_dispatch`** with explicit **`version`** = `vX.Y.Z` (e.g. `v0.8.3`) and **`push_latest`**; bare `X.Y.Z` is **rejected**. It does **not** run automatically on git tags alone. PyPI releases use the same `vX.Y.Z` string in `pyproject.toml` (`python -m build`, `twine upload`).

</details>

## Install

```bash
pip install fors33-scanner
```

## Usage

Scan the current directory (default root) with a 1 MB threshold:

```bash
fors33-scanner --threshold-mb 1.0
```

Scan multiple roots:

```bash
fors33-scanner --root /var/log --root /data/telemetry --threshold-mb 10
```

Emit JSON instead of human output (for CI, pipelines):

```bash
fors33-scanner --root /data --json
```

Fail CI/CD when exposure breaches policy threshold:

```bash
fors33-scanner --root /data --max-exposure 5.0 --json
```

Throttle hashing workers for shared runners:

```bash
fors33-scanner --root /data --workers 2
```

Stream SIEM-ready JSONL events (records + summary):

```bash
fors33-scanner --root /data --emit-jsonl -
```

Depth-limit traversal (`0=root only`, `1=root + direct children`):

```bash
fors33-scanner --root /data --max-depth 1
```

Strict audit (fail on permission or file-lock errors instead of skipping):

```bash
fors33-scanner --root /data --strict-audit
```

**Single-file scanning:**

```bash
# Scan a single file
fors33-scanner --root /path/to/file.csv

# Scan a single file with baseline generation
fors33-scanner --root /path/to/file.csv --emit-checksums baseline.txt

# Scan a single file with JSON manifest
fors33-scanner --root /path/to/file.csv --emit-json manifest.json
```
Single-file mode accepts individual file paths in addition to directories, enabling direct scanning of specific files without directory traversal. By default it recognizes all attestation sidecar extensions (.f33, .sig, .asc, .sha256, .sha512, .blake3, .md5, .pem) for parity with directory scanning.

Pre-0.8.0 stats (below-threshold single-file roots bump `skipped_files`, and `.blake3` siblings are not counted as external attestation):

```bash
fors33-scanner --root /data --legacy-scanner-stats
```

Equivalent: set **`FORS33_SCANNER_LEGACY_STATS=1`**.

Record TSA endpoint for tooling that reads `FORS33_TSA_URL`:

```bash
fors33-scanner --tsa-url https://tsa.example.com/rfc3161
```

Worker count: **positive `--workers`** wins; otherwise a **positive `FORS33_WORKERS`**; otherwise **`default_dpk_worker_count()`** (uses `cpu_count` and optional **`FORS33_DPK_MAX_WORKERS`**). Non-positive values mean auto. Hard cap **64**.

Large-file hashing uses **`FORS33_MMAP_MIN_MB`** / **`FORS33_MMAP_MAX_MB`** (defaults `500` / `4000`), clamped to cgroup/RAM ceiling on Linux; optional **`FORS33_MMAP_PSI_SOME_AVG10_MAX`** disables mmap under memory pressure.

For production Docker or CI, **pin** a **semver image tag** or **immutable digest** instead of relying on `:latest` alone.

Generate checksum baseline (sha256, sha512, or blake3 per --algo):

```bash
fors33-scanner --root /data --emit-checksums fors33_baseline.sha256
fors33-scanner --root /data --algo sha512 --emit-checksums fors33_baseline.sha512
```

Emit CSV or JSON baseline (compatible with fors33-verifier):

```bash
fors33-scanner --root /data --emit-csv fors33_baseline.csv
fors33-scanner --root /data --emit-json fors33_baseline.json
```

Add compliance exposure text to human output (default is strictly mathematical):

```bash
fors33-scanner --root /data --compliance-report
```

## Exit codes

- `0`: successful scan / threshold not breached
- `1`: exposure threshold breach (`--max-exposure`)
- `2`: invocation/parameter misuse, or **`--strict-audit`** I/O access failure
- `130`: user interrupted scan (Ctrl+C)

## Output

Default human output (mathematical only):

```text
[FILE COUNT]    : 14,205
[TOTAL BYTES]   : 2.1 TB
[ATTESTED]      : 48 files, 4.1 GB
[UNATTESTED]    : 264 files, 2.1 TB
[ELAPSED]       : 4.20s
```

## Safety and scope

- Read-only: does not modify files or sidecars.
- Scan-only: O(1) discovery; baseline generation uses streaming chunked hashing.
- Excludes common dirs (.git, node_modules, venv, etc). Respects .f33ignore and --ignore-pattern / --exclude-dir.
- Legal notice prints to `stderr` on startup so data/JSON streams on `stdout` remain parse-safe.
- See `DISCLAIMER.md` for enterprise legal/regulatory boundaries.

## JSONL contract

- `--emit-jsonl PATH` emits one flat JSON object per line.
- Multi-root scans include both `root_index` and `root_path` in each `scan_record`.
- `timestamp` represents hash completion time.
- Final line is `scan_summary` with aggregate stats and scan parameters.
- If `--emit-jsonl -` and `--json` are both requested, JSONL takes precedence on `stdout`.
- **`unverified_paths_sample`** entries (JSON/JSONL consumers): each row includes **`path`**, **`status`**, and **`has_sidecar`** (`"true"` / `"false"`) since **0.7.1** for integration with seal/re-seal workflows.

## Requirements

Python 3.9+. Optional `blake3` for BLAKE3 hashing. Linux, macOS, Windows.

## License

MIT License. See `LICENSE`.
