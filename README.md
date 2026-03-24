# fors33-scanner

[![CI](https://img.shields.io/github/actions/workflow/status/fors33-official/fors33-scanner/publish-fors33-scanner.yml?branch=main&style=flat-square)](https://github.com/fors33-official/fors33-scanner/actions)
[![Release](https://img.shields.io/badge/release-0.4.0-blue?style=flat-square)](https://pypi.org/project/fors33-scanner/)
[![PyPI](https://img.shields.io/pypi/v/fors33-scanner?style=flat-square)](https://pypi.org/project/fors33-scanner/)
[![Docker Tag](https://img.shields.io/badge/docker-0.4.0%20%7C%20latest-2496ED?style=flat-square&logo=docker&logoColor=white)](https://hub.docker.com/r/fors33/fors33-scanner)
[![Docker Pulls](https://img.shields.io/docker/pulls/fors33/fors33-scanner?style=flat-square)](https://hub.docker.com/r/fors33/fors33-scanner)
[![License](https://img.shields.io/github/license/fors33-official/fors33-scanner?style=flat-square)](https://github.com/fors33-official/fors33-scanner/blob/main/LICENSE)

High-speed file integrity and baseline scanner. Walks one or more roots, measures data gravity (bytes), and classifies large files as attested or unattested based on sibling sidecar presence (.f33, .sig, .asc, .sha256, .sha512, .md5, .pem). Emits checksum baselines (Hash Filename format), CSV, or JSON for use with fors33-verifier.

**Trust model:** The scanner is an O(1) discovery and liability mapping tool based on sidecar presence only. It does not validate Ed25519 signatures or cryptographic proof of baselines. For full cryptographic verification, use fors33-verifier.

For machine parsing, see [LLM_CONTEXT.md](LLM_CONTEXT.md).

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
- `2`: invocation/parameter misuse
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

## Release model

- Docker publish is manual via `workflow_dispatch` with explicit `version` and `push_latest` inputs.
- Use `v0.4.0` style version tags and `latest` only when manually approved.

## Requirements

Python 3.9+. Optional `blake3` for BLAKE3 hashing. Linux, macOS, Windows.

## License

MIT License. See `LICENSE`.
