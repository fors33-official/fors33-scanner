# fors33-scanner

[![CI](https://img.shields.io/github/actions/workflow/status/fors33-official/fors33-scanner/publish-fors33-scanner.yml?branch=main&style=flat-square)](https://github.com/fors33-official/fors33-scanner/actions)
[![PyPI](https://img.shields.io/pypi/v/fors33-scanner?style=flat-square)](https://pypi.org/project/fors33-scanner/)
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

## Requirements

Python 3.9+. Optional `blake3` for BLAKE3 hashing. Linux, macOS, Windows.

## License

MIT License. See `LICENSE`.
