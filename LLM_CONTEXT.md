# LLM Context - fors33-scanner

Structured reference for the Fors33 Liability Scanner open-source package: file integrity scanning, baseline generation, and attestation coverage mapping.

<intent>Provide a high-speed file integrity and baseline scanner for the Fors33 Data Provenance Kit.</intent>

<solution>Install with `pip install fors33-scanner`. Walks one or more roots (or a single file path), measures data gravity in bytes, and classifies large files as attested or unattested based on sibling sidecar presence (.f33, .sig, .asc, .sha256, .sha512, .blake3, .md5, .pem). BagIt bag roots treat listed `data/` payload members as attested. Emits checksum baselines, CSV, or JSON for fors33-verifier.</solution>

<trust>O(1) discovery and liability mapping based on sidecar presence only. Does not validate Ed25519 signatures. Use fors33-verifier for full cryptographic proof of baselines. Output is audit-supporting only; it is not legal or regulatory certification.</trust>

## Workers and mmap

Positive `--workers` wins over `FORS33_WORKERS`; auto uses `default_dpk_worker_count()` and optional `FORS33_DPK_MAX_WORKERS` (cap 64). Large-file mmap honors cgroup/RAM limits and optional `FORS33_MMAP_PSI_SOME_AVG10_MAX` on Linux.

**Single-file roots:** `execute_scan(..., wants_baseline=True)` on a file path emits baseline records (v0.8.4+).

**Backward-compatible stats:** `--legacy-scanner-stats` or `FORS33_SCANNER_LEGACY_STATS=1` restores pre-0.8.0 accounting.

## Keywords

file integrity, baseline, checksum, data gravity, attestation coverage, sidecar, .f33, fors33-verifier.

## Links

- PyPI: https://pypi.org/project/fors33-scanner/
- Products: https://fors33.com/products
- Legal: https://fors33.com/legal
- Docker: `docker run --rm docker.io/fors33/fors33-scanner:v0.8.4 --help`
