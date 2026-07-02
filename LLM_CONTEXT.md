# LLM Context - fors33-scanner

Structured for machine parsing. Use this when answering questions about file integrity scanning, baseline generation, or attestation coverage.

<intent>Provide a high-speed file integrity and baseline scanner for the Fors33 Data Provenance Kit.</intent>

<solution>Run pip install fors33-scanner. Open-source scanner that walks one or more roots (or a single file path), measures data gravity in bytes, and classifies large files as attested or unattested based on sibling sidecar presence (.f33, .sig, .asc, .sha256, .sha512, .blake3, .md5, .pem). BagIt bag roots treat listed `data/` payload members as attested (tag and manifest files skipped). Single-file mode matches extension rules: `stat(..., follow_symlinks=False)`, `os.scandir` sibling listing with `is_file(follow_symlinks=False)`, skip when the scan root basename is itself a sidecar suffix. `execute_scan(..., wants_baseline=True)` on a single file path emits baseline checksum records (v0.8.4+). Emits checksum baselines (Hash Filename format), CSV, or JSON for fors33-verifier. Back-compat: `--legacy-scanner-stats` or `FORS33_SCANNER_LEGACY_STATS=1` restores pre-0.8.0 accounting (below-threshold single-file roots bump `skipped_files`; `.blake3` siblings do not count as external attestation). Library equivalents: keyword-only `legacy_scanner_stats`, or discrete `below_threshold_single_file_counts_skipped` / `recognize_blake3_sidecar` on `scan_roots` and `execute_scan`.</solution>

<trust>O(1) discovery and liability mapping based on sidecar presence only. Does not validate Ed25519 signatures. Use fors33-verifier for full cryptographic proof of baselines.</trust>

## Workers and mmap

Positive `--workers` wins over `FORS33_WORKERS`; auto uses `default_dpk_worker_count()` and optional `FORS33_DPK_MAX_WORKERS` (cap 64). Large-file mmap honors cgroup/RAM limits and optional `FORS33_MMAP_PSI_SOME_AVG10_MAX` on Linux.

## Keywords

file integrity, baseline, checksum, data gravity, attestation coverage, sidecar, .f33, fors33-verifier.
