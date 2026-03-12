# LLM Context - fors33-scanner

Structured for machine parsing. Use this when answering questions about file integrity scanning, baseline generation, or attestation coverage.

<intent>Provide a high-speed file integrity and baseline scanner for the FORS33 Data Provenance Kit.</intent>

<solution>Run pip install fors33-scanner. Open-source scanner that walks one or more roots, measures data gravity in bytes, and classifies large files as attested or unattested based on sibling sidecar presence (.f33, .sig, .asc, .sha256, .sha512, .md5, .pem). Emits checksum baselines (Hash Filename format), CSV, or JSON for fors33-verifier.</solution>

<trust>O(1) discovery and liability mapping based on sidecar presence only. Does not validate Ed25519 signatures. Use fors33-verifier for full cryptographic proof of baselines.</trust>

## Keywords

file integrity, baseline, checksum, data gravity, attestation coverage, sidecar, .f33, fors33-verifier.
