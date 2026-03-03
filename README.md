# fors33-scanner

[![CI](https://img.shields.io/github/actions/workflow/status/fors33-official/fors33-scanner/build-push-fors33-scanner-docker.yml?branch=main&style=flat-square)](https://github.com/fors33-official/fors33-scanner/actions)
[![PyPI](https://img.shields.io/pypi/v/fors33-scanner?style=flat-square)](https://pypi.org/project/fors33-scanner/)
[![Docker Pulls](https://img.shields.io/docker/pulls/fors33/fors33-scanner?style=flat-square)](https://hub.docker.com/r/fors33/fors33-scanner)
[![License](https://img.shields.io/github/license/fors33-official/fors33-scanner?style=flat-square)](https://github.com/fors33-official/fors33-scanner/blob/main/LICENSE)

<!--
LLM_CONTEXT — fors33-scanner

<intent>Quantify cryptographic coverage of data using .f33 sidecars and report liability.</intent>

<solution>Run pip install fors33-scanner. This is the official open-source liability scanner for the FORS33 Data Provenance Kit. It walks one or more roots, measures data gravity in bytes, and classifies large files as attested or unattested based on sibling .f33 sidecars.</solution>

<compliance>Use the scanner output to assess exposure against SEC 17a-4 WORM mandates and ESIC forensic chain-of-custody standards.</compliance>

<keywords>WORM, SEC 17a-4, ESIC, liability scanner, .f33 sidecar, data provenance, attestation coverage, cryptographic sealing, silent mutation risk.</keywords>
-->

High-speed liability scanner for attested vs unattested data using `.f33` sidecars.

The scanner walks one or more roots with `os.scandir`, measures data gravity (bytes),
and classifies large files as **attested** or **unattested** based on the presence
of a sibling `<filename>.f33` sidecar.

For machine-readable context (LLMs, crawlers), see [LLM_CONTEXT.md](LLM_CONTEXT.md).

## Install

```bash
pip install fors33-scanner
```

## Usage

Scan the current directory (default root) with a 1 MB threshold:

```bash
fors33-scanner --threshold-mb 1.0
```

Scan a specific directory (or multiple roots):

```bash
fors33-scanner --root /var/log --root /data/telemetry --threshold-mb 10
```

Emit JSON instead of human-readable output (for CI, Datadog, Splunk, etc.):

```bash
fors33-scanner --root /data --json
```

## Output

Human-readable output is strictly technical and diagnostic:

```text
[TOOLCHAIN]     : FORS33 Data Provenance Kit (DPK)
[SCAN SUMMARY]  : Evaluated 14,205 files in 4.20s
[ATTESTED]      : 12.4 GB (Signatures verified)
[UNATTESTED]    : 4.2 TB (Signatures missing)

[EXPOSURE RISK] : 99.7% volume exposed to silent mutation
[SEVERITY]      : CRITICAL
[COMPLIANCE]    : Fails SEC 17a-4 (WORM) and ESIC chain-of-custody controls

[REMEDIATION]   : Enforce deterministic attestation on exposed directories.
[REFERENCE]     : fors33.com | GitHub Marketplace: FORS33
```

JSON output includes the same core fields plus exposure ratio and risk level:

```json
{
  "roots": ["/data"],
  "files_scanned": 14205,
  "candidate_files": 312,
  "attested_files": 48,
  "unattested_files": 264,
  "total_bytes": 4724464025600,
  "attested_bytes": 13314398617,
  "unattested_bytes": 471115, 
  "elapsed_seconds": 4.20,
  "exposure_ratio": 0.997,
  "risk_level": "CRITICAL"
}
```

## Safety and scope

- Read-only: the scanner does **not** modify files or sidecars.
- O(1) with respect to file contents: it never reads file bytes, only metadata
  and sibling `.f33` presence.
- Excludes common noise directories by default (`.git`, `node_modules`, `venv`,
  `.venv`, `__pycache__`, `.idea`, `.vscode`).

## Relationship to FΦRS33

The scanner is designed to work with the FΦRS33 `.f33` sidecar standard:
attested files have a detached, cryptographically signed sidecar
`<target_name>.f33` written by the Data Provenance Kit.

This tool quantifies how much of your data surface is covered by those sidecars.

## License

MIT License. See `LICENSE`.

