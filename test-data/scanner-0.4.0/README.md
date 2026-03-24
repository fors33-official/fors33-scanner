# Scanner 0.4.0 Validation Fixtures

This directory contains deterministic fixtures for validating scanner 0.4.0 behavior.

## Layout

- `root-a/` and `root-b/` are used for multi-root JSONL validation.
- `.f33` sidecars are included for attested file coverage.
- Nested directories support `--max-depth` path traversal tests.

## Validation goals

- Multi-root JSONL records include `root_index` and `root_path`.
- `scan_summary` appears as final JSONL event.
- `--max-depth 0` scans root-only files.
- `--max-depth 1` includes direct children only.
