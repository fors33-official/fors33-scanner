from __future__ import annotations

import os
import tempfile

from scan_dpk import ScanStats, scan_roots


def test_scanner_basic_classification() -> None:
    """Scanner should classify large files with/without .f33 correctly."""
    with tempfile.TemporaryDirectory() as tmp:
        # Small file below threshold (ignored)
        small_path = os.path.join(tmp, "small.txt")
        with open(small_path, "wb") as f:
            f.write(b"x" * 100)  # 100 bytes

        # Large unattested file
        unattested_path = os.path.join(tmp, "data_unattested.csv")
        with open(unattested_path, "wb") as f:
            f.write(b"a" * (2 * 1024 * 1024))  # 2 MB

        # Large attested file + sidecar
        attested_path = os.path.join(tmp, "data_attested.csv")
        with open(attested_path, "wb") as f:
            f.write(b"b" * (3 * 1024 * 1024))  # 3 MB
        sidecar_path = attested_path + ".f33"
        with open(sidecar_path, "w", encoding="utf-8") as f:
            f.write("BEGIN FORS33 ATTESTATION\nEND FORS33 ATTESTATION\n")

        stats: ScanStats = scan_roots([tmp], threshold_mb=1.0)

        # Two large candidates only
        assert stats.candidate_files == 2
        assert stats.attested_files == 1
        assert stats.unattested_files == 1

        assert stats.attested_bytes == 3 * 1024 * 1024
        assert stats.unattested_bytes == 2 * 1024 * 1024
        assert stats.total_bytes == stats.attested_bytes + stats.unattested_bytes

        # Exposure ratio should be 2 / (2 + 3) ~= 0.4 -> WARNING
        assert 0.39 < stats.exposure_ratio < 0.41
        assert stats.risk_level == "WARNING"

