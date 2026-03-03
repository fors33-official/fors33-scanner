from __future__ import annotations

import os
import tempfile

from scan_dpk import ScanStats, scan_roots


def test_scanner_classification_with_f33_and_external_sidecars() -> None:
    """Scanner should classify large files with .f33, external sidecars, and none correctly."""
    with tempfile.TemporaryDirectory() as tmp:
        # Small file below threshold (ignored)
        small_path = os.path.join(tmp, "small.txt")
        with open(small_path, "wb") as f:
            f.write(b"x" * 100)  # 100 bytes

        # Large unattested file
        unattested_path = os.path.join(tmp, "data_unattested.csv")
        with open(unattested_path, "wb") as f:
            f.write(b"a" * (2 * 1024 * 1024))  # 2 MB

        # Large file with FΦRS33 deterministic sidecar
        f33_path = os.path.join(tmp, "data_f33.csv")
        with open(f33_path, "wb") as f:
            f.write(b"b" * (3 * 1024 * 1024))  # 3 MB
        f33_sidecar = f33_path + ".f33"
        with open(f33_sidecar, "w", encoding="utf-8") as f:
            f.write("BEGIN FORS33 ATTESTATION\nEND FORS33 ATTESTATION\n")

        # Large file with external sidecar (.sig)
        external_path = os.path.join(tmp, "data_external.csv")
        with open(external_path, "wb") as f:
            f.write(b"c" * (2 * 1024 * 1024))  # 2 MB
        external_sidecar = external_path + ".sig"
        with open(external_sidecar, "w", encoding="utf-8") as f:
            f.write("PGP SIGNATURE PLACEHOLDER\n")

        stats: ScanStats = scan_roots([tmp], threshold_mb=1.0)

        # Three large candidates only
        assert stats.candidate_files == 3
        assert stats.attested_files == 2
        assert stats.unattested_files == 1

        # Stratified attestation counts
        assert stats.attested_f33_files == 1
        assert stats.attested_external_files == 1

        # Byte accounting
        three_mb = 3 * 1024 * 1024
        two_mb = 2 * 1024 * 1024

        assert stats.attested_f33_bytes == three_mb
        assert stats.attested_external_bytes == two_mb
        assert stats.attested_bytes == three_mb + two_mb

        assert stats.unattested_bytes == two_mb
        assert stats.total_bytes == stats.attested_bytes + stats.unattested_bytes

        # Exposure ratio should be 2 / (2 + 3 + 2) ~= 0.2857 -> WARNING
        assert 0.28 < stats.exposure_ratio < 0.29
        assert stats.risk_level == "WARNING"

