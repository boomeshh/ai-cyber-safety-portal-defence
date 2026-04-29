"""
Preservation property tests — Task 2 of localhost-config-restore bugfix spec.

These tests record the SHA-256 baseline checksums of every file that MUST NOT be
modified by the fix.  They are written BEFORE the fix is applied so that:

  * They all PASS now  (confirming the baseline is recorded correctly).
  * If any of these files is accidentally changed during the fix, the corresponding
    test will FAIL, giving an immediate regression signal.

Validates: Requirements 3.1, 3.2, 3.3, 3.4, 3.5, 3.6, 3.7
"""

import hashlib
import os
from pathlib import Path

import pytest

# ---------------------------------------------------------------------------
# Baseline checksums — computed from the UNFIXED repository state.
# Keys use forward-slash paths relative to the repository root.
# ---------------------------------------------------------------------------
BASELINE_CHECKSUMS: dict[str, str] = {
    # Backend source
    "backend/main.py": "15ff1f21359bd32c2d9ad75270559661481e09e18b44b889326ce26e2ecc4096",
    # Frontend .env files (must not be touched by the fix)
    "user-frontend/.env": "39ff42e7beb6b7813780855448775346d29b1df963f0b3932c0ad92dd58330c6",
    "admin-frontend/.env": "39ff42e7beb6b7813780855448775346d29b1df963f0b3932c0ad92dd58330c6",
    "cert-frontend/.env": "39ff42e7beb6b7813780855448775346d29b1df963f0b3932c0ad92dd58330c6",
    # .env.example files (must not be touched by the fix)
    "user-frontend/.env.example": "0dcb3d3a40d4b28252fac60329218fd12e9ceef4c7c2cbab27f21863bb79d3ad",
    "admin-frontend/.env.example": "1432348c52c528e12f159c1ea80c65e6ebaa362332f61ef6e7d7e980bec766e7",
    "cert-frontend/.env.example": "02f336381b9e1fa5f540284239e404b280c539e57974433f7bd0495619799115",
    "backend/.env.example": "9114b17f6704e2aef0a4868fa5adbc62fa76bbf5b3b99737ca3b9353b6c3e7f4",
    # user-frontend JS source files
    "user-frontend/src/App.js": "748eef8542077c0ca73d2ca1342a2ecd24deecc5c45c0dfbe7556daab12e5b28",
    "user-frontend/src/index.js": "10943746c5e810a957d9983e74b9c27e40a819c256af8b3592feb1972944e439",
    "user-frontend/src/pages/Dashboard.js": "719345c2f7821d97a1b1f72bd5df5b9c3215f72e416e999b3949d1997d9cf144",
    "user-frontend/src/pages/Login.js": "03b99da8c7042a53cd0c13712045930c2001e04c12e8ab0d4f924ccb85e76623",
    "user-frontend/src/pages/MyComplaints.js": "dd48f678a1ad14db5b5285dea6a8a665af1f3f4af160ab95f7086a7aef2ad29b",
    "user-frontend/src/pages/Register.js": "b752dae41ee6c69c980101b430159836c06b23bddd3a8ca1f1ec0210b5407970",
    "user-frontend/src/pages/SubmitComplaint.js": "cf9d1d215909421613a3b1323bc8010a126a1ae4269ecf4fe9e6ee87453a7fc6",
    "user-frontend/src/reportWebVitals.js": "5efbb84cbed52b82cab1165c816c92390b0a5d752e490ca564172a14e3a84a6d",
    "user-frontend/src/setupTests.js": "c630b70e0f17b0fddf547079fd2ec64e6d677252588037f873f1008f307f49b9",
    "user-frontend/src/utils/auth.js": "8b5c9a44e4b09935005515add53a7ba04d83e36ec80ec4bdc6646e7f0eb75c58",
    # admin-frontend JS source files
    "admin-frontend/src/App.js": "e16460339010ba771af3d6b430db3cf1adcbb1a4b08e33f758a185b860a26f6a",
    "admin-frontend/src/App.test.js": "215249688b88564c9ed8da9cb534c2975a50e44016b746537cff6acf0d44340c",
    "admin-frontend/src/index.js": "39f6891bebce856ce604ea450f08ace26fa1b931415985881fbb323f63ba26fb",
    "admin-frontend/src/pages/AdminDashboard.js": "5fe5cd7be1332415840d329abb6619857bf5b072bcd3b1a7fd38b590def142cd",
    "admin-frontend/src/reportWebVitals.js": "714851669856152806c289f9aac6240b414bbac50c60ee4f7e6247f31eac0c1c",
    "admin-frontend/src/setupTests.js": "22583759d0045fdf8d62c9db0aacba9fd8bddde79c671aa08c97dcfd4e930cc6",
    "admin-frontend/src/utils/auth.js": "86feacaca1ce3d7d3c8880df018fea72fdcfb2e3b1852307e4adace36302034e",
    # cert-frontend JS source files
    "cert-frontend/src/App.js": "65e02fd67be104c9598ee713fbde952ca7747e359f059e882180e375948e42d1",
    "cert-frontend/src/App.test.js": "f7784693194b8657d1bf70c37ea70f4a2d694c4566ec41550a8e650eb600aaa4",
    "cert-frontend/src/components/Heatmap.js": "56eebf627dc9ff091c5d69ef04c4db04e4d39f959c0a360bdf0c070454a3095f",
    "cert-frontend/src/index.js": "39f6891bebce856ce604ea450f08ace26fa1b931415985881fbb323f63ba26fb",
    "cert-frontend/src/reportWebVitals.js": "714851669856152806c289f9aac6240b414bbac50c60ee4f7e6247f31eac0c1c",
    "cert-frontend/src/setupTests.js": "22583759d0045fdf8d62c9db0aacba9fd8bddde79c671aa08c97dcfd4e930cc6",
    "cert-frontend/src/utils/auth.js": "86feacaca1ce3d7d3c8880df018fea72fdcfb2e3b1852307e4adace36302034e",
}

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _repo_root() -> Path:
    """Return the repository root (two levels up from this test file)."""
    return Path(__file__).resolve().parent.parent.parent


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


# ---------------------------------------------------------------------------
# Parametrized preservation test
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("rel_path,expected_hash", list(BASELINE_CHECKSUMS.items()))
def test_file_is_unchanged(rel_path: str, expected_hash: str) -> None:
    """
    Assert that *rel_path* (relative to the repo root) has not been modified.

    This test records the baseline state of every file that must NOT be touched
    by the localhost-config-restore fix.  It passes on the unfixed code and will
    continue to pass after the fix — any accidental modification will cause an
    immediate failure here.

    **Validates: Requirements 3.1, 3.2, 3.3, 3.4, 3.5, 3.6, 3.7**
    """
    full_path = _repo_root() / Path(rel_path)
    assert full_path.exists(), (
        f"Preserved file is missing: {rel_path}\n"
        f"(looked at {full_path})"
    )
    actual_hash = _sha256(full_path)
    assert actual_hash == expected_hash, (
        f"File was modified: {rel_path}\n"
        f"  expected SHA-256: {expected_hash}\n"
        f"  actual  SHA-256: {actual_hash}"
    )
