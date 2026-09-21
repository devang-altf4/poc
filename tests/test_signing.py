"""Automated test suite for pyHanko signing, ByteRange inspection, verification, and tampering."""

import os
from pathlib import Path
import pytest

from app.certs import cert_manager
from app.invoices import generate_sample_invoices, DATA_DIR, INPUT_DIR
from app.signing import (
    load_signer,
    sign_pdf_bytes,
    inspect_byte_range,
    verify_pdf,
    tamper_pdf,
)

OUTPUT_DIR = DATA_DIR / "output"


@pytest.fixture(scope="session", autouse=True)
def setup_environment():
    """Ensure certs and directories are created."""
    cert_manager.init_environment()
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    yield


def test_cert_generation_and_metadata():
    """Verify demo certificate properties and key usage."""
    info = cert_manager.get_active_info()
    assert info["subject_cn"] == "Dream Road Technologies (TEST Document Signer)"
    assert info["subject_org"] == "Dream Road Technologies"
    assert info["is_self_signed"] is True
    assert info["is_demo"] is True
    assert cert_manager.active_pfx_path.exists()
    assert cert_manager.active_pem_path.exists()


def test_sample_invoice_uncompressed():
    """Verify invoices contain uncompressed plain text bytes for the total amount."""
    files = generate_sample_invoices(2)
    assert len(files) == 2
    inv_path = INPUT_DIR / files[0]
    assert inv_path.exists()

    with open(inv_path, "rb") as f:
        data = f.read()

    # Must contain uncompressed 'Total: Rs. 59,000.00'
    assert b"Total: Rs. 59,000.00" in data, "Invoice total amount must be stored uncompressed in page stream"


def test_sign_single_pdf():
    """Verify pyHanko signing and signature creation."""
    inv_path = INPUT_DIR / "INV-2026-001.pdf"
    with open(inv_path, "rb") as f:
        raw_bytes = f.read()

    signer = load_signer(cert_manager.active_pfx_path, cert_manager.active_password)
    signed_bytes = sign_pdf_bytes(raw_bytes, signer)

    assert len(signed_bytes) > len(raw_bytes)
    assert b"/ByteRange" in signed_bytes
    assert b"/Contents" in signed_bytes

    out_path = OUTPUT_DIR / "INV-2026-001-signed.pdf"
    with open(out_path, "wb") as f:
        f.write(signed_bytes)


def test_reject_already_signed():
    """Verify pyHanko rejects signing a document that already has a signature."""
    signed_path = OUTPUT_DIR / "INV-2026-001-signed.pdf"
    with open(signed_path, "rb") as f:
        signed_bytes = f.read()

    signer = load_signer(cert_manager.active_pfx_path, cert_manager.active_password)
    with pytest.raises(ValueError, match="already digitally signed"):
        sign_pdf_bytes(signed_bytes, signer)


def test_inspect_byterange():
    """Verify /ByteRange extraction and SHA-256 calculation."""
    signed_path = OUTPUT_DIR / "INV-2026-001-signed.pdf"
    with open(signed_path, "rb") as f:
        signed_bytes = f.read()

    info = inspect_byte_range(signed_bytes)
    assert "byte_range" in info
    assert len(info["byte_range"]) == 4
    s1, l1, s2, l2 = info["byte_range"]
    assert s1 == 0
    assert l1 > 0
    assert s2 > (s1 + l1)
    assert l2 > 0

    assert len(info["sha256_hash"]) == 64
    assert len(info["first_64_hex"]) == 64
    assert info["placeholder_size"] > 0
    assert info["actual_sig_bytes"] > 0
    assert info["zero_padding_bytes"] >= 0
    # the gap is exactly the hex slot, so on disk it is 2x the bytes plus '<' '>'
    assert info["placeholder_size"] == 2 * info["total_contents_bytes"] + 2
    assert info["actual_sig_bytes"] + info["zero_padding_bytes"] == info["total_contents_bytes"]
    # the hash we compute over the ByteRange is the one the signer committed to
    assert info["digest_matches"] is True
    assert info["message_digest_hex"] == info["sha256_hash"]


def test_verify_original_signed_pdf():
    """Verify valid signature is Intact, Valid, and Trusted."""
    signed_path = OUTPUT_DIR / "INV-2026-001-signed.pdf"
    with open(signed_path, "rb") as f:
        signed_bytes = f.read()

    res = verify_pdf(signed_bytes, cert_manager.active_pem_path)
    assert res["signed"] is True
    assert res["intact"] is True
    assert res["valid"] is True
    assert res["trusted"] is True
    assert "Dream Road Technologies" in (res["signer"] or "")


def test_verify_unsigned_pdf():
    """Verify unsigned PDF returns graceful status."""
    inv_path = INPUT_DIR / "INV-2026-002.pdf"
    with open(inv_path, "rb") as f:
        raw_bytes = f.read()

    res = verify_pdf(raw_bytes, cert_manager.active_pem_path)
    assert res["signed"] is False
    assert res["status_text"] == "Unsigned"


def test_safe_path_blocks_traversal():
    """Client-supplied filenames must never escape their folder (public deploy)."""
    from fastapi import HTTPException
    from app.main import _safe_path

    assert _safe_path(INPUT_DIR, "INV-2026-001.pdf") == INPUT_DIR / "INV-2026-001.pdf"
    for bad in ["../demo-signer.pfx", "..\\demo-signer.pfx", "../../app/main.py", "..", ".", ""]:
        with pytest.raises(HTTPException):
            _safe_path(INPUT_DIR, bad)


def test_healthz():
    from app.main import healthz
    assert healthz() == {"ok": True}


def test_tamper_and_verify_fails():
    """Verify tampering with total amount causes verification intact check to fail."""
    signed_path = OUTPUT_DIR / "INV-2026-001-signed.pdf"
    with open(signed_path, "rb") as f:
        signed_bytes = f.read()

    tampered_bytes, action = tamper_pdf(signed_bytes)
    assert "59,000.00" in action or "offset" in action
    assert len(tampered_bytes) == len(signed_bytes)

    res = verify_pdf(tampered_bytes, cert_manager.active_pem_path)
    assert res["signed"] is True
    assert res["intact"] is False
    assert "altered" in res["message"].lower() or "tampered" in res["status_text"].lower()
