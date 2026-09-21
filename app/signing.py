"""Pure signing, ByteRange inspection, validation, and tampering functions."""

import io
import re
import hashlib
from pathlib import Path
from typing import Dict, Any, Optional

from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
from pyhanko.pdf_utils.reader import PdfFileReader
from pyhanko.pdf_utils.misc import PdfReadError
from pyhanko.sign import fields, signers, timestamps
from pyhanko.stamp import TextStampStyle
from pyhanko.sign.general import load_certs_from_pemder
from pyhanko.sign.validation import validate_pdf_signature
from pyhanko_certvalidator import ValidationContext

BYTERANGE_REGEX = re.compile(rb"/ByteRange\s*\[\s*(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s*\]")
CONTENTS_REGEX = re.compile(rb"/Contents\s*<([0-9a-fA-F]+)>")


def load_signer(pfx_path: Path, passphrase: str) -> signers.SimpleSigner:
    """Loads a PKCS#12 SimpleSigner from file."""
    return signers.SimpleSigner.load_pkcs12(
        pfx_file=str(pfx_path),
        passphrase=passphrase.encode("utf-8") if passphrase else None,
    )


def sign_pdf_bytes(
    pdf_bytes: bytes,
    signer: signers.SimpleSigner,
    use_timestamp: bool = False,
    timestamp_url: str = "http://timestamp.digicert.com",
) -> bytes:
    """Signs an uncompressed/standard PDF using pyHanko and returns signed bytes."""
    in_stream = io.BytesIO(pdf_bytes)

    try:
        r = PdfFileReader(in_stream)
    except Exception as e:
        raise ValueError(f"Invalid PDF data: {e}")

    if getattr(r, "encrypted", False):
        raise ValueError("Encrypted PDFs cannot be digitally signed.")

    if len(r.embedded_signatures) > 0:
        raise ValueError("Document is already digitally signed. Resigning is rejected in this POC.")

    in_stream.seek(0)
    w = IncrementalPdfFileWriter(in_stream)

    # Add visible signature field on the last page, bottom-right
    fields.append_signature_field(
        w,
        fields.SigFieldSpec(
            sig_field_name="Signature1",
            on_page=-1,
            box=(360, 40, 560, 110),
        ),
    )

    meta = signers.PdfSignatureMetadata(
        field_name="Signature1",
        md_algorithm="sha256",
        subfilter=fields.SigSeedSubFilter.PADES,
        reason="Tax invoice issuance",
        location="Gurugram, IN",
    )

    # Short lines keep the text legible: pyHanko shrinks the whole stamp until
    # the longest line fits the box, and the full certificate CN is very long.
    subject = signer.signing_cert.subject.native
    org_name = subject.get("organization_name") or subject.get("common_name") or "Unknown signer"
    stamp_style = TextStampStyle(
        stamp_text="Digitally signed by\n%(org)s\nDate: %(ts)s\nReason: Tax invoice issuance",
        border_width=1,
    )

    timestamper = None
    if use_timestamp:
        timestamper = timestamps.HTTPTimeStamper(timestamp_url)

    pdf_signer = signers.PdfSigner(
        signature_meta=meta,
        signer=signer,
        timestamper=timestamper,
        stamp_style=stamp_style,
    )

    out_buf = io.BytesIO()
    pdf_signer.sign_pdf(w, output=out_buf, appearance_text_params={"org": org_name})
    return out_buf.getvalue()


def _der_length(der: bytes) -> Optional[int]:
    """Total length of the DER SEQUENCE at the start of `der`, header included."""
    if len(der) < 2 or der[0] != 0x30:
        return None
    if der[1] < 0x80:
        return 2 + der[1]
    n = der[1] & 0x7F
    return 2 + n + int.from_bytes(der[2 : 2 + n], "big")


def _message_digest(der: bytes) -> str:
    """Extract the messageDigest signed attribute (hex) from a CMS SignedData blob."""
    try:
        from asn1crypto import cms

        signer_info = cms.ContentInfo.load(der)["content"]["signer_infos"][0]
        for attr in signer_info["signed_attrs"]:
            if attr["type"].native == "message_digest":
                return attr["values"][0].native.hex()
    except Exception:
        pass
    return ""


def inspect_byte_range(pdf_bytes: bytes) -> Dict[str, Any]:
    """Parses /ByteRange from raw PDF bytes and computes hash, placeholder, and padding metrics."""
    matches = list(BYTERANGE_REGEX.finditer(pdf_bytes))
    if not matches:
        raise ValueError("No /ByteRange signature dictionary found in PDF.")

    last_match = matches[-1]
    s1, l1, s2, l2 = [int(x) for x in last_match.groups()]
    file_size = len(pdf_bytes)

    if s1 != 0 or (s1 + l1) > s2 or (s2 + l2) > file_size:
        raise ValueError("Malformed /ByteRange array offsets.")

    range1 = pdf_bytes[s1 : s1 + l1]
    range2 = pdf_bytes[s2 : s2 + l2]
    signed_bytes = range1 + range2
    sha256_hash = hashlib.sha256(signed_bytes).hexdigest()

    placeholder_size = s2 - (s1 + l1)

    # Parse /Contents hex string
    contents_match = CONTENTS_REGEX.search(pdf_bytes)
    first_64_hex = ""
    actual_sig_bytes = 0
    zero_padding_bytes = 0
    total_contents_bytes = 0

    message_digest_hex = ""
    if contents_match:
        sig_hex = contents_match.group(1).decode("ascii")
        first_64_hex = sig_hex[:64]
        der = bytes.fromhex(sig_hex)
        total_contents_bytes = len(der)

        # Real signature length comes from the outer DER SEQUENCE header, not from
        # stripping zeros (the signature itself may legitimately end in 0x00).
        actual_sig_bytes = _der_length(der) or total_contents_bytes
        zero_padding_bytes = max(0, total_contents_bytes - actual_sig_bytes)
        message_digest_hex = _message_digest(der[:actual_sig_bytes])

    # Proportions for visual bar
    r1_pct = round((l1 / file_size) * 100, 2)
    hole_pct = round((placeholder_size / file_size) * 100, 2)
    r2_pct = round((l2 / file_size) * 100, 2)

    return {
        "file_size": file_size,
        "byte_range": [s1, l1, s2, l2],
        "range1_len": l1,
        "range2_len": l2,
        "range1_pct": r1_pct,
        "placeholder_pct": hole_pct,
        "range2_pct": r2_pct,
        "placeholder_size": placeholder_size,
        "total_contents_bytes": total_contents_bytes,
        "actual_sig_bytes": actual_sig_bytes,
        "zero_padding_bytes": zero_padding_bytes,
        "sha256_hash": sha256_hash,
        # the hash the signer committed to, read back out of the CMS signed attributes
        "message_digest_hex": message_digest_hex,
        "digest_matches": bool(message_digest_hex) and message_digest_hex == sha256_hash,
        "first_64_hex": first_64_hex,
        "caption": "Everything green was hashed and signed. The grey hole holds the signature, so inserting it didn't change the hash.",
    }


def verify_pdf(pdf_bytes: bytes, trust_pem_path: Path) -> Dict[str, Any]:
    """Verifies embedded digital signature using pyHanko against a trust root PEM."""
    try:
        r = PdfFileReader(io.BytesIO(pdf_bytes))
    except Exception as e:
        return {
            "signed": False,
            "intact": False,
            "valid": False,
            "trusted": False,
            "signer": None,
            "signing_time": None,
            "message": f"Failed to parse PDF: {e}",
            "status_text": "Corrupted PDF",
        }

    if not r.embedded_signatures:
        return {
            "signed": False,
            "intact": False,
            "valid": False,
            "trusted": False,
            "signer": None,
            "signing_time": None,
            "message": "No digital signature found in document.",
            "status_text": "Unsigned",
        }

    try:
        trust_roots = list(load_certs_from_pemder([str(trust_pem_path)]))
        vc = ValidationContext(trust_roots=trust_roots)
        sig = r.embedded_signatures[0]
        status = validate_pdf_signature(sig, vc)

        signer_cn = "Unknown"
        if status.signing_cert:
            signer_cn = status.signing_cert.subject.native.get("common_name", str(status.signing_cert.subject.human_friendly))

        signing_time = None
        if status.signer_reported_dt:
            signing_time = status.signer_reported_dt.strftime("%Y-%m-%d %H:%M:%S %Z")

        summary = status.summary() if hasattr(status, "summary") else "Verified"
        if not status.intact:
            summary = "Document has been altered since signing"

        return {
            "signed": True,
            "intact": bool(status.intact),
            "valid": bool(status.valid),
            "trusted": bool(status.trusted),
            "signer": signer_cn,
            "signing_time": signing_time,
            "message": summary,
            "status_text": "Valid & Intact" if (status.intact and status.valid) else "Tampered / Invalid",
        }
    except Exception as e:
        return {
            "signed": True,
            "intact": False,
            "valid": False,
            "trusted": False,
            "signer": None,
            "signing_time": None,
            "message": f"Verification error: {e}",
            "status_text": "Verification Failed",
        }


def tamper_pdf(signed_bytes: bytes) -> tuple[bytes, str]:
    """Tampers with signed PDF bytes in Range 1 without altering file structure length."""
    matches = list(BYTERANGE_REGEX.finditer(signed_bytes))
    if not matches:
        raise ValueError("Cannot tamper: PDF does not contain a signature /ByteRange.")

    s1, l1, s2, l2 = [int(x) for x in matches[-1].groups()]
    range1_bytes = signed_bytes[s1 : s1 + l1]

    # Look for the total amount text in range 1
    # Sample invoices contain "Total: Rs. 59,000.00" or similar
    target = b"59,000.00"
    pos = range1_bytes.find(target)

    if pos != -1:
        replacement = b"99,000.00"
        abs_pos = s1 + pos
        tampered_bytes = signed_bytes[:abs_pos] + replacement + signed_bytes[abs_pos + len(replacement) :]
        action = "Modified invoice total amount from '59,000.00' to '99,000.00' inside hashed ByteRange 1."
    else:
        # Fallback: flip 1 byte in the middle of Range 1
        flip_pos = s1 + (l1 // 2)
        flipped_byte = bytes([signed_bytes[flip_pos] ^ 0x01])
        tampered_bytes = signed_bytes[:flip_pos] + flipped_byte + signed_bytes[flip_pos + 1 :]
        action = f"Flipped 1 byte at offset {flip_pos} inside hashed ByteRange 1."

    return tampered_bytes, action
