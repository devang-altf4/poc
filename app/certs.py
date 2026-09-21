"""Certificate generation, loading, and inspection."""

import datetime
from pathlib import Path
from typing import Any, Dict, Optional
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

# Absolute, so the app works no matter which directory it is started from.
DATA_DIR = Path(__file__).resolve().parent.parent / "data"
# The self-signed TEST certificate is shared by every workspace.
DEMO_PFX_PATH = DATA_DIR / "demo-signer.pfx"
DEMO_PEM_PATH = DATA_DIR / "demo-signer.pem"
DEMO_PASSWORD = "demo1234"


class CertificateManager:
    """Manages the active signing certificate and verification trust root
    for one workspace. An uploaded .pfx lives inside that workspace only."""

    def __init__(self, workspace: Path = DATA_DIR) -> None:
        self.workspace = workspace
        self.uploaded_pfx_path: Path = workspace / "uploaded-signer.pfx"
        self.uploaded_pem_path: Path = workspace / "uploaded-signer.pem"
        self.active_pfx_path: Path = DEMO_PFX_PATH
        self.active_pem_path: Path = DEMO_PEM_PATH
        self.active_password: str = DEMO_PASSWORD
        self.is_demo: bool = True

    def init_environment(self) -> None:
        """Ensures the workspace directories and the shared demo certificate exist."""
        DATA_DIR.mkdir(parents=True, exist_ok=True)
        (self.workspace / "input").mkdir(parents=True, exist_ok=True)
        (self.workspace / "output").mkdir(parents=True, exist_ok=True)

        if not DEMO_PFX_PATH.exists() or not DEMO_PEM_PATH.exists():
            self.generate_demo_certificate()
        else:
            self.reset_to_demo()

    def generate_demo_certificate(self) -> None:
        """Generates self-signed test document signer certificate."""
        DATA_DIR.mkdir(parents=True, exist_ok=True)

        # Generate RSA 2048 key
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, "Dream Road Technologies (TEST Document Signer)"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Dream Road Technologies"),
            x509.NameAttribute(NameOID.COUNTRY_NAME, "IN"),
        ])

        now = datetime.datetime.now(datetime.timezone.utc)
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(minutes=5))
            .not_valid_after(now + datetime.timedelta(days=730))  # 2 years
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    content_commitment=True,  # nonRepudiation
                    key_encipherment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=False,
                    crl_sign=False,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            .sign(key, hashes.SHA256())
        )

        pfx_bytes = serialization.pkcs12.serialize_key_and_certificates(
            name=b"demo-signer",
            key=key,
            cert=cert,
            cas=None,
            encryption_algorithm=serialization.BestAvailableEncryption(DEMO_PASSWORD.encode("utf-8")),
        )
        with open(DEMO_PFX_PATH, "wb") as f:
            f.write(pfx_bytes)

        pem_bytes = cert.public_bytes(serialization.Encoding.PEM)
        with open(DEMO_PEM_PATH, "wb") as f:
            f.write(pem_bytes)

        self.active_pfx_path = DEMO_PFX_PATH
        self.active_pem_path = DEMO_PEM_PATH
        self.active_password = DEMO_PASSWORD
        self.is_demo = True

    def set_custom_certificate(self, pfx_bytes: bytes, password: str) -> None:
        """Loads and activates a user-uploaded .pfx certificate."""
        key, cert, cas = serialization.pkcs12.load_key_and_certificates(
            pfx_bytes,
            password.encode("utf-8") if password else None,
        )
        if cert is None:
            raise ValueError("The provided .pfx file does not contain a certificate.")
        if key is None:
            raise ValueError("The provided .pfx file does not contain a private key.")

        self.workspace.mkdir(parents=True, exist_ok=True)
        with open(self.uploaded_pfx_path, "wb") as f:
            f.write(pfx_bytes)

        pem_bytes = cert.public_bytes(serialization.Encoding.PEM)
        with open(self.uploaded_pem_path, "wb") as f:
            f.write(pem_bytes)

        self.active_pfx_path = self.uploaded_pfx_path
        self.active_pem_path = self.uploaded_pem_path
        self.active_password = password
        self.is_demo = False

    def reset_to_demo(self) -> None:
        """Resets active certificate to the demo certificate."""
        self.active_pfx_path = DEMO_PFX_PATH
        self.active_pem_path = DEMO_PEM_PATH
        self.active_password = DEMO_PASSWORD
        self.is_demo = True

    def get_active_info(self) -> Dict[str, Any]:
        """Returns metadata about the active certificate."""
        if not self.active_pem_path.exists():
            self.generate_demo_certificate()

        with open(self.active_pem_path, "rb") as f:
            cert = x509.load_pem_x509_certificate(f.read())

        def _get_attr(name: x509.Name, oid: x509.ObjectIdentifier) -> str:
            attrs = name.get_attributes_for_oid(oid)
            return attrs[0].value if attrs else ""

        subject = cert.subject
        issuer = cert.issuer

        is_self_signed = subject == issuer

        return {
            "subject_cn": _get_attr(subject, NameOID.COMMON_NAME),
            "subject_org": _get_attr(subject, NameOID.ORGANIZATION_NAME),
            "subject_country": _get_attr(subject, NameOID.COUNTRY_NAME),
            "issuer_cn": _get_attr(issuer, NameOID.COMMON_NAME),
            "issuer_org": _get_attr(issuer, NameOID.ORGANIZATION_NAME),
            "serial_number": format(cert.serial_number, "X"),
            "not_valid_before": cert.not_valid_before_utc.isoformat(),
            "not_valid_after": cert.not_valid_after_utc.isoformat(),
            "is_self_signed": is_self_signed,
            "is_demo": self.is_demo,
            "filename": self.active_pfx_path.name,
        }


# Default workspace, used when authentication is off (local runs, tests).
cert_manager = CertificateManager()
