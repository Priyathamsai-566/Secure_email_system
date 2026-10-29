from datetime import datetime, timedelta, timezone
from pathlib import Path
import secrets

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.x509.oid import NameOID

from app.config import CERTS_DIR
from app.services.keys import load_public_key_from_bytes
from app.services.storage import safe_id


CA_KEY_PATH = CERTS_DIR / "local_ca_private.pem"
CA_CERT_PATH = CERTS_DIR / "local_ca_certificate.pem"
TRUST_ANCHOR_PATH = CERTS_DIR / "trusted_ca_fingerprint.txt"


def _name(common_name: str) -> x509.Name:
    return x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, common_name[:100]),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "PGP-Style Educational Demo"),
    ])


def initialize_ca(password: str) -> str:
    if len(password) < 8:
        raise ValueError("CA password must be at least 8 characters.")
    if CA_KEY_PATH.exists() or CA_CERT_PATH.exists():
        raise FileExistsError("The local CA is already initialized.")

    CERTS_DIR.mkdir(parents=True, exist_ok=True)
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    now = datetime.now(timezone.utc)
    subject = _name("PGP Demo Local Root CA")
    certificate = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .sign(private_key, hashes.SHA256())
    )

    CA_KEY_PATH.write_bytes(private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(
            password.encode("utf-8")
        ),
    ))
    CA_CERT_PATH.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
    TRUST_ANCHOR_PATH.write_text(
        certificate.fingerprint(hashes.SHA256()).hex(),
        encoding="ascii",
    )
    return certificate.fingerprint(hashes.SHA256()).hex().upper()


def issue_certificate(
    subject_id: str,
    subject_public_pem: bytes,
    ca_password: str,
) -> bytes:
    subject_id = safe_id(subject_id)
    if not CA_KEY_PATH.is_file() or not CA_CERT_PATH.is_file():
        raise FileNotFoundError("Initialize the local CA first.")

    try:
        ca_key = serialization.load_pem_private_key(
            CA_KEY_PATH.read_bytes(),
            password=ca_password.encode("utf-8"),
        )
    except (ValueError, TypeError) as exc:
        raise ValueError("Incorrect CA password or invalid CA key.") from exc

    subject_public_key = load_public_key_from_bytes(subject_public_pem)
    ca_certificate = x509.load_pem_x509_certificate(CA_CERT_PATH.read_bytes())
    now = datetime.now(timezone.utc)

    certificate = (
        x509.CertificateBuilder()
        .subject_name(_name(subject_id))
        .issuer_name(ca_certificate.subject)
        .public_key(subject_public_key)
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName(f"{subject_id}.demo.local")]),
            critical=False,
        )
        .sign(ca_key, hashes.SHA256())
    )
    output = CERTS_DIR / f"{subject_id}.pem"
    output.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
    return output.read_bytes()


def validate_certificate(certificate_pem: bytes, expected_subject_id: str) -> dict:
    expected_subject_id = safe_id(expected_subject_id)
    try:
        certificate = x509.load_pem_x509_certificate(certificate_pem)
        ca_certificate = x509.load_pem_x509_certificate(CA_CERT_PATH.read_bytes())
        trusted_fingerprint = TRUST_ANCHOR_PATH.read_text(encoding="ascii").strip()
    except (ValueError, OSError) as exc:
        return {"valid": False, "reason": "Malformed certificate or CA is not initialized."}

    actual_anchor = ca_certificate.fingerprint(hashes.SHA256()).hex()
    if not secrets.compare_digest(actual_anchor, trusted_fingerprint):
        return {"valid": False, "reason": "CA certificate does not match the local trust anchor."}

    now = datetime.now(timezone.utc)
    not_before = certificate.not_valid_before_utc
    not_after = certificate.not_valid_after_utc
    if not (not_before <= now <= not_after):
        return {"valid": False, "reason": "Certificate is outside its validity period."}

    if certificate.issuer != ca_certificate.subject:
        return {"valid": False, "reason": "Certificate issuer does not match the trusted CA."}

    common_names = certificate.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    if not common_names or common_names[0].value != expected_subject_id:
        return {"valid": False, "reason": "Certificate subject does not match expected identity."}

    ca_public_key = ca_certificate.public_key()
    try:
        ca_public_key.verify(
            certificate.signature,
            certificate.tbs_certificate_bytes,
            padding.PKCS1v15(),
            certificate.signature_hash_algorithm,
        )
    except Exception:
        return {"valid": False, "reason": "Certificate signature is invalid."}

    return {
        "valid": True,
        "reason": "Certificate signature, issuer, subject, and validity period are valid.",
        "subject": expected_subject_id,
        "serial_number": str(certificate.serial_number),
        "not_before": not_before.isoformat(),
        "not_after": not_after.isoformat(),
        "issuer": "PGP Demo Local Root CA",
    }