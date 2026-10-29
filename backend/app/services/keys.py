import hashlib
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from app.config import USERS_DIR
from app.services.storage import safe_id


def user_directory(user_id: str) -> Path:
    return USERS_DIR / safe_id(user_id)


def public_key_path(user_id: str) -> Path:
    return user_directory(user_id) / "public.pem"


def private_key_path(user_id: str) -> Path:
    return user_directory(user_id) / "private.pem"


def generate_user_keypair(user_id: str, password: str) -> str:
    if len(password) < 8:
        raise ValueError("Private-key password must be at least 8 characters.")

    folder = user_directory(user_id)
    folder.mkdir(parents=True, exist_ok=True)
    if private_key_path(user_id).exists():
        raise FileExistsError("This user already has a key pair.")

    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=3072,
    )
    public_key = private_key.public_key()

    encrypted_private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(
            password.encode("utf-8")
        ),
    )
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    private_key_path(user_id).write_bytes(encrypted_private_pem)
    public_key_path(user_id).write_bytes(public_pem)
    return fingerprint(public_key)


def load_private_key(user_id: str, password: str):
    path = private_key_path(user_id)
    if not path.is_file():
        raise FileNotFoundError("No private key exists for this user.")
    try:
        return serialization.load_pem_private_key(
            path.read_bytes(),
            password=password.encode("utf-8"),
        )
    except (ValueError, TypeError) as exc:
        raise ValueError("Incorrect password or invalid private-key file.") from exc


def load_public_key_from_bytes(pem_data: bytes):
    key = serialization.load_pem_public_key(pem_data)
    if not isinstance(key, rsa.RSAPublicKey):
        raise ValueError("Only RSA public keys are accepted.")
    return key


def load_user_public_key(user_id: str):
    path = public_key_path(user_id)
    if not path.is_file():
        raise FileNotFoundError("No public key exists for this user.")
    return load_public_key_from_bytes(path.read_bytes())


def export_public_key(user_id: str) -> bytes:
    return public_key_path(user_id).read_bytes()


def fingerprint(public_key) -> str:
    der = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    digest = hashlib.sha256(der).hexdigest().upper()
    return ":".join(digest[i:i + 4] for i in range(0, len(digest), 4))


def import_public_key(pem_data: bytes) -> tuple[bytes, str]:
    key = load_public_key_from_bytes(pem_data)
    normalized = key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return normalized, fingerprint(key)