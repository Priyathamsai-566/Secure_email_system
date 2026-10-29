import base64
import json
import os
import uuid
from datetime import datetime, timezone
from typing import Any

from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from app.config import PROTOCOL_VERSION
from app.services.keys import load_private_key


OAEP_LABEL = b"PGP-Style-Secure-Email-v1"


def b64e(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def b64d(value: str) -> bytes:
    try:
        return base64.b64decode(value, validate=True)
    except Exception as exc:
        raise ValueError("Invalid base64 field in message package.") from exc


def canonical_bytes(package: dict[str, Any]) -> bytes:
    unsigned = {key: value for key, value in package.items() if key != "signature"}
    return json.dumps(
        unsigned,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def create_encrypted_package(
    *,
    sender_id: str,
    recipient_id: str,
    subject: str,
    body: str,
    sender_private_key,
    recipient_public_key,
) -> dict[str, Any]:
    if not isinstance(recipient_public_key, rsa.RSAPublicKey):
        raise ValueError("Recipient key must be RSA.")
    if len(subject) > 300 or len(body) > 100_000:
        raise ValueError("Subject or message body is too long.")

    aes_key = AESGCM.generate_key(bit_length=256)
    nonce = os.urandom(12)
    plaintext = json.dumps(
        {"subject": subject, "body": body},
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")

    ciphertext_and_tag = AESGCM(aes_key).encrypt(nonce, plaintext, None)
    wrapped_key = recipient_public_key.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=OAEP_LABEL,
        ),
    )

    package = {
        "version": PROTOCOL_VERSION,
        "message_id": str(uuid.uuid4()),
        "sender_id": sender_id,
        "recipient_id": recipient_id,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "encryption": "AES-256-GCM",
        "key_wrapping": "RSA-OAEP-SHA256",
        "signature_algorithm": "RSA-PSS-SHA256",
        "nonce": b64e(nonce),
        "wrapped_key": b64e(wrapped_key),
        "ciphertext_and_tag": b64e(ciphertext_and_tag),
    }
    signature = sender_private_key.sign(
        canonical_bytes(package),
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH,
        ),
        hashes.SHA256(),
    )
    package["signature"] = b64e(signature)
    return package


def verify_package(package: dict[str, Any], sender_public_key) -> bool:
    if not isinstance(sender_public_key, rsa.RSAPublicKey):
        return False
    try:
        sender_public_key.verify(
            b64d(package["signature"]),
            canonical_bytes(package),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH,
            ),
            hashes.SHA256(),
        )
        return True
    except (InvalidSignature, KeyError, ValueError, TypeError):
        return False


def decrypt_package(package: dict[str, Any], recipient_private_key) -> dict[str, str]:
    if package.get("encryption") != "AES-256-GCM":
        raise ValueError("Unsupported encryption algorithm.")
    if package.get("key_wrapping") != "RSA-OAEP-SHA256":
        raise ValueError("Unsupported key-wrapping algorithm.")

    aes_key = recipient_private_key.decrypt(
        b64d(package["wrapped_key"]),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=OAEP_LABEL,
        ),
    )
    plaintext = AESGCM(aes_key).decrypt(
        b64d(package["nonce"]),
        b64d(package["ciphertext_and_tag"]),
        None,
    )
    decoded = json.loads(plaintext.decode("utf-8"))
    if not isinstance(decoded, dict):
        raise ValueError("Decrypted message has an invalid format.")
    if not isinstance(decoded.get("subject"), str):
        raise ValueError("Decrypted subject has an invalid format.")
    if not isinstance(decoded.get("body"), str):
        raise ValueError("Decrypted body has an invalid format.")
    return {"subject": decoded["subject"], "body": decoded["body"]}

def create_encrypted_package(
    *,
    sender_id: str,
    recipient_id: str,
    subject: str,
    body: str,
    sender_private_key,
    sender_public_key,
    recipient_public_key,
) -> dict[str, Any]:
    if not isinstance(sender_public_key, rsa.RSAPublicKey):
        raise ValueError("Sender key must be RSA.")
    if not isinstance(recipient_public_key, rsa.RSAPublicKey):
        raise ValueError("Recipient key must be RSA.")
    if len(subject) > 300 or len(body) > 100_000:
        raise ValueError("Subject or message body is too long.")

    from cryptography.hazmat.primitives import serialization

    aes_key = AESGCM.generate_key(bit_length=256)
    nonce = os.urandom(12)
    plaintext = json.dumps(
        {"subject": subject, "body": body},
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")

    ciphertext_and_tag = AESGCM(aes_key).encrypt(nonce, plaintext, None)
    wrapped_key = recipient_public_key.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=OAEP_LABEL,
        ),
    )
    sender_public_pem = sender_public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("ascii")

    package = {
        "version": PROTOCOL_VERSION,
        "message_id": str(uuid.uuid4()),
        "sender_id": sender_id,
        "recipient_id": recipient_id,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "encryption": "AES-256-GCM",
        "key_wrapping": "RSA-OAEP-SHA256",
        "signature_algorithm": "RSA-PSS-SHA256",
        "nonce": b64e(nonce),
        "wrapped_key": b64e(wrapped_key),
        "ciphertext_and_tag": b64e(ciphertext_and_tag),
        "sender_public_key_pem": sender_public_pem,
    }

    package["signature"] = b64e(sender_private_key.sign(
        canonical_bytes(package),
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH,
        ),
        hashes.SHA256(),
    ))
    return package