from pathlib import Path
from typing import Any
import hmac

from cryptography.hazmat.primitives import serialization
from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import Response
from pydantic import BaseModel

from app.config import DEMO_PASSWORDS, MESSAGES_DIR, PROTOCOL_VERSION
from app.models import (
    ContactImportRequest,
    DecryptMessageRequest,
    InitializeCaRequest,
    IssueCertificateRequest,
    KeyGenerateRequest,
    LabTamperRequest,
    LoginRequest,
    SendMessageRequest,
    TrustRequest,
    ValidateCertificateRequest,
    VerifyRequest,
)
from app.services import certificates, contacts, crypto, keys
from app.services.auth import (
    clear_session_cookie,
    require_matching_user,
    require_user,
    set_session_cookie,
)
from app.services.storage import (
    initialize_storage,
    read_json,
    safe_id,
    write_json_atomic,
)


app = FastAPI(
    title="PGP-Style Secure Email System",
    version=PROTOCOL_VERSION,
    description=(
        "Local educational demonstration of hybrid encryption, signatures, "
        "key trust, and a local X.509 CA."
    ),
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://127.0.0.1:5500", "http://localhost:5500"],
    allow_credentials=True,
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type"],
)


@app.on_event("startup")
def startup() -> None:
    initialize_storage()


def _message_path(message_id: str) -> Path:
    try:
        return MESSAGES_DIR / f"{safe_id(message_id)}.json"
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


def _read_package(message_id: str) -> dict[str, Any]:
    path = _message_path(message_id)
    if not path.is_file():
        raise HTTPException(status_code=404, detail="Message not found.")

    package = read_json(path, None)
    if not isinstance(package, dict):
        raise HTTPException(status_code=422, detail="Stored message package is malformed.")
    return package


def _sender_public_key(package: dict[str, Any], recipient_id: str):
    sender_id = package.get("sender_id")
    contact = contacts.get_contact(recipient_id, sender_id) if sender_id else None

    # Prefer the recipient's independently imported contact key.
    if contact:
        return keys.load_public_key_from_bytes(
            contact["public_key_pem"].encode("ascii")
        )

    # A signature checked with an embedded key does not establish identity.
    pem = package.get("sender_public_key_pem")
    if not isinstance(pem, str):
        raise ValueError("Sender public key is missing.")
    return keys.load_public_key_from_bytes(pem.encode("ascii"))


@app.get("/api/health")
def health():
    return {"status": "ok", "protocol_version": PROTOCOL_VERSION}


@app.post("/api/auth/login")
def login(request: LoginRequest, response: Response):
    expected_password = DEMO_PASSWORDS[request.username]
    if not hmac.compare_digest(request.password, expected_password):
        raise HTTPException(status_code=401, detail="Incorrect username or password.")

    set_session_cookie(response, request.username)
    return {"user_id": request.username}


@app.post("/api/auth/logout")
def logout(response: Response, user_id: str = Depends(require_user)):
    clear_session_cookie(response)
    return {"logged_out": True}


@app.get("/api/auth/me")
def current_session(user_id: str = Depends(require_user)):
    return {"user_id": user_id}


@app.get("/api/users")
def users(user_id: str = Depends(require_user)):
    # Only return the current session identity.
    return [{"user_id": user_id}]


@app.post("/api/keys/generate")
def generate_keys(
    request: KeyGenerateRequest,
    user_id: str = Depends(require_user),
):
    require_matching_user(user_id, request.user_id)
    try:
        fingerprint = keys.generate_user_keypair(
            request.user_id,
            request.password,
        )
        return {"user_id": request.user_id, "fingerprint": fingerprint}
    except FileExistsError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.get("/api/keys/{requested_user_id}/fingerprint")
def get_fingerprint(
    requested_user_id: str,
    user_id: str = Depends(require_user),
):
    require_matching_user(user_id, requested_user_id)
    try:
        public_key = keys.load_user_public_key(user_id)
        return {"user_id": user_id, "fingerprint": keys.fingerprint(public_key)}
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.get("/api/keys/{requested_user_id}/public")
def export_public_key(
    requested_user_id: str,
    user_id: str = Depends(require_user),
):
    require_matching_user(user_id, requested_user_id)
    try:
        pem = keys.export_public_key(user_id)
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc

    return Response(
        content=pem,
        media_type="application/x-pem-file",
        headers={
            "Content-Disposition": f'attachment; filename="{user_id}-public.pem"'
        },
    )


@app.post("/api/contacts/import")
def import_contact(
    request: ContactImportRequest,
    user_id: str = Depends(require_user),
):
    require_matching_user(user_id, request.owner_id)
    if request.contact_id == user_id:
        raise HTTPException(status_code=400, detail="Choose the other demo user as contact.")

    try:
        contact = contacts.add_or_update_contact(
            owner_id=user_id,
            contact_id=request.contact_id,
            display_name=request.display_name,
            public_pem=request.public_key_pem.encode("ascii"),
            accept_replacement=request.accept_replacement,
        )
        return {
            key: value for key, value in contact.items()
            if key != "public_key_pem"
        }
    except UnicodeEncodeError as exc:
        raise HTTPException(
            status_code=400,
            detail="Public key must be ASCII PEM text.",
        ) from exc
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@app.get("/api/contacts/{owner_id}")
def list_contacts(
    owner_id: str,
    user_id: str = Depends(require_user),
):
    require_matching_user(user_id, owner_id)
    result = []
    for contact in contacts.list_contacts(user_id):
        result.append({
            key: value for key, value in contact.items()
            if key != "public_key_pem"
        })
    return result


@app.get("/api/contacts/{owner_id}/{contact_id}/public")
def contact_public_key(
    owner_id: str,
    contact_id: str,
    user_id: str = Depends(require_user),
):
    require_matching_user(user_id, owner_id)
    try:
        pem = contacts.get_contact_public_pem(user_id, contact_id)
        return Response(content=pem, media_type="application/x-pem-file")
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.post("/api/trust")
def update_trust(
    request: TrustRequest,
    user_id: str = Depends(require_user),
):
    require_matching_user(user_id, request.owner_id)
    try:
        record = contacts.set_trust(
            owner_id=user_id,
            contact_id=request.contact_id,
            status=request.status,
            method=request.method,
            notes=request.notes,
        )
        return {"contact_id": request.contact_id, **record}
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.post("/api/messages/send")
def send_message(
    request: SendMessageRequest,
    user_id: str = Depends(require_user),
):
    require_matching_user(user_id, request.sender_id)
    if request.sender_id == request.recipient_id:
        raise HTTPException(status_code=400, detail="Choose a different recipient.")

    try:
        sender_private = keys.load_private_key(user_id, request.password)
        sender_public = keys.load_user_public_key(user_id)
        recipient_public = keys.load_user_public_key(request.recipient_id)

        package = crypto.create_encrypted_package(
            sender_id=user_id,
            recipient_id=request.recipient_id,
            subject=request.subject,
            body=request.body,
            sender_private_key=sender_private,
            sender_public_key=sender_public,
            recipient_public_key=recipient_public,
        )
        write_json_atomic(_message_path(package["message_id"]), package)

        return {
            "message_id": package["message_id"],
            "sender_id": user_id,
            "recipient_id": request.recipient_id,
            "encrypted": True,
            "signed": True,
        }
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.get("/api/inbox/{requested_user_id}")
def inbox(
    requested_user_id: str,
    user_id: str = Depends(require_user),
):
    require_matching_user(user_id, requested_user_id)
    result = []

    for path in MESSAGES_DIR.glob("*.json"):
        package = read_json(path, {})
        if isinstance(package, dict) and package.get("recipient_id") == user_id:
            result.append({
                "message_id": package.get("message_id"),
                "sender_id": package.get("sender_id"),
                "recipient_id": package.get("recipient_id"),
                "created_at": package.get("created_at"),
                "encrypted": True,
            })

    return sorted(
        result,
        key=lambda item: item.get("created_at") or "",
        reverse=True,
    )


@app.get("/api/messages/{message_id}")
def message_details(
    message_id: str,
    user_id: str = Depends(require_user),
):
    package = _read_package(message_id)
    if package.get("recipient_id") != user_id:
        raise HTTPException(status_code=403, detail="Not authorized to view this message.")

    return {
        key: value for key, value in package.items()
        if key != "sender_public_key_pem"
    }


@app.post("/api/messages/{message_id}/verify")
def verify_message(
    message_id: str,
    request: VerifyRequest,
    user_id: str = Depends(require_user),
):
    require_matching_user(user_id, request.recipient_id)
    package = _read_package(message_id)
    if package.get("recipient_id") != user_id:
        raise HTTPException(status_code=403, detail="Not authorized to verify this message.")

    try:
        sender_public = _sender_public_key(package, user_id)
        signature_valid = crypto.verify_package(package, sender_public)
    except (KeyError, ValueError, TypeError):
        signature_valid = False

    return {
        "signature_valid": signature_valid,
        "sender_trust": contacts.get_trust(user_id, package.get("sender_id", "")),
        "certificate_status": "not_applicable",
    }


@app.post("/api/messages/{message_id}/decrypt")
def decrypt_message(
    message_id: str,
    request: DecryptMessageRequest,
    user_id: str = Depends(require_user),
):
    require_matching_user(user_id, request.user_id)
    package = _read_package(message_id)
    if package.get("recipient_id") != user_id:
        raise HTTPException(status_code=403, detail="Not authorized to decrypt this message.")

    try:
        sender_public = _sender_public_key(package, user_id)
        signature_valid = crypto.verify_package(package, sender_public)
    except (KeyError, ValueError, TypeError):
        signature_valid = False

    if not signature_valid:
        raise HTTPException(
            status_code=422,
            detail="Signature verification failed; message was not decrypted.",
        )

    try:
        recipient_private = keys.load_private_key(user_id, request.password)
        plaintext = crypto.decrypt_package(package, recipient_private)
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(
            status_code=422,
            detail="Decryption failed; plaintext was not accepted.",
        ) from exc
    except Exception as exc:
        raise HTTPException(
            status_code=422,
            detail=(
                "Decryption or AES-GCM authentication failed; "
                "plaintext was not accepted."
            ),
        ) from exc

    return {
        "decryption_successful": True,
        "message_authentication_successful": True,
        **plaintext,
    }


@app.post("/api/ca/initialize")
def ca_initialize(
    request: InitializeCaRequest,
    user_id: str = Depends(require_user),
):
    try:
        fingerprint = certificates.initialize_ca(request.password)
        return {"initialized": True, "ca_fingerprint": fingerprint}
    except FileExistsError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.post("/api/ca/issue")
def ca_issue(
    request: IssueCertificateRequest,
    user_id: str = Depends(require_user),
):
    require_matching_user(user_id, request.subject_id)
    try:
        public_pem = keys.export_public_key(user_id)
        certificate_pem = certificates.issue_certificate(
            user_id,
            public_pem,
            request.ca_password,
        )
        return {
            "subject_id": user_id,
            "certificate_pem": certificate_pem.decode("ascii"),
        }
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.post("/api/ca/validate")
def ca_validate(
    request: ValidateCertificateRequest,
    user_id: str = Depends(require_user),
):
    require_matching_user(user_id, request.subject_id)
    try:
        return certificates.validate_certificate(
            request.certificate_pem.encode("ascii"),
            user_id,
        )
    except UnicodeEncodeError as exc:
        raise HTTPException(
            status_code=400,
            detail="Certificate must be ASCII PEM text.",
        ) from exc


@app.post("/api/lab/tamper/{message_id}")
def lab_tamper(
    message_id: str,
    request: LabTamperRequest,
    user_id: str = Depends(require_user),
):
    require_matching_user(user_id, request.recipient_id)
    package = _read_package(message_id)
    if package.get("recipient_id") != user_id:
        raise HTTPException(status_code=403, detail="Not authorized to test this message.")

    tampered = dict(package)
    if request.field == "subject":
        tampered["lab_subject_tamper"] = "changed"
    else:
        try:
            raw = crypto.b64d(tampered["ciphertext_and_tag"])
        except (KeyError, ValueError) as exc:
            raise HTTPException(
                status_code=422,
                detail="Stored ciphertext is malformed.",
            ) from exc

        if not raw:
            raise HTTPException(status_code=422, detail="Stored ciphertext is empty.")

        tampered["ciphertext_and_tag"] = crypto.b64e(
            raw[:-1] + bytes([raw[-1] ^ 1])
        )

    try:
        sender_public = _sender_public_key(package, user_id)
        signature_valid = crypto.verify_package(tampered, sender_public)
    except (KeyError, ValueError, TypeError):
        signature_valid = False

    return {
        "test_copy_only": True,
        "signature_valid_after_tamper": signature_valid,
        "tampering_detected": not signature_valid,
    }