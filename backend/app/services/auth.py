import base64
import hashlib
import hmac
import json
import os
import time

from fastapi import HTTPException, Request, Response


SESSION_COOKIE_NAME = "secure_mail_session"
SESSION_LIFETIME_SECONDS = 60 * 60 * 8


def _session_secret() -> bytes:
    # Set SECURE_EMAIL_SESSION_SECRET in PowerShell before starting the backend.
    secret = os.environ.get("SECURE_EMAIL_SESSION_SECRET")
    if not secret or len(secret) < 32:
        raise RuntimeError(
            "Set SECURE_EMAIL_SESSION_SECRET to a random value "
            "of at least 32 characters before starting the backend."
        )
    return secret.encode("utf-8")


def _b64encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def _b64decode(value: str) -> bytes:
    padding = "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode(value + padding)


def create_session_token(user_id: str) -> str:
    payload = {
        "sub": user_id,
        "exp": int(time.time()) + SESSION_LIFETIME_SECONDS,
    }
    encoded_payload = _b64encode(
        json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    )
    signature = hmac.new(
        _session_secret(),
        encoded_payload.encode("ascii"),
        hashlib.sha256,
    ).digest()
    return f"{encoded_payload}.{_b64encode(signature)}"


def read_session_token(token: str) -> str | None:
    try:
        encoded_payload, encoded_signature = token.split(".", 1)
        expected_signature = hmac.new(
            _session_secret(),
            encoded_payload.encode("ascii"),
            hashlib.sha256,
        ).digest()

        supplied_signature = _b64decode(encoded_signature)
        if not hmac.compare_digest(expected_signature, supplied_signature):
            return None

        payload = json.loads(_b64decode(encoded_payload))
        user_id = payload.get("sub")
        expires_at = payload.get("exp")

        if user_id not in {"alice", "bob"}:
            return None
        if not isinstance(expires_at, int) or expires_at < int(time.time()):
            return None

        return user_id
    except (ValueError, TypeError, KeyError, json.JSONDecodeError):
        return None


def set_session_cookie(response: Response, user_id: str) -> None:
    response.set_cookie(
        key=SESSION_COOKIE_NAME,
        value=create_session_token(user_id),
        httponly=True,
        secure=False,  # Local HTTP demo only. Production must use HTTPS and Secure=True.
        samesite="strict",
        max_age=SESSION_LIFETIME_SECONDS,
        path="/",
    )


def clear_session_cookie(response: Response) -> None:
    response.delete_cookie(
        key=SESSION_COOKIE_NAME,
        httponly=True,
        secure=False,
        samesite="strict",
        path="/",
    )


def require_user(request: Request) -> str:
    token = request.cookies.get(SESSION_COOKIE_NAME)
    user_id = read_session_token(token) if token else None
    if not user_id:
        raise HTTPException(status_code=401, detail="Please log in.")
    return user_id


def require_matching_user(authenticated_user: str, requested_user: str) -> None:
    if authenticated_user != requested_user:
        raise HTTPException(
            status_code=403,
            detail="You are not authorized to act as this user.",
        )