import json
import os
import tempfile
from pathlib import Path
from typing import Any

from app.config import (
    USERS_DIR,
    CONTACTS_DIR,
    MESSAGES_DIR,
    TRUST_DIR,
    CERTS_DIR,
    METADATA_DIR,
)


def initialize_storage() -> None:
    for directory in (
        USERS_DIR,
        CONTACTS_DIR,
        MESSAGES_DIR,
        TRUST_DIR,
        CERTS_DIR,
        METADATA_DIR,
    ):
        directory.mkdir(parents=True, exist_ok=True)


def safe_id(value: str) -> str:
    if not value or len(value) > 80:
        raise ValueError("Invalid identifier.")
    if any(c not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_"
           for c in value):
        raise ValueError("Identifier contains unsupported characters.")
    return value


def read_json(path: Path, default: Any) -> Any:
    try:
        with path.open("r", encoding="utf-8") as handle:
            return json.load(handle)
    except FileNotFoundError:
        return default
    except (json.JSONDecodeError, OSError):
        return default


def write_json_atomic(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    data = json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2)
    fd, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.", suffix=".tmp", dir=path.parent
    )
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary_name, path)
    finally:
        try:
            os.unlink(temporary_name)
        except FileNotFoundError:
            pass