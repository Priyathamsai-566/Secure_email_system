from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from app.config import CONTACTS_DIR, TRUST_DIR
from app.services.keys import fingerprint, import_public_key
from app.services.storage import read_json, safe_id, write_json_atomic


def _contact_file(owner_id: str) -> Path:
    return CONTACTS_DIR / f"{safe_id(owner_id)}.json"


def _trust_file(owner_id: str) -> Path:
    return TRUST_DIR / f"{safe_id(owner_id)}.json"


def list_contacts(owner_id: str) -> list[dict[str, Any]]:
    contacts = read_json(_contact_file(owner_id), {})
    return list(contacts.values())


def get_contact(owner_id: str, contact_id: str) -> dict[str, Any] | None:
    contacts = read_json(_contact_file(owner_id), {})
    return contacts.get(safe_id(contact_id))


def add_or_update_contact(
    owner_id: str,
    contact_id: str,
    display_name: str,
    public_pem: bytes,
    accept_replacement: bool = False,
) -> dict[str, Any]:
    owner_id = safe_id(owner_id)
    contact_id = safe_id(contact_id)
    normalized_pem, key_fingerprint = import_public_key(public_pem)

    path = _contact_file(owner_id)
    contacts = read_json(path, {})
    existing = contacts.get(contact_id)

    if existing and existing["fingerprint"] != key_fingerprint:
        if not accept_replacement:
            raise ValueError(
                "This contact's public key changed. Explicitly accept the replacement "
                "only after comparing its fingerprint through an independent channel."
            )
        history = existing.get("key_history", [])
        history.append({
            "fingerprint": existing["fingerprint"],
            "replaced_at": datetime.now(timezone.utc).isoformat(),
        })
    else:
        history = existing.get("key_history", []) if existing else []

    contacts[contact_id] = {
        "contact_id": contact_id,
        "display_name": display_name.strip()[:100],
        "public_key_pem": normalized_pem.decode("ascii"),
        "fingerprint": key_fingerprint,
        "trust": existing.get("trust", "unknown") if existing else "unknown",
        "key_history": history,
        "updated_at": datetime.now(timezone.utc).isoformat(),
    }
    write_json_atomic(path, contacts)
    return contacts[contact_id]


def set_trust(
    owner_id: str,
    contact_id: str,
    status: str,
    method: str,
    notes: str = "",
) -> dict[str, Any]:
    if status not in {"trusted", "untrusted", "unknown"}:
        raise ValueError("Trust must be trusted, untrusted, or unknown.")

    contact_id = safe_id(contact_id)
    contacts_path = _contact_file(owner_id)
    contacts = read_json(contacts_path, {})
    if contact_id not in contacts:
        raise FileNotFoundError("Contact does not exist.")

    record = {
        "status": status,
        "method": method.strip()[:200],
        "notes": notes.strip()[:500],
        "recorded_at": datetime.now(timezone.utc).isoformat(),
    }
    contacts[contact_id]["trust"] = status
    contacts[contact_id]["trust_record"] = record
    write_json_atomic(contacts_path, contacts)

    trust_path = _trust_file(owner_id)
    trust_records = read_json(trust_path, {})
    trust_records[contact_id] = record
    write_json_atomic(trust_path, trust_records)
    return record


def get_trust(owner_id: str, contact_id: str) -> str:
    contact = get_contact(owner_id, contact_id)
    return contact.get("trust", "unknown") if contact else "unknown"


def get_contact_public_pem(owner_id: str, contact_id: str) -> bytes:
    contact = get_contact(owner_id, contact_id)
    if not contact:
        raise FileNotFoundError("Contact does not exist.")
    return contact["public_key_pem"].encode("ascii")