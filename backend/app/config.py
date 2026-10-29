from pathlib import Path
import os

APP_ROOT = Path(__file__).resolve().parents[2]
STORAGE_ROOT = Path(
    os.environ.get("SECURE_EMAIL_STORAGE", APP_ROOT / "storage")
).resolve()

USERS_DIR = STORAGE_ROOT / "users"
CONTACTS_DIR = STORAGE_ROOT / "contacts"
MESSAGES_DIR = STORAGE_ROOT / "messages"
TRUST_DIR = STORAGE_ROOT / "trust"
CERTS_DIR = STORAGE_ROOT / "certificates"
METADATA_DIR = STORAGE_ROOT / "metadata"

DEMO_USERS = {"alice", "bob"}

# These are intentionally fixed only for the requested local demonstration.
# Anyone with access to the source code can see them.
DEMO_PASSWORDS = {
    "alice": "1234",
    "bob": "8765",
}

PROTOCOL_VERSION = "1.0"