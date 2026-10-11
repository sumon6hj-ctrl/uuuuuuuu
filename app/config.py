# -*- coding: utf-8 -*-
import os
import secrets
import hmac
import hashlib
from pathlib import Path
from cryptography.fernet import Fernet
from dotenv import load_dotenv

BASE_DIR = Path(__file__).resolve().parent.parent
ENV_PATH = BASE_DIR / ".env"
DATA_DIR = BASE_DIR / "data"
DATA_DIR.mkdir(parents=True, exist_ok=True)

# Hosting/platform environment variables take precedence over .env by default.
# Capture the source before dotenv fills missing values; never print the value.
ADMIN_PASSWORD_ENV_OVERRIDE = bool(os.getenv("ADMIN_PASSWORD", "").strip())
load_dotenv(ENV_PATH)


def _ensure_env_secrets() -> tuple[str, str]:
    """Ensure persistent SECRET_KEY and FERNET_KEY exist so encrypted accounts survive restarts."""
    secret_key = os.getenv("SECRET_KEY", "").strip()
    fernet_key = os.getenv("FERNET_KEY", "").strip()

    updated_lines = []
    need_write = False

    if not secret_key:
        secret_key = secrets.token_hex(32)
        os.environ["SECRET_KEY"] = secret_key
        updated_lines.append(f"SECRET_KEY={secret_key}")
        need_write = True

    if not fernet_key:
        fernet_key = Fernet.generate_key().decode("utf-8")
        os.environ["FERNET_KEY"] = fernet_key
        updated_lines.append(f"FERNET_KEY={fernet_key}")
        need_write = True

    if need_write:
        try:
            existing = ENV_PATH.read_text(encoding="utf-8") if ENV_PATH.exists() else ""
            with open(ENV_PATH, "a", encoding="utf-8") as f:
                if existing and not existing.endswith("\n"):
                    f.write("\n")
                for line in updated_lines:
                    f.write(line + "\n")
            ENV_PATH.chmod(0o600)
        except OSError as exc:
            raise RuntimeError("Set persistent SECRET_KEY and FERNET_KEY in hosting secrets; .env is not writable.") from exc

    return secret_key, fernet_key


SECRET_KEY, FERNET_KEY = _ensure_env_secrets()

ADMIN_USERNAME = os.getenv("ADMIN_USERNAME", "admin").strip()


def _admin_password() -> str:
    password = os.getenv("ADMIN_PASSWORD", "").strip()
    if password and (len(password) < 12 or password in {
        "admin123", "ChangeThisStrongPassword!2026", "password123456"
    }):
        raise RuntimeError("Insecure ADMIN_PASSWORD. Set a unique password of at least 12 characters in .env or hosting secrets.")
    if password:
        return password
    # First-run local installation: create a strong *private* persistent secret
    # instead of shipping a public/admin123 fallback. Never print it in logs.
    password = secrets.token_urlsafe(32)
    try:
        with open(ENV_PATH, "a", encoding="utf-8") as f:
            f.write(f"\nADMIN_PASSWORD={password}\n")
        ENV_PATH.chmod(0o600)
    except OSError as exc:
        raise RuntimeError("Set ADMIN_PASSWORD in the hosting secrets manager; .env is not writable.") from exc
    os.environ["ADMIN_PASSWORD"] = password
    return password


ADMIN_PASSWORD = _admin_password()


def admin_config_fingerprint(username: str, password: str) -> str:
    """Secret-keyed marker for deliberate deployment credential rotation.

    Never store a raw or unsalted password digest in the database.
    """
    message = ("admin-config-v1\0" + username + "\0" + password).encode("utf-8")
    return hmac.new(SECRET_KEY.encode("utf-8"), message, hashlib.sha256).hexdigest()


# Explicit one-boot operator recovery for hosts without a terminal; remove after reset.
ADMIN_PASSWORD_RESET_ON_START = os.getenv("ADMIN_PASSWORD_RESET_ON_START", "").strip() == "1"
SESSION_EXPIRE_HOURS = int(os.getenv("SESSION_EXPIRE_HOURS", "24"))

DATABASE_PATH = os.getenv("DATABASE_PATH", str(DATA_DIR / "dashboard.db"))
DEVICES_FILE_PATH = os.getenv("DEVICES_FILE_PATH", str(DATA_DIR / "devices.json"))
os.environ["DEVICES_FILE_PATH"] = DEVICES_FILE_PATH

# Limits are explicit: account workers are long-lived; logins are short bursts.
# Increase gradually only after monitoring CPU, memory, network and rate limits.
MAX_ACTIVE_WORKERS = max(1, min(1000, int(os.getenv("MAX_ACTIVE_WORKERS", "50"))))
MAX_CONCURRENT_LOGINS = max(1, min(100, int(os.getenv("MAX_CONCURRENT_LOGINS", "8"))))

DEFAULT_ACCOUNT_REGION = os.getenv("DEFAULT_ACCOUNT_REGION", "ME").upper()
PORT = int(os.getenv("PORT", "8000"))
HOST = os.getenv("HOST", "0.0.0.0")

# Each account is cooled down independently after 100 consecutive successful
# StartMatch sends without a server-confirmed UDP JOIN_MATCH.
QUEUE_NO_JOIN_LIMIT = max(10, min(10000, int(os.getenv("QUEUE_NO_JOIN_LIMIT", "100"))))
QUEUE_COOLDOWN_SECONDS = max(60, min(3600, int(os.getenv("QUEUE_COOLDOWN_SECONDS", "600"))))
