import os
import re
from pathlib import Path

from fastapi import HTTPException

from .signature import generate_key_pair

KEY_DIR = Path(os.environ.get("KEY_DIR", Path(__file__).resolve().parent.parent / "keys"))
NAME_RE = re.compile(r"^[a-zA-Z0-9_-]{1,32}$")


def _check(name: str) -> None:
    if not NAME_RE.match(name):
        raise HTTPException(400, "Invalid name. Use 1-32 chars: letters, digits, _ or -.")


def _priv(name: str) -> Path:
    return KEY_DIR / f"{name}.private.pem"


def _pub(name: str) -> Path:
    return KEY_DIR / f"{name}.public.pem"


def create_keys(name: str) -> str:
    _check(name)
    if _pub(name).exists():
        raise HTTPException(409, f'Keys for "{name}" already exist.')
    KEY_DIR.mkdir(parents=True, exist_ok=True)
    private_pem, public_pem = generate_key_pair()
    # Private key never leaves the server; file is owner-read/write only.
    fd = os.open(_priv(name), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(private_pem)
    _pub(name).write_bytes(public_pem)
    return public_pem.decode()


def get_public_key(name: str) -> bytes:
    _check(name)
    if not _pub(name).exists():
        raise HTTPException(404, f'No public key found for "{name}".')
    return _pub(name).read_bytes()


def get_private_key(name: str) -> bytes:
    _check(name)
    if not _priv(name).exists():
        raise HTTPException(404, f'No private key found for "{name}".')
    return _priv(name).read_bytes()
