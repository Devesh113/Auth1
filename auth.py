from __future__ import annotations

import base64
import hashlib
import hmac
import os
from dataclasses import dataclass


def _b64encode(value: bytes) -> str:
    return base64.b64encode(value).decode("utf-8")


def _b64decode(value: str) -> bytes:
    return base64.b64decode(value.encode("utf-8"))


def hash_password(password: str, *, iterations: int = 200_000) -> str:
    if not password:
        raise ValueError("Password must not be empty")

    salt = os.urandom(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)
    return f"{iterations}${_b64encode(salt)}${_b64encode(digest)}"


def verify_password(password: str, hashed_password: str) -> bool:
    try:
        iterations_text, salt_text, digest_text = hashed_password.split("$", 2)
        iterations = int(iterations_text)
    except (ValueError, AttributeError):
        return False

    digest = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        _b64decode(salt_text),
        iterations,
    )
    expected_digest = _b64decode(digest_text)
    return hmac.compare_digest(digest, expected_digest)


@dataclass(frozen=True)
class UserRecord:
    username: str
    password_hash: str


class AuthService:
    def __init__(self) -> None:
        self._users: dict[str, UserRecord] = {}

    def signup(self, username: str, password: str) -> UserRecord:
        if not username:
            raise ValueError("Username must not be empty")
        if username in self._users:
            raise ValueError("Username already exists")

        user = UserRecord(username=username, password_hash=hash_password(password))
        self._users[username] = user
        return user

    def login(self, username: str, password: str) -> bool:
        user = self._users.get(username)
        if user is None:
            return False
        return verify_password(password, user.password_hash)
