"""Password hashing and verification using Argon2id."""

from functools import lru_cache
from secrets import token_urlsafe

from pwdlib import PasswordHash

password_hash = PasswordHash.recommended()


@lru_cache(maxsize=1)
def _dummy_hash() -> str:
    """Create one throwaway hash for timing-resistant unknown-account checks."""
    return password_hash.hash(token_urlsafe(32))


def hash_password(password: str) -> str:
    """Hash a plaintext password using the recommended Argon2 parameters."""
    return password_hash.hash(password)


def verify_password(password: str, stored_hash: str | None) -> bool:
    """Verify a password; unknown accounts still perform a password-hash check."""
    return password_hash.verify(password, stored_hash or _dummy_hash()) and stored_hash is not None
