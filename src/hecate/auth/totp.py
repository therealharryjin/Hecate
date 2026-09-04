"""TOTP enrollment and verification for unlocking the vault.

All TOTP arithmetic -- the HMAC, the time-step counter, the dynamic
truncation, the drift window -- is handled by ``pyotp``. Hand-rolling RFC 6238
would be exactly the sort of thing worth flagging; we do not do it here.

Scope: this is the vault's *own* second factor. Hecate never stores TOTP
secrets belonging to other services.
"""

from __future__ import annotations

import base64
import secrets

import pyotp

ISSUER = "Hecate"

#: Accept the immediately preceding and following 30s step to tolerate clock
#: skew between this machine and the phone. One step either side is the usual
#: compromise; widening it linearly widens the window for a stolen code.
DRIFT_WINDOW = 1


def generate_secret() -> str:
    """Create a fresh base32 TOTP secret (160 bits, per RFC 4226 guidance)."""
    return base64.b32encode(secrets.token_bytes(20)).decode("ascii").rstrip("=")


def provisioning_uri(secret: str, account: str) -> str:
    """Build the ``otpauth://`` URI the authenticator app scans."""
    return pyotp.TOTP(secret).provisioning_uri(name=account, issuer_name=ISSUER)


def verify(secret: str, code: str, *, at: int | None = None) -> bool:
    """Constant-time verification of a submitted code, with drift tolerance."""
    if not code or not code.strip().isdigit():
        return False
    totp = pyotp.TOTP(secret)
    if at is None:
        return totp.verify(code.strip(), valid_window=DRIFT_WINDOW)
    return totp.verify(code.strip(), for_time=at, valid_window=DRIFT_WINDOW)


def current_code(secret: str, *, at: int | None = None) -> str:
    """Generate the code for a given moment. Used only by tests and enrollment
    confirmation -- never to bypass a prompt."""
    totp = pyotp.TOTP(secret)
    return totp.now() if at is None else totp.at(at)
