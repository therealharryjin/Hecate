"""Copy a secret to the clipboard, and clear it again after a delay.

A CLI command exits long before the delay is up, so clearing is handed to a
small detached helper process (``python -m hecate.clipboard``). The helper is
never given the secret. It receives a keyed fingerprint over a pipe -- never
on its command line, where other processes could read it -- waits, and clears
the clipboard only if it still holds the same secret. Anything you copied in
the meantime is left alone.

This is best effort and the README says so: clearing replaces what is on the
clipboard now, but it cannot reach clipboard history (Windows' Win+V, desktop
clipboard managers) or anything already pasted somewhere.
"""

from __future__ import annotations

import hashlib
import hmac
import subprocess
import sys
import time

import pyperclip

from .crypto import rng

_PEPPER_SIZE = 32
_DIGEST_SIZE = 32


class ClipboardUnavailable(Exception):
    """No working clipboard here -- e.g. a headless Linux box without xclip."""


def copy(secret: str, *, clear_after: int) -> None:
    """Copy ``secret`` and schedule it to be cleared in ``clear_after`` seconds.

    There is deliberately no way to copy without clearing: a secret must never
    be left on the clipboard indefinitely.
    """
    if clear_after <= 0:
        raise ValueError("clear_after must be positive; a copied secret always expires")
    try:
        pyperclip.copy(secret)
    except (pyperclip.PyperclipException, OSError) as exc:
        raise ClipboardUnavailable(str(exc)) from None
    _schedule_clear(secret, clear_after)


def _fingerprint(text: str, pepper: bytes) -> bytes:
    # Some backends hand text back with a trailing newline, so both sides drop
    # trailing line breaks before comparing. Stripping only the clipboard's
    # side would mean a stored password that ends in one is never cleared.
    return hashlib.blake2b(
        text.rstrip("\r\n").encode("utf-8"), key=pepper, digest_size=_DIGEST_SIZE
    ).digest()


def _schedule_clear(secret: str, seconds: int) -> None:
    pepper = rng.random_bytes(_PEPPER_SIZE)
    digest = _fingerprint(secret, pepper)
    helper = subprocess.Popen(
        [sys.executable, "-m", "hecate.clipboard", str(seconds)],
        stdin=subprocess.PIPE,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        start_new_session=True,  # outlive the command, and the terminal
    )
    assert helper.stdin is not None
    helper.stdin.write(f"{pepper.hex()} {digest.hex()}\n".encode("ascii"))
    helper.stdin.close()


def clear_if_unchanged(pepper: bytes, digest: bytes) -> bool:
    """Clear the clipboard if it still holds the fingerprinted secret.

    Returns True if it cleared. Never raises: the helper runs detached with
    nowhere to report an error, and failing to clear must not crash anything.
    """
    try:
        current = pyperclip.paste()
    except Exception:  # noqa: BLE001 - backends raise all sorts; see docstring
        return False
    if not current:
        return False
    if not hmac.compare_digest(_fingerprint(current, pepper), digest):
        return False
    try:
        pyperclip.copy("")
    except Exception:  # noqa: BLE001
        return False
    return True


def _helper_main(argv: list[str]) -> None:
    seconds = int(argv[0])
    pepper_hex, digest_hex = sys.stdin.readline().split()
    time.sleep(seconds)
    clear_if_unchanged(bytes.fromhex(pepper_hex), bytes.fromhex(digest_hex))


if __name__ == "__main__":
    _helper_main(sys.argv[1:])
