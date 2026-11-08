"""Have I Been Pwned's Pwned Passwords lookup, by k-anonymity.

What leaves the machine
-----------------------
For each password, Hecate takes its SHA-1 hash and sends only the first five
hex characters to ``api.pwnedpasswords.com/range/``. The service answers with
every breached hash that starts with those characters -- several hundred of
them -- and the match is made here. The password and its full hash never
leave the machine. :meth:`Client.fetch_range` refuses anything but a 5-character
prefix, so no caller can send more by mistake.

Each request asks for padding (``Add-Padding: true``): the reply is filled out
with decoy entries, so an eavesdropper cannot tell from its size which prefix
was asked about. Decoys have a count of 0 and are ignored.

What the service learns
-----------------------
Your IP address, and the prefix of each password checked. For a password that
is in a breach, the prefix narrows it to the few hundred breached passwords
that share it. That is the trade k-anonymity makes, and the README says so.

No cache, on purpose
--------------------
Nothing about a check is written to disk -- not results, not prefixes. A saved
prefix sits outside the vault's encryption, and for a breached password it
narrows it to a few hundred candidates. Within one run, each distinct prefix
is fetched once.

SHA-1 is used because the service's list is keyed by it, not to protect
anything.
"""

from __future__ import annotations

import hashlib
import importlib.metadata
import string
from typing import Callable, Sequence

import requests

API_URL = "https://api.pwnedpasswords.com/range/"
PREFIX_LENGTH = 5
#: (connect, read) seconds. Generous enough for a slow link, short enough that
#: a dead one fails instead of hanging.
TIMEOUT = (5, 15)

_HEX = set(string.hexdigits.upper())


class BreachCheckError(Exception):
    """The service could not be reached, or answered unexpectedly.

    Messages never include the request URL, so not even a hash prefix ends up
    in an error message.
    """


def sha1_hex(password: str) -> str:
    return hashlib.sha1(password.encode("utf-8"), usedforsecurity=False).hexdigest().upper()


def parse_range(body: str) -> dict[str, int]:
    """Turn a range reply into {hash suffix: times seen}, dropping decoys."""
    seen: dict[str, int] = {}
    for line in body.splitlines():
        suffix, sep, count = line.strip().partition(":")
        if not sep:
            continue
        try:
            times = int(count)
        except ValueError:
            continue
        if times > 0:
            seen[suffix.upper()] = times
    return seen


def _user_agent() -> str:
    try:
        return f"Hecate/{importlib.metadata.version('hecate')}"
    except importlib.metadata.PackageNotFoundError:
        return "Hecate"


def _new_session() -> requests.Session:
    return requests.Session()


class Client:
    def __init__(self, session: requests.Session | None = None) -> None:
        self._session = session if session is not None else _new_session()

    def fetch_range(self, prefix: str) -> dict[str, int]:
        """Every breached hash suffix that follows ``prefix``, with its count."""
        if len(prefix) != PREFIX_LENGTH or not set(prefix) <= _HEX:
            raise ValueError(f"a range prefix is exactly {PREFIX_LENGTH} uppercase hex characters")
        try:
            response = self._session.get(
                API_URL + prefix,
                headers={"Add-Padding": "true", "User-Agent": _user_agent()},
                timeout=TIMEOUT,
                allow_redirects=False,
            )
        except requests.RequestException as exc:
            raise BreachCheckError(
                f"could not reach Have I Been Pwned ({type(exc).__name__})"
            ) from None
        if response.status_code != 200:
            raise BreachCheckError(
                f"Have I Been Pwned answered with HTTP {response.status_code}"
            )
        return parse_range(response.text)


def breach_counts(
    passwords: Sequence[str],
    *,
    fetch: Callable[[str], dict[str, int]] | None = None,
) -> list[int]:
    """How many times each password has been seen in a breach; 0 if never.

    The result lines up with ``passwords``. Each distinct prefix is fetched
    once, so a password used by several entries costs one request.
    """
    if fetch is None:
        fetch = Client().fetch_range
    hashes = [sha1_hex(password) for password in passwords]
    ranges: dict[str, dict[str, int]] = {}
    for digest in hashes:
        prefix = digest[:PREFIX_LENGTH]
        if prefix not in ranges:
            ranges[prefix] = fetch(prefix)
    return [ranges[d[:PREFIX_LENGTH]].get(d[PREFIX_LENGTH:], 0) for d in hashes]
