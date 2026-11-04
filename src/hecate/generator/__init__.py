"""Password and passphrase generation.

All randomness comes from :mod:`hecate.crypto.rng`, which is the OS CSPRNG.
Nothing here keeps state or touches the disk: a generated secret exists only in
the caller's hands until the caller decides to store it.
"""

from .passphrase import PassphrasePolicy, generate_passphrase, passphrase_entropy
from .password import PasswordPolicy, generate_password, password_entropy
from .result import Generated

__all__ = [
    "Generated",
    "PassphrasePolicy",
    "PasswordPolicy",
    "generate_passphrase",
    "generate_password",
    "passphrase_entropy",
    "password_entropy",
]
