"""The value every generator returns."""

from __future__ import annotations

import dataclasses


@dataclasses.dataclass(frozen=True)
class Generated:
    """A generated secret and how hard it is to guess.

    ``entropy_bits`` is log2 of the number of equally likely outcomes the
    generator could have produced with the same settings. It measures the
    settings, not this particular value -- no generated password is "weaker"
    than its siblings just because it happens to look like a word.

    The value is kept out of ``repr`` so a secret never lands in a traceback.
    """

    value: str = dataclasses.field(repr=False)
    entropy_bits: float
    kind: str
