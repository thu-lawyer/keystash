"""Random secret generation backed by the `secrets` module."""

from __future__ import annotations

import secrets
import string

AMBIGUOUS = set("Il1O0o|`'\";:,.")


def generate(
    length: int = 24,
    *,
    symbols: bool = True,
    no_ambiguous: bool = True,
) -> str:
    if length < 8:
        raise ValueError("length must be at least 8")
    pools = [string.ascii_lowercase, string.ascii_uppercase, string.digits]
    if symbols:
        pools.append("!@#$%^&*()-_=+[]{}<>?")
    if no_ambiguous:
        pools = ["".join(c for c in pool if c not in AMBIGUOUS) for pool in pools]
    alphabet = "".join(pools)
    # Guarantee at least one char from every class, then fill randomly.
    chars = [secrets.choice(pool) for pool in pools]
    chars += [secrets.choice(alphabet) for _ in range(length - len(chars))]
    secrets.SystemRandom().shuffle(chars)
    return "".join(chars)


def token_hex_compat(nbytes: int = 32) -> str:
    return secrets.token_hex(nbytes)
