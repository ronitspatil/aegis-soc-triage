"""Shared CLI startup behaviour.

Configuration problems are the first thing a new user meets, and a pydantic
traceback does not tell them what to do about it.
"""

from __future__ import annotations

import sys
from collections.abc import Callable
from typing import Any, TypeVar

from pydantic import ValidationError

T = TypeVar("T")

_SETUP_HINT = """
Aegis is not configured yet. To get started:

    cp .env.example .env

Then set a reasoning model in .env, either:

    REASONER_PROVIDER=openrouter
    OPENROUTER_API_KEY=...

or:

    REASONER_PROVIDER=anthropic
    ANTHROPIC_API_KEY=...

Worker models run locally, so also:  ollama pull llama3.1:8b

No credentials are needed to run the test suite:  pytest
"""


def with_friendly_config_errors(fn: Callable[..., T]) -> Callable[..., T]:
    """Turn a settings validation failure into an explanation."""

    def wrapper(*args: Any, **kwargs: Any) -> T:
        try:
            return fn(*args, **kwargs)
        except ValidationError as exc:
            problems = "; ".join(e.get("msg", "") for e in exc.errors())
            print(f"Configuration error: {problems}", file=sys.stderr)
            print(_SETUP_HINT, file=sys.stderr)
            raise SystemExit(2) from None

    return wrapper
