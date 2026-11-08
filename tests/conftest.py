import sys
from pathlib import Path

import pytest
import requests

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))


@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    """No test may reach the internet. Breach tests hand in a fake session."""

    def refuse(*_args, **_kwargs):
        raise AssertionError("a test tried to make a real network request")

    monkeypatch.setattr(requests.Session, "request", refuse)
