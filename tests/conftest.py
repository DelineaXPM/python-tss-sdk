"""Fixtures shared by the offline test modules in this directory.

Additive to the repository-root ``conftest.py``, which holds the live-tenant
fixtures. Neither is ``autouse``; offline modules opt in via ``pytestmark``.
"""

import pytest

from delinea.secrets.server import Authorizer
from fakes import HTTP_GET, HTTP_POST


@pytest.fixture
def clear_detection_cache():
    """Isolate the process-global server-detection cache.

    It lives on the ``Authorizer`` class for the life of the process, so
    without this one test's cached detection changes what a later one runs.
    """
    Authorizer.clear_server_type_cache()
    yield
    Authorizer.clear_server_type_cache()


@pytest.fixture
def no_network(monkeypatch):
    """Turn an unmocked HTTP call in an offline test into a loud failure.

    Raising is not enough on its own: the health probe swallows exceptions, so
    every attempt is recorded and asserted at teardown instead.
    """
    attempts = []

    def blocked(*args, **kwargs):
        attempts.append(args[0] if args else kwargs.get("url"))
        raise AssertionError(
            "offline test attempted a real network call; patch "
            "delinea.secrets.server.requests.get / .post in the test"
        )

    monkeypatch.setattr(HTTP_GET, blocked)
    monkeypatch.setattr(HTTP_POST, blocked)
    yield attempts
    assert not attempts, (
        f"offline test reached the network guard {len(attempts)} time(s) and "
        f"the SDK swallowed the failure: {attempts[:3]}"
    )
