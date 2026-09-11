"""Shared test doubles for the offline test modules in this directory.

Plain helpers, kept out of ``conftest.py`` so a second importable module of
that name cannot make imports depend on ``sys.path`` order.
"""

import json
import time

from delinea.secrets.server import (
    AccessTokenAuthorizer,
    PasswordGrantAuthorizer,
    SecretServer,
)

# The two network primitives the SDK calls; patch these, never the literal.
HTTP_GET = "delinea.secrets.server.requests.get"
HTTP_POST = "delinea.secrets.server.requests.post"

# Pass as ``json_data`` for a body that is the JSON literal ``null``: a real
# ``requests.Response`` returns ``None`` from ``json()`` for it, which is a
# different branch from "no JSON at all" (``json()`` raising).
JSON_NULL = object()


class FakeResponse:
    """Minimal stand-in for ``requests.Response`` as consumed by the SDK.

    Exposes only what the SDK reads. ``json()`` raises ``ValueError`` when no
    body was given; pass ``json_data=JSON_NULL`` for a body of ``null``.
    """

    def __init__(self, status_code=200, json_data=None, text=None):
        self.status_code = status_code
        # Mirrors ``requests.Response.ok``: true for anything under 400, so a
        # test cannot pass here while production treats a 3xx differently.
        self.ok = status_code < 400
        self._has_json = json_data is not None
        self._json = None if json_data is JSON_NULL else json_data
        if text is not None:
            self.text = text
        elif self._has_json:
            self.text = json.dumps(self._json)
        else:
            self.text = ""
        self.content = self.text.encode()

    def json(self):
        if not self._has_json:
            raise ValueError("no JSON body")
        return self._json


class HostileBody:
    """A 2xx response whose body cannot be read at all.

    ``json()`` and ``text`` raise something other than ``ValueError``, the case
    the health-check guard exists for: "unhealthy", never "abort detection".
    """

    status_code = 200
    ok = True

    def json(self):
        raise AttributeError("body accessor blew up")

    @property
    def text(self):
        raise AttributeError("body accessor blew up")


class BytesOnlyResponse:
    """A response whose body can only be read as bytes.

    Reading ``.text`` makes ``requests`` decode (and charset-sniff) the whole
    body, which the error path must not do just to keep a short excerpt.
    """

    status_code = 502
    ok = False

    def __init__(self, content):
        self.content = content

    @property
    def text(self):
        raise AssertionError("the error path must not decode the whole body")

    def json(self):
        raise ValueError("no JSON body")


class AttachmentResponse:
    """The secret-field endpoint as ``requests`` delivers an attachment.

    ``.text`` raises, so a production path that decodes the file fails here
    instead of quietly passing on a fake's empty string.
    """

    status_code = 200
    ok = True

    def __init__(self, content, encoding=None):
        self.content = content
        self.encoding = encoding

    @property
    def text(self):
        raise AssertionError("an attachment must be carried as bytes, not text")


class EncodinglessResponse(AttachmentResponse):
    """An attachment response with no ``encoding`` attribute at all.

    What ``getattr(response, "encoding", None)`` at the call site defends
    against: a proxy, or anything that never sets the field.
    """

    def __init__(self, content):
        self.content = content


def health_response(healthy, status_code=200):
    """A health-check response as ``_validate_health_endpoint`` reads it."""
    return FakeResponse(status_code=status_code, json_data={"Healthy": bool(healthy)})


def vault_broker_payload(vault_url="https://vault.example.com"):
    """The ``/vaultbroker/api/vaults`` body ``ensure_vault_url`` parses."""
    return {
        "vaults": [
            {"isDefault": True, "isActive": True, "connection": {"url": vault_url}}
        ]
    }


def vault_broker_response(vault_url="https://vault.example.com"):
    """``vault_broker_payload`` as a 200 response."""
    return FakeResponse(json_data=vault_broker_payload(vault_url))


TOKEN_FROM_FAKE_ENDPOINT = "tok-from-fake-token-endpoint"


def fake_token_post(url, *args, **kwargs):
    """Stand in for ``requests.post`` against an OAuth2 token endpoint.

    Patching only ``requests.get`` would let a grant request reach the real
    network with the test's fake credentials, and block for the full timeout.
    """
    return FakeResponse(
        json_data={"access_token": TOKEN_FROM_FAKE_ENDPOINT, "expires_in": 1200}
    )


def make_grant_authorizer(
    base_url="https://ss.example.com", username="user", password="pass", **kwargs
):
    """A ``PasswordGrantAuthorizer`` with an explicit type, so no probe fires."""
    kwargs.setdefault("server_type", "secret_server")
    return PasswordGrantAuthorizer(base_url, username, password, **kwargs)


def make_server(base_url, server_type, token="tok"):
    """A ``SecretServer`` over a pre-resolved ``AccessTokenAuthorizer``.

    The explicit ``server_type`` means construction issues no health probe, so
    the caller's ``requests.get`` patch only ever sees the calls under test.
    """
    return SecretServer(
        base_url, AccessTokenAuthorizer(token, base_url, server_type=server_type)
    )


def join_all(threads, timeout=10):
    """Join worker threads with a bound, so a deadlock fails in seconds with
    the stuck workers named.

    ``timeout`` is a total budget, not per thread; create threads as daemons.
    """
    deadline = time.monotonic() + timeout
    for t in threads:
        t.join(max(0.0, deadline - time.monotonic()))
    stuck = [t.name for t in threads if t.is_alive()]
    assert not stuck, f"worker threads did not finish within {timeout}s: {stuck}"
