"""Offline unit tests for the Phase 1 security-review fixes (see DevPlan.md).

Covers:
- SDK-1: every HTTP call the SDK issues passes an explicit ``timeout``.
- SDK-3: the OAuth2 grant refreshes *before* expiry (drift subtracted).
- SDK-9: ``SecretServerError.response`` is populated, and ``process()`` no
  longer raises ``UnboundLocalError`` on a 4xx JSON body without a
  message/error key.

Fully OFFLINE, in the style of ``tests/test_server_detection_cache.py``: the
network is mocked by patching ``delinea.secrets.server.requests``.
"""

import json
from datetime import datetime, timedelta, timezone

import pytest

from delinea.secrets.server import (
    AccessTokenAuthorizer,
    PasswordGrantAuthorizer,
    SecretServer,
    SecretServerClientError,
    SecretServerError,
)


class FakeResponse:
    """Minimal stand-in for ``requests.Response`` as consumed by the SDK."""

    def __init__(self, status_code=200, json_data=None, text=None):
        self.status_code = status_code
        self._json = json_data
        if text is not None:
            self.text = text
        elif json_data is not None:
            self.text = json.dumps(json_data)
        else:
            self.text = ""
        self.content = self.text.encode()

    def json(self):
        if self._json is None:
            raise ValueError("no JSON body")
        return self._json


# ---------------------------------------------------------------------------
# SDK-1: timeout coverage
# ---------------------------------------------------------------------------


@pytest.fixture
def http_spy(monkeypatch):
    """Replace ``requests.get``/``requests.post`` with a recording fake that
    serves canned, route-appropriate responses. Returns the list of recorded
    (method, url, kwargs) calls."""

    calls = []

    def route(url, params=None):
        if url.endswith("/secrets/search-total"):
            return FakeResponse(text="3")
        if url.endswith("/folders/lookup"):
            return FakeResponse(
                json_data={"total": 2, "records": [{"id": 7}, {"id": 8}]}
            )
        if url.endswith("/secrets"):
            return FakeResponse(json_data={"records": [{"id": 1}]})
        if "/secrets/" in url:
            return FakeResponse(json_data={"items": []})
        if "/folders/" in url:
            return FakeResponse(json_data={"id": 1})
        return FakeResponse(json_data={})

    def fake_get(url, *args, **kwargs):
        calls.append(("GET", url, kwargs))
        return route(url, kwargs.get("params"))

    def fake_post(url, *args, **kwargs):
        calls.append(("POST", url, kwargs))
        return FakeResponse(json_data={"access_token": "tok", "expires_in": 1200})

    monkeypatch.setattr("delinea.secrets.server.requests.get", fake_get)
    monkeypatch.setattr("delinea.secrets.server.requests.post", fake_post)
    return calls


def _server(base_url="https://ss.example.com"):
    authorizer = AccessTokenAuthorizer("tok", base_url, server_type="secret_server")
    return SecretServer(base_url, authorizer)


def test_every_http_call_passes_a_timeout(http_spy):
    """Exercise every SecretServer request path and assert an explicit timeout
    is passed on each underlying HTTP call (SDK-1)."""
    server = _server()

    server.get_secret_json(1)
    server.get_secret_json(1, query_params={"a": "b"})
    server.get_folder_json(1, query_params={})  # get_all_children default True
    server.get_folder_json(1, query_params={"a": "b"}, get_all_children=False)
    server.search_secrets()
    server.search_secrets(query_params={"a": "b"})
    server.lookup_folders()
    server.lookup_folders(query_params={"a": "b"})
    server.get_secret_ids_by_folderid(2)
    server.get_child_folder_ids_by_folderid(2)

    assert len(http_spy) > 0
    missing = [
        (method, url) for method, url, kwargs in http_spy if "timeout" not in kwargs
    ]
    assert missing == [], f"HTTP calls issued without a timeout: {missing}"


def test_token_grant_passes_a_timeout(http_spy):
    """The OAuth2 token POST must also carry a timeout (SDK-1)."""
    grant = PasswordGrantAuthorizer(
        "https://ss.example.com", "user", "pass", server_type="secret_server"
    )
    grant.get_access_token()

    posts = [c for c in http_spy if c[0] == "POST"]
    assert len(posts) == 1
    assert "timeout" in posts[0][2]


# ---------------------------------------------------------------------------
# SDK-3: refresh drift is subtracted (refresh happens BEFORE expiry)
# ---------------------------------------------------------------------------


def _grant_authorizer_with_token(refreshed_seconds_ago, expires_in=1200):
    auth = PasswordGrantAuthorizer(
        "https://ss.example.com", "user", "pass", server_type="secret_server"
    )
    auth.access_grant = {"access_token": "old", "expires_in": expires_in}
    auth.access_grant_refreshed = datetime.now(timezone.utc) - timedelta(
        seconds=refreshed_seconds_ago
    )
    # Shadow the grant call on the instance so no network is needed.
    auth.get_access_grant = lambda token_url, grant_request: {
        "access_token": "new",
        "expires_in": expires_in,
    }
    return auth


def test_refresh_fires_inside_drift_window():
    """A token expiring within the 300s drift window is refreshed early."""
    # expires_in=1200, refreshed 901s ago -> 299s of validity left (< 300 drift)
    auth = _grant_authorizer_with_token(refreshed_seconds_ago=1200 - 299)
    assert auth.get_access_token() == "new"


def test_refresh_skipped_outside_drift_window():
    """A token with more than the drift window of validity left is reused."""
    # expires_in=1200, refreshed 899s ago -> 301s of validity left (> 300 drift)
    auth = _grant_authorizer_with_token(refreshed_seconds_ago=1200 - 301)
    assert auth.get_access_token() == "old"


def test_expired_token_is_refreshed():
    """A token past its expiry is never reused (regression guard: the old
    ``+ seconds_of_drift`` arithmetic kept expired tokens alive for 300s)."""
    auth = _grant_authorizer_with_token(refreshed_seconds_ago=1201)
    assert auth.get_access_token() == "new"


# ---------------------------------------------------------------------------
# SDK-9: exception plumbing
# ---------------------------------------------------------------------------


def test_error_response_attribute_is_set():
    response = FakeResponse(status_code=403)
    err = SecretServerError("denied", response)
    assert err.response is response
    assert err.message == "denied"


def test_process_4xx_json_without_message_key():
    """A 4xx JSON body lacking message/error keys must raise a client error
    with a fallback message, not ``UnboundLocalError``."""
    response = FakeResponse(status_code=403, json_data={"foo": 1})
    with pytest.raises(SecretServerClientError) as excinfo:
        SecretServer.process(response)
    assert excinfo.value.response is response
    assert "403" in excinfo.value.message


def test_process_4xx_json_with_message_key():
    response = FakeResponse(status_code=400, json_data={"message": "bad request"})
    with pytest.raises(SecretServerClientError) as excinfo:
        SecretServer.process(response)
    assert excinfo.value.message == "bad request"
    assert excinfo.value.response is response


def test_process_4xx_non_json_body():
    response = FakeResponse(status_code=404, text="<html>not found</html>")
    with pytest.raises(SecretServerClientError) as excinfo:
        SecretServer.process(response)
    assert excinfo.value.response is response
