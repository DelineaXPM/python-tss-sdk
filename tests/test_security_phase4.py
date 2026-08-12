"""Offline unit tests for the Phase 4 housekeeping fixes (see DevPlan.md).

Covers:
- 4.1: token refresh is thread-safe (a lock guards ``_refresh``).
- 4.2: grant expiry bookkeeping uses timezone-aware UTC timestamps.
- 4.3: mutable default arguments don't leak state between calls.
- 4.4: ``get_folder_json`` no longer raises TypeError when called with no
  query_params and the default ``get_all_children=True``.
- 4.5: file-attachment ``itemValue`` is the response text, not a Response
  object.
- 4.6: a non-numeric ``search-total`` body raises a clear error instead of
  silently corrupting the subsequent search.

Fully OFFLINE, in the style of ``tests/test_server_detection_cache.py``: the
network is mocked by patching ``delinea.secrets.server.requests``.
"""

import json
import threading
from datetime import datetime, timezone

import pytest

from delinea.secrets.server import (
    AccessTokenAuthorizer,
    Authorizer,
    PasswordGrantAuthorizer,
    SecretServer,
    SecretServerError,
)


class FakeResponse:
    """Minimal stand-in for ``requests.Response``."""

    def __init__(self, status_code=200, json_data=None, text=None):
        self.status_code = status_code
        self.ok = 200 <= status_code < 300
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


@pytest.fixture(autouse=True)
def clear_detection_cache():
    Authorizer._clear_server_type_cache()
    yield
    Authorizer._clear_server_type_cache()


# ---------------------------------------------------------------------------
# 4.1 / 4.2: thread-safe, UTC-aware token refresh
# ---------------------------------------------------------------------------


def test_refresh_is_thread_safe_and_grants_once(monkeypatch):
    """20 threads calling get_access_token() concurrently on a fresh
    authorizer must not corrupt access_grant and should only need to grant a
    small, bounded number of times (never once per thread if the lock works
    as intended for the common case of a already-populated grant)."""
    grant_calls = {"count": 0}

    def fake_get_access_grant(token_url, grant_request):
        grant_calls["count"] += 1
        return {"access_token": f"tok-{grant_calls['count']}", "expires_in": 1200}

    auth = PasswordGrantAuthorizer(
        "https://ss.example.com", "user", "pass", server_type="secret_server"
    )
    monkeypatch.setattr(auth, "get_access_grant", fake_get_access_grant)

    results = []
    errors = []
    start = threading.Event()

    def worker():
        start.wait()
        try:
            results.append(auth.get_access_token())
        except Exception as exc:  # pragma: no cover - failure path
            errors.append(exc)

    threads = [threading.Thread(target=worker) for _ in range(20)]
    for t in threads:
        t.start()
    start.set()
    for t in threads:
        t.join()

    assert errors == []
    assert len(results) == 20
    # No thread must observe a torn/partial access_grant.
    assert all(r == results[0] for r in results)


def test_access_grant_refreshed_is_timezone_aware(monkeypatch):
    monkeypatch.setattr(
        PasswordGrantAuthorizer,
        "get_access_grant",
        staticmethod(
            lambda token_url, grant_request: {
                "access_token": "tok",
                "expires_in": 1200,
            }
        ),
    )
    auth = PasswordGrantAuthorizer(
        "https://ss.example.com", "user", "pass", server_type="secret_server"
    )
    auth.get_access_token()

    assert auth.access_grant_refreshed.tzinfo is not None
    # Comparable against an aware "now" without raising TypeError.
    assert auth.access_grant_refreshed <= datetime.now(timezone.utc)


# ---------------------------------------------------------------------------
# 4.3: mutable default arguments don't leak state
# ---------------------------------------------------------------------------


def test_headers_default_not_shared_between_calls():
    auth = AccessTokenAuthorizer(
        "tok", "https://ss.example.com", server_type="secret_server"
    )
    first = auth.headers()
    first["Poisoned"] = "yes"

    second = auth.headers()
    assert "Poisoned" not in second


# ---------------------------------------------------------------------------
# 4.4: get_folder_json tolerates the None/True default combination
# ---------------------------------------------------------------------------


def test_get_folder_json_bare_call_does_not_raise(monkeypatch):
    calls = []

    def fake_get(url, *args, **kwargs):
        calls.append(kwargs.get("params"))
        return FakeResponse(json_data={"id": 1})

    monkeypatch.setattr("delinea.secrets.server.requests.get", fake_get)

    authorizer = AccessTokenAuthorizer(
        "tok", "https://ss.example.com", server_type="secret_server"
    )
    server = SecretServer("https://ss.example.com", authorizer)

    # No query_params, default get_all_children=True: must not raise TypeError.
    result = server.get_folder_json(1)
    assert result == '{"id": 1}'
    assert calls[-1] == {"getAllChildren": "true"}


# ---------------------------------------------------------------------------
# 4.5: file-attachment itemValue is text, not a Response object
# ---------------------------------------------------------------------------


def test_file_attachment_item_value_is_text(monkeypatch):
    def fake_get(url, *args, **kwargs):
        if url.endswith("/fields/file-slug"):
            return FakeResponse(text="file-bytes-as-text")
        return FakeResponse(
            json_data={
                "items": [
                    {
                        "fileAttachmentId": 42,
                        "slug": "file-slug",
                        "itemValue": None,
                    }
                ]
            }
        )

    monkeypatch.setattr("delinea.secrets.server.requests.get", fake_get)

    authorizer = AccessTokenAuthorizer(
        "tok", "https://ss.example.com", server_type="secret_server"
    )
    server = SecretServer("https://ss.example.com", authorizer)

    secret = server.get_secret(1, fetch_file_attachments=True)
    item_value = secret["items"][0]["itemValue"]
    assert item_value == "file-bytes-as-text"
    assert isinstance(item_value, str)


# ---------------------------------------------------------------------------
# 4.6: non-numeric search-total body is rejected, not silently propagated
# ---------------------------------------------------------------------------


def test_non_numeric_search_total_raises(monkeypatch):
    def fake_get(url, *args, **kwargs):
        if url.endswith("/secrets/search-total"):
            return FakeResponse(text="not-a-number")
        return FakeResponse(json_data={"records": []})

    monkeypatch.setattr("delinea.secrets.server.requests.get", fake_get)

    authorizer = AccessTokenAuthorizer(
        "tok", "https://ss.example.com", server_type="secret_server"
    )
    server = SecretServer("https://ss.example.com", authorizer)

    with pytest.raises(SecretServerError, match="non-numeric"):
        server.get_secret_ids_by_folderid(1)


def test_numeric_search_total_still_works(monkeypatch):
    def fake_get(url, *args, **kwargs):
        if url.endswith("/secrets/search-total"):
            return FakeResponse(text="2")
        return FakeResponse(json_data={"records": [{"id": 1}, {"id": 2}]})

    monkeypatch.setattr("delinea.secrets.server.requests.get", fake_get)

    authorizer = AccessTokenAuthorizer(
        "tok", "https://ss.example.com", server_type="secret_server"
    )
    server = SecretServer("https://ss.example.com", authorizer)

    assert server.get_secret_ids_by_folderid(1) == [1, 2]
