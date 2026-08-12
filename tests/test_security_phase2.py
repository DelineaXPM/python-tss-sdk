"""Offline unit tests for the Phase 2 security-review fixes (see DevPlan.md).

Covers:
- SDK-2: a UserWarning is emitted when base_url is not https.
- SDK-4: health-check validation requires a 2xx status and an exact
  "healthy" match, no longer a "healthy" substring match with no status
  check.
- SDK-6: response bodies are truncated/omitted from exception messages.
- SDK-7: the platform vault-broker redirect URL must be a valid https URL.

Fully OFFLINE, in the style of ``tests/test_server_detection_cache.py``: the
network is mocked by patching ``delinea.secrets.server.requests``.
"""

import json

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
    """Same isolation as tests/test_server_detection_cache.py: the detection
    cache is process-global."""
    Authorizer._clear_server_type_cache()
    yield
    Authorizer._clear_server_type_cache()


# ---------------------------------------------------------------------------
# SDK-2: warn on non-https base_url
# ---------------------------------------------------------------------------


def test_access_token_authorizer_warns_on_http():
    with pytest.warns(UserWarning, match="does not use https"):
        AccessTokenAuthorizer("tok", "http://ss.example.com", server_type="platform")


def test_access_token_authorizer_no_warning_on_https(recwarn):
    AccessTokenAuthorizer("tok", "https://ss.example.com", server_type="platform")
    assert len(recwarn) == 0


def test_password_grant_authorizer_warns_on_http():
    with pytest.warns(UserWarning, match="does not use https"):
        PasswordGrantAuthorizer(
            "http://ss.example.com", "user", "pass", server_type="platform"
        )


def test_secret_server_warns_on_http():
    authorizer = AccessTokenAuthorizer(
        "tok", "https://ss.example.com", server_type="platform"
    )
    with pytest.warns(UserWarning, match="does not use https"):
        SecretServer("http://ss.example.com", authorizer)


def test_secret_server_no_warning_on_https(recwarn):
    authorizer = AccessTokenAuthorizer(
        "tok", "https://ss.example.com", server_type="platform"
    )
    recwarn.clear()
    SecretServer("https://ss.example.com", authorizer)
    assert len(recwarn) == 0


# ---------------------------------------------------------------------------
# SDK-4: health-check validation tightened
# ---------------------------------------------------------------------------


def _probe(monkeypatch, response):
    """Drive ``_validate_health_endpoint`` on a real authorizer instance
    (constructed via an explicit server_type override so no probe fires
    during construction itself)."""
    monkeypatch.setattr("delinea.secrets.server.requests.get", lambda *a, **k: response)
    authorizer = AccessTokenAuthorizer(
        "tok", "https://x.example.com", server_type="platform"
    )
    return authorizer._validate_health_endpoint("https://x.example.com/health")


def test_health_check_rejects_unhealthy_substring(monkeypatch):
    """A body containing "Unhealthy" must NOT be treated as healthy (the old
    substring check ``b"healthy" in body`` incorrectly matched it)."""
    response = FakeResponse(status_code=200, text="Unhealthy")
    assert _probe(monkeypatch, response) is False


def test_health_check_rejects_non_2xx_even_with_healthy_body(monkeypatch):
    response = FakeResponse(status_code=500, text="Healthy")
    assert _probe(monkeypatch, response) is False


def test_health_check_rejects_json_healthy_false(monkeypatch):
    response = FakeResponse(status_code=200, json_data={"Healthy": False})
    assert _probe(monkeypatch, response) is False


def test_health_check_accepts_plain_healthy_text(monkeypatch):
    response = FakeResponse(status_code=200, text="Healthy")
    assert _probe(monkeypatch, response) is True


def test_health_check_accepts_json_healthy_true(monkeypatch):
    response = FakeResponse(status_code=200, json_data={"Healthy": True})
    assert _probe(monkeypatch, response) is True


def test_health_check_probe_exception_is_unhealthy(monkeypatch):
    def raise_get(*a, **k):
        raise ConnectionError("boom")

    # server_type="platform" skips probing during construction; only the
    # explicit _validate_health_endpoint call below is under test.
    authorizer = AccessTokenAuthorizer(
        "tok", "https://x.example.com", server_type="platform"
    )
    monkeypatch.setattr("delinea.secrets.server.requests.get", raise_get)
    assert authorizer._validate_health_endpoint("https://x.example.com/health") is False


# ---------------------------------------------------------------------------
# SDK-6: response bodies sanitized out of exception messages
# ---------------------------------------------------------------------------


def _platform_server(monkeypatch, vault_url="https://vault.example.com"):
    """Build a SecretServer wired to a platform authorizer, with
    requests.get mocked to serve a vault-broker response."""
    authorizer = AccessTokenAuthorizer(
        "tok", "https://platform.example.com", server_type="platform"
    )
    server = SecretServer("https://platform.example.com", authorizer)

    def fake_get(url, *args, **kwargs):
        if "vaultbroker" in url:
            return FakeResponse(
                json_data={
                    "vaults": [
                        {
                            "isDefault": True,
                            "isActive": True,
                            "connection": {"url": vault_url},
                        }
                    ]
                }
            )
        return FakeResponse(json_data={})

    monkeypatch.setattr("delinea.secrets.server.requests.get", fake_get)
    return server


def test_vault_fetch_failure_truncates_body(monkeypatch):
    authorizer = AccessTokenAuthorizer(
        "tok", "https://platform.example.com", server_type="platform"
    )
    server = SecretServer("https://platform.example.com", authorizer)
    huge_body = "x" * 5000

    monkeypatch.setattr(
        "delinea.secrets.server.requests.get",
        lambda *a, **k: FakeResponse(status_code=500, text=huge_body),
    )

    with pytest.raises(SecretServerError) as excinfo:
        server.ensure_vault_url()
    assert "...[truncated]" in str(excinfo.value)
    assert len(str(excinfo.value)) < len(huge_body)


def test_get_secret_json_decode_failure_has_no_body(monkeypatch):
    authorizer = AccessTokenAuthorizer(
        "tok", "https://ss.example.com", server_type="secret_server"
    )
    server = SecretServer("https://ss.example.com", authorizer)
    secret_marker = "TOP-SECRET-VALUE"

    monkeypatch.setattr(
        "delinea.secrets.server.requests.get",
        lambda *a, **k: FakeResponse(status_code=200, text=secret_marker),
    )

    with pytest.raises(SecretServerError) as excinfo:
        server.get_secret(1, fetch_file_attachments=False)
    assert secret_marker not in str(excinfo.value)


def test_get_folder_json_decode_failure_is_truncated_not_omitted(monkeypatch):
    authorizer = AccessTokenAuthorizer(
        "tok", "https://ss.example.com", server_type="secret_server"
    )
    server = SecretServer("https://ss.example.com", authorizer)

    monkeypatch.setattr(
        "delinea.secrets.server.requests.get",
        lambda *a, **k: FakeResponse(status_code=200, text="not json"),
    )

    with pytest.raises(SecretServerError) as excinfo:
        server.get_folder(1, query_params={})
    assert "not json" in str(excinfo.value)


# ---------------------------------------------------------------------------
# SDK-7: vault-broker redirect URL must be a valid https URL
# ---------------------------------------------------------------------------


def test_vault_url_rejects_http(monkeypatch):
    server = _platform_server(monkeypatch, vault_url="http://evil.example.com")
    with pytest.raises(SecretServerError, match="https"):
        server.ensure_vault_url()


def test_vault_url_accepts_https(monkeypatch):
    server = _platform_server(monkeypatch, vault_url="https://vault.example.com")
    server.ensure_vault_url()
    assert server.base_url == "https://vault.example.com"
