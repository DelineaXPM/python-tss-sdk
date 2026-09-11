"""Offline unit tests for the Phase 1 security-review fixes (see PR #98).

Covers SDK-1 (timeouts on every call), SDK-3 (refresh before expiry) and SDK-9
(``.response`` populated). Offline: ``requests`` is patched in the SDK module.
"""

from datetime import datetime, timedelta, timezone

import pytest

from urllib.parse import urlsplit

from delinea.secrets.server import (
    _MAX_GRANT_LIFETIME_SECONDS,
    DEFAULT_REQUEST_TIMEOUT,
    AccessTokenAuthorizer,
    PasswordGrantAuthorizer,
    SecretServer,
    SecretServerClientError,
    SecretServerError,
    SecretServerV0,
    _with_query_flag,
)
from fakes import (
    HTTP_GET,
    HTTP_POST,
    FakeResponse,
    fake_token_post,
    health_response,
    make_grant_authorizer,
    make_server,
    vault_broker_response,
)

# Shared fixtures from tests/conftest.py: fail loudly on an unmocked HTTP
# call, and isolate the process-global server-detection cache.
pytestmark = pytest.mark.usefixtures("no_network", "clear_detection_cache")


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
        if url.endswith("/api/v1/healthcheck"):
            return health_response(False)
        if url.endswith("/health"):
            return health_response(True)
        if url.endswith("/vaultbroker/api/vaults"):
            return vault_broker_response()
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
        return fake_token_post(url, *args, **kwargs)

    monkeypatch.setattr(HTTP_GET, fake_get)
    monkeypatch.setattr(HTTP_POST, fake_post)
    return calls


def _server(base_url="https://ss.example.com"):
    return make_server(base_url, "secret_server")


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
    # ``timeout=None`` is the exact hang SDK-1 fixed, so "present" is not
    # enough: every call must carry the configured value.
    missing = [
        (method, url)
        for method, url, kwargs in http_spy
        if kwargs.get("timeout") != DEFAULT_REQUEST_TIMEOUT
    ]
    assert missing == [], f"HTTP calls issued without the timeout: {missing}"


def test_every_http_call_site_passes_the_timeout(http_spy):
    """One lazily detected Platform flow visits all four ``requests`` call
    sites: both health probes, the token POST, the vault lookup and an API GET.
    The test above pins an explicit ``server_type``, so it reaches only two.
    """
    authorizer = PasswordGrantAuthorizer("https://platform.example.com", "u", "p")
    server = SecretServer("https://platform.example.com", authorizer)
    server.get_secret_json(1)

    paths = {(method, urlsplit(url).path) for method, url, _ in http_spy}
    assert paths == {
        ("GET", "/api/v1/healthcheck"),
        ("GET", "/health"),
        ("POST", PasswordGrantAuthorizer.PLATFORM_TOKEN_PATH_URI),
        ("GET", "/vaultbroker/api/vaults"),
        ("GET", "/api/v1/secrets/1"),
    }
    assert server.base_url == "https://vault.example.com"
    wrong = [
        (method, url, kwargs.get("timeout"))
        for method, url, kwargs in http_spy
        if kwargs.get("timeout") != DEFAULT_REQUEST_TIMEOUT
    ]
    assert wrong == []


def test_token_grant_passes_a_timeout(http_spy):
    """The OAuth2 token POST must also carry a timeout (SDK-1)."""
    grant = make_grant_authorizer()
    grant.get_access_token()

    posts = [c for c in http_spy if c[0] == "POST"]
    assert len(posts) == 1
    assert posts[0][2].get("timeout") == DEFAULT_REQUEST_TIMEOUT


# ---------------------------------------------------------------------------
# SDK-3: refresh drift is subtracted (refresh happens BEFORE expiry)
# ---------------------------------------------------------------------------


def _grant_authorizer_with_token(refreshed_seconds_ago, expires_in=1200):
    auth = make_grant_authorizer()
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


# ---------------------------------------------------------------------------
# Review step 1: short-lived grants are not refreshed on every call
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("expires_in", [300, 60])
def test_short_lived_grant_is_reused_when_fresh(expires_in):
    """``expires_in <= drift`` used to yield a zero/negative validity window,
    forcing a token POST on every ``get_access_token()`` call."""
    auth = _grant_authorizer_with_token(refreshed_seconds_ago=0, expires_in=expires_in)
    assert auth.get_access_token() == "old"


def test_short_lived_grant_refreshes_after_half_lifetime():
    """A short-lived grant is reused for half its lifetime, then refreshed."""
    auth = _grant_authorizer_with_token(refreshed_seconds_ago=31, expires_in=60)
    assert auth.get_access_token() == "new"


def test_long_lived_grant_still_uses_full_drift():
    validity = PasswordGrantAuthorizer._grant_validity_seconds(
        {"expires_in": 1200}, 300
    )
    assert validity == 900


# ---------------------------------------------------------------------------
# Review step 5: expires_in defaults, rejections and warnings
# ---------------------------------------------------------------------------


def _token_endpoint(monkeypatch, grant):
    response = FakeResponse(status_code=200, json_data=grant)
    monkeypatch.setattr(HTTP_POST, lambda *a, **k: response)
    return response


def test_grant_without_expires_in_defaults_to_one_hour(monkeypatch, caplog):
    """RFC 6749 makes ``expires_in`` RECOMMENDED, not required. A grant
    without it is assumed to last an hour (and says so at DEBUG) rather
    than being re-requested on every API call."""
    _token_endpoint(monkeypatch, {"access_token": "tok"})
    with caplog.at_level("DEBUG", logger="delinea.secrets.server"):
        grant = PasswordGrantAuthorizer.get_access_grant(
            "https://ss.example.com/oauth2/token", {}
        )
    assert grant == {"access_token": "tok", "expires_in": 3600}
    assert any("no expires_in" in record.getMessage() for record in caplog.records)
    # And the default flows through to the refresh arithmetic.
    assert PasswordGrantAuthorizer._grant_validity_seconds(grant, 300) == 3300


def test_grant_with_null_expires_in_is_treated_as_missing(monkeypatch):
    _token_endpoint(monkeypatch, {"access_token": "tok", "expires_in": None})
    grant = PasswordGrantAuthorizer.get_access_grant(
        "https://ss.example.com/oauth2/token", {}
    )
    assert grant["expires_in"] == 3600


def test_directly_assigned_grant_without_expires_in_uses_default():
    """The same default applies to a grant assigned without going through
    ``get_access_grant`` (no debug log on this path: it runs per call)."""
    auth = _grant_authorizer_with_token(refreshed_seconds_ago=0)
    auth.access_grant = {"access_token": "old"}
    assert auth.get_access_token() == "old"
    auth.access_grant_refreshed -= timedelta(seconds=3301)
    assert auth.get_access_token() == "new"


@pytest.mark.parametrize(
    "bad",
    [
        # Not a number at all.
        "soon",
        "",
        True,
        False,
        {"seconds": 60},
        [3600],
        # Numeric but non-finite.
        "NaN",
        "Infinity",
    ],
)
def test_non_numeric_expires_in_is_rejected_at_token_endpoint(monkeypatch, bad):
    """A grant whose ``expires_in`` cannot be read as a finite number is
    malformed. It is rejected once, here, with the response attached,
    instead of being stored and wedging every later call."""
    response = _token_endpoint(monkeypatch, {"access_token": "tok", "expires_in": bad})
    with pytest.raises(SecretServerError) as excinfo:
        PasswordGrantAuthorizer.get_access_grant(
            "https://ss.example.com/oauth2/token", {}
        )
    assert "non-numeric expires_in" in excinfo.value.message
    assert excinfo.value.response is response


@pytest.mark.parametrize("lifetime", [0, -1, "0", 1e-9])
def test_non_positive_expires_in_is_honoured_and_warned(monkeypatch, caplog, lifetime):
    """``expires_in: 0`` is a token the server issued with no reuse window.
    Refusing it would be an outage and assuming an hour would hand the caller
    an expired token, so it is honoured and warned once per authorizer.
    """
    posts = []

    def counting_post(url, *a, **k):
        posts.append(url)
        return FakeResponse(
            json_data={"access_token": f"tok-{len(posts)}", "expires_in": lifetime}
        )

    monkeypatch.setattr(HTTP_POST, counting_post)
    auth = make_grant_authorizer()
    with caplog.at_level("WARNING", logger="delinea.secrets.server"):
        tokens = [auth.get_access_token() for _ in range(3)]
    assert tokens == ["tok-1", "tok-2", "tok-3"]  # every call works...
    assert len(posts) == 3  # ...at the cost the server asked for
    warnings_ = [r for r in caplog.records if "re-requested on every" in r.getMessage()]
    assert len(warnings_) == 1 and warnings_[0].levelname == "WARNING"
    # A second authorizer against the same server warns on its own.
    other = PasswordGrantAuthorizer(
        "https://ss.example.com", "user2", "pass", server_type="secret_server"
    )
    with caplog.at_level("WARNING", logger="delinea.secrets.server"):
        other.get_access_token()
    assert (
        len([r for r in caplog.records if "re-requested on every" in r.getMessage()])
        == 2
    )


def test_numeric_string_expires_in_is_accepted(monkeypatch):
    """Some OAuth2 servers serialize the field as a string."""
    _token_endpoint(monkeypatch, {"access_token": "tok", "expires_in": "1200"})
    grant = PasswordGrantAuthorizer.get_access_grant(
        "https://ss.example.com/oauth2/token", {}
    )
    assert grant["expires_in"] == "1200"
    assert PasswordGrantAuthorizer._grant_validity_seconds(grant, 300) == 900


def test_non_numeric_expires_in_error_detail_is_capped(monkeypatch):
    _token_endpoint(monkeypatch, {"access_token": "tok", "expires_in": "x" * 5000})
    with pytest.raises(SecretServerError) as excinfo:
        PasswordGrantAuthorizer.get_access_grant(
            "https://ss.example.com/oauth2/token", {}
        )
    assert len(excinfo.value.message) < 400


# ---------------------------------------------------------------------------
# Review step 2: SecretServerError contract is uniform on every raise path
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("body", ["null", "5", '"Access denied"', '["error"]', "true"])
def test_process_4xx_non_object_json_raises_client_error(body):
    """A 4xx body that is valid JSON but not an object must not escape as
    ``TypeError``; it is a client error with the status fallback message."""
    response = FakeResponse(status_code=403, text=body)
    with pytest.raises(SecretServerClientError) as excinfo:
        SecretServer.process(response)
    assert excinfo.value.response is response
    assert excinfo.value.message == "HTTP 403"


def test_process_4xx_non_string_message_key_falls_back():
    response = FakeResponse(status_code=400, json_data={"message": {"code": 1}})
    with pytest.raises(SecretServerClientError) as excinfo:
        SecretServer.process(response)
    assert excinfo.value.message == "HTTP 400"


def test_process_5xx_populates_response_and_message():
    from delinea.secrets.server import SecretServerServiceError

    response = FakeResponse(status_code=500, text="<html>" + "x" * 500)
    with pytest.raises(SecretServerServiceError) as excinfo:
        SecretServer.process(response)
    err = excinfo.value
    assert err.response is response
    assert err.message.startswith("HTTP 500: <html>")
    assert err.message.endswith("...[truncated]")
    assert len(err.message) < 300
    assert str(err) == err.message
    assert "<Response" not in str(err)


def test_token_grant_non_json_body_has_response(monkeypatch):
    response = FakeResponse(status_code=200, text="<html>login</html>")
    monkeypatch.setattr(HTTP_POST, lambda *a, **k: response)
    with pytest.raises(SecretServerError) as excinfo:
        PasswordGrantAuthorizer.get_access_grant(
            "https://ss.example.com/oauth2/token", {}
        )
    err = excinfo.value
    assert err.response is response
    assert "HTTP 200" in err.message
    assert "<html>login</html>" in err.message
    assert "<Response" not in str(err)


def test_process_4xx_non_json_body_keeps_status():
    """A 4xx whose body is not JSON keeps its status code and a body hint.

    The JSON parser's own complaint gave messages like "Expecting value",
    dropping the status and any clue; the example only prints ``.message``.
    """
    response = FakeResponse(status_code=401, text="<html>Unauthorized</html>")
    with pytest.raises(SecretServerClientError) as excinfo:
        SecretServer.process(response)
    err = excinfo.value
    assert err.message.startswith("HTTP 401")
    assert "Unauthorized" in err.message
    assert err.response is response
    assert "Expecting value" not in err.message


@pytest.mark.parametrize(
    "body,expected_detail",
    [
        (
            {"error": "invalid_grant", "error_description": "bad password"},
            "bad password",
        ),
        ({"error": "invalid_client"}, "invalid_client"),
        ({"token_type": "bearer"}, "HTTP 200"),
        ([], "HTTP 200"),
        ("ok", "HTTP 200"),
    ],
)
def test_token_grant_without_access_token_raises(monkeypatch, body, expected_detail):
    """A 200 whose JSON is an OAuth2 error body, or not an object, must raise a
    SecretServerError now -- not be stored as the grant and surface later as a
    KeyError from get_access_token()."""
    response = FakeResponse(status_code=200, json_data=body)
    monkeypatch.setattr(HTTP_POST, lambda *a, **k: response)

    with pytest.raises(SecretServerError) as excinfo:
        PasswordGrantAuthorizer.get_access_grant(
            "https://ss.example.com/oauth2/token", {}
        )
    err = excinfo.value
    assert err.response is response
    assert err.message.startswith("Token endpoint did not return an access grant")
    assert expected_detail in err.message


def test_token_grant_error_body_never_reaches_get_access_token(monkeypatch):
    response = FakeResponse(status_code=200, json_data={"error": "invalid_grant"})
    monkeypatch.setattr(HTTP_POST, lambda *a, **k: response)
    grant = make_grant_authorizer()
    with pytest.raises(SecretServerError):
        grant.get_access_token()
    assert not hasattr(grant, "access_grant")


def test_subclass_token_path_override_is_honoured(monkeypatch):
    """``TOKEN_PATH_URI`` / ``PLATFORM_TOKEN_PATH_URI`` are the pre-existing
    extension point; a class-level snapshot silently ignored a subclass."""
    posted = []

    def fake_post(url, *args, **kwargs):
        posted.append(url)
        return fake_token_post(url, *args, **kwargs)

    monkeypatch.setattr(HTTP_POST, fake_post)

    class CustomPath(PasswordGrantAuthorizer):
        TOKEN_PATH_URI = "/SecretServer/oauth2/token"

    CustomPath(
        "https://ss.example.com", "u", "p", server_type="secret_server"
    ).get_access_token()
    assert posted == ["https://ss.example.com/SecretServer/oauth2/token"]


@pytest.mark.parametrize("bad", [float("nan"), float("inf"), "NaN", "Infinity"])
def test_non_finite_expires_in_does_not_wedge_refresh(bad):
    """``get_access_grant`` rejects these, so they only reach the refresh
    arithmetic via a directly assigned grant. Even then they must mean
    "refresh", not a ValueError/OverflowError on every later call."""
    assert (
        PasswordGrantAuthorizer._grant_validity_seconds({"expires_in": bad}, 300) == 0
    )
    auth = _grant_authorizer_with_token(refreshed_seconds_ago=0)
    auth.access_grant = {"access_token": "old", "expires_in": bad}
    assert auth.get_access_token() == "new"


def test_token_grant_error_detail_is_capped_once(monkeypatch):
    response = FakeResponse(
        status_code=200, json_data={"error_description": "d" * 1000}
    )
    monkeypatch.setattr(HTTP_POST, lambda *a, **k: response)
    with pytest.raises(SecretServerError) as excinfo:
        PasswordGrantAuthorizer.get_access_grant(
            "https://ss.example.com/oauth2/token", {}
        )
    message = excinfo.value.message
    assert message.count("...[truncated]") == 1
    assert "d" * 200 in message


def test_token_grant_body_excerpt_is_not_truncated_twice(monkeypatch):
    """The fallback detail is already capped by ``_describe_response``; running
    it through the excerpt helper again used to chop ~10 chars off the body."""
    response = FakeResponse(status_code=200, json_data=["y" * 1000])
    monkeypatch.setattr(HTTP_POST, lambda *a, **k: response)
    with pytest.raises(SecretServerError) as excinfo:
        PasswordGrantAuthorizer.get_access_grant(
            "https://ss.example.com/oauth2/token", {}
        )
    message = excinfo.value.message
    assert "HTTP 200: " + '["' + "y" * 198 in message
    assert message.endswith("...[truncated]")


# ---------------------------------------------------------------------------
# Round 9: grant lifetime edge cases, params forms, constructor arguments
# ---------------------------------------------------------------------------


def test_naive_refresh_timestamp_is_treated_as_stale():
    """A naive ``access_grant_refreshed`` (the pre-2.1 convention, or one set
    by hand) must mean "refresh", not a TypeError against the aware clock."""
    auth = make_grant_authorizer()
    auth.access_grant = {"access_token": "old", "expires_in": 1200}
    auth.access_grant_refreshed = datetime.now()  # naive on purpose
    auth.get_access_grant = lambda *a, **k: {"access_token": "new", "expires_in": 1200}
    assert auth.get_access_token() == "new"
    assert auth.access_grant_refreshed.tzinfo is not None


def test_huge_expires_in_does_not_overflow_the_refresh_arithmetic(monkeypatch):
    """A lifetime of 1e12 seconds is finite, so the validator admits it; the
    validity window is capped so ``now + timedelta`` cannot raise OverflowError."""
    posts = []

    def counting_post(url, *a, **k):
        posts.append(url)
        return FakeResponse(json_data={"access_token": "tok", "expires_in": 1e12})

    monkeypatch.setattr(HTTP_POST, counting_post)
    auth = make_grant_authorizer()
    assert [auth.get_access_token() for _ in range(3)] == ["tok"] * 3
    assert len(posts) == 1
    validity = PasswordGrantAuthorizer._grant_validity_seconds(
        {"expires_in": 1e12}, 300
    )
    assert validity <= _MAX_GRANT_LIFETIME_SECONDS


def test_boolean_expires_in_gives_no_reuse_window():
    """``True`` is not a one-second lifetime; both parsers now agree."""
    assert (
        PasswordGrantAuthorizer._grant_validity_seconds({"expires_in": True}, 300) == 0
    )


def test_query_flag_keeps_repeated_keys_in_non_mapping_forms():
    """A list of pairs or a query string keeps its repeated keys; only the flag
    is collapsed to a single winning value, at the end."""
    pairs = [("filter.x", "a"), ("filter.x", "b"), ("getAllChildren", "false")]
    assert _with_query_flag(pairs, "getAllChildren", "true") == [
        ("filter.x", "a"),
        ("filter.x", "b"),
        ("getAllChildren", "true"),
    ]
    assert _with_query_flag("a=1&a=2", "getAllChildren", "true") == [
        ("a", "1"),
        ("a", "2"),
        ("getAllChildren", "true"),
    ]
    assert _with_query_flag({"take": 1}, "getAllChildren", "true") == {
        "take": 1,
        "getAllChildren": "true",
    }
    assert _with_query_flag(None, "getAllChildren", "true") == {
        "getAllChildren": "true"
    }


def test_malformed_base_url_raises_a_clear_valueerror():
    with pytest.raises(ValueError, match="is not a valid URL"):
        AccessTokenAuthorizer(
            "tok", "https://[::1/SecretServer", server_type="platform"
        )


def test_secret_server_v0_forwards_server_type():
    """The legacy wrapper can now skip detection too; ``no_network`` would
    fail at teardown if a probe had been issued here."""
    server = SecretServerV0(
        "https://legacy.example.com", "u", "p", server_type="platform"
    )
    assert server.authorizer._server_type == "platform"


def _json_endpoint_calls():
    return [
        ("get_secret", lambda s: s.get_secret(1), "Secret endpoint", True),
        ("get_folder", lambda s: s.get_folder(1), "Folder endpoint", False),
        (
            "get_secret_ids_by_folderid",
            lambda s: s.get_secret_ids_by_folderid(2),
            "Secrets search",
            False,
        ),
        (
            "get_child_folder_ids_by_folderid",
            lambda s: s.get_child_folder_ids_by_folderid(2),
            "Folder lookup",
            False,
        ),
    ]


@pytest.mark.parametrize("name, call, what, redacted", _json_endpoint_calls())
@pytest.mark.parametrize(
    "body",
    [FakeResponse(text="<html>not json</html>"), FakeResponse(json_data=[1, 2])],
    ids=["not-json", "json-list"],
)
def test_json_endpoints_reject_non_object_bodies(
    monkeypatch, name, call, what, redacted, body
):
    """Every JSON read goes through one helper: a body that is not a JSON object
    is a SecretServerError with the response attached, never a TypeError."""

    def fake_get(url, *a, **k):
        if url.endswith("/secrets/search-total"):
            return FakeResponse(text="3")
        return body

    monkeypatch.setattr(HTTP_GET, fake_get)
    server = make_server("https://ss.example.com", "secret_server")
    with pytest.raises(SecretServerError) as excinfo:
        call(server)
    assert excinfo.value.response is body
    assert excinfo.value.message.startswith(f"{what} did not return")
    assert ("<html>" in excinfo.value.message) is (
        not redacted and body.text.startswith("<html>")
    )


@pytest.mark.parametrize(
    "lifetime, warned", [(2, False), (1, False), (0.5, True), (0, True), (-1, True)]
)
def test_short_lifetime_warning_only_without_a_reuse_window(
    monkeypatch, caplog, lifetime, warned
):
    """The warning describes a token re-requested on every call, so it must
    fire on the lifetime the server sent, not on the drift-adjusted window."""
    monkeypatch.setattr(
        HTTP_POST,
        lambda *a, **k: FakeResponse(
            json_data={"access_token": "tok", "expires_in": lifetime}
        ),
    )
    auth = make_grant_authorizer()
    with caplog.at_level("WARNING", logger="delinea.secrets.server"):
        auth.get_access_token()
    fired = any("re-requested on every" in r.getMessage() for r in caplog.records)
    assert fired is warned


def test_folder_count_errors_carry_the_response(monkeypatch):
    """Every error on the folder paths attaches the response it describes."""
    bodies = {
        "total": FakeResponse(text="abc"),
        "lookup": FakeResponse(json_data={"total": True}),
    }

    def fake_get(url, *a, **k):
        return (
            bodies["total"]
            if url.endswith("/secrets/search-total")
            else bodies["lookup"]
        )

    monkeypatch.setattr(HTTP_GET, fake_get)
    server = make_server("https://ss.example.com", "secret_server")
    with pytest.raises(SecretServerError) as count_error:
        server.get_secret_ids_by_folderid(2)
    assert count_error.value.response is bodies["total"]
    with pytest.raises(SecretServerError) as total_error:
        server.get_child_folder_ids_by_folderid(2)
    assert total_error.value.response is bodies["lookup"]


def test_non_datetime_refresh_timestamp_reads_as_stale():
    auth = make_grant_authorizer()
    auth.access_grant = {"access_token": "old", "expires_in": 1200}
    auth.access_grant_refreshed = "yesterday"
    auth.get_access_grant = lambda *a, **k: {"access_token": "new", "expires_in": 1200}
    assert auth.get_access_token() == "new"
