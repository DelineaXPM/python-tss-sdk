"""Offline unit tests for the Phase 2 security-review fixes (see PR #98).

Covers SDK-2 (a warning on plaintext http), SDK-4 (health checks need a 2xx and
an exact match), SDK-6 (bodies capped in messages), SDK-7 (https vault URLs).
"""

import pytest

from delinea.secrets.server import (
    AccessTokenAuthorizer,
    PasswordGrantAuthorizer,
    SecretServer,
    SecretServerError,
)
from fakes import (
    HTTP_GET,
    JSON_NULL,
    BytesOnlyResponse,
    FakeResponse,
    HostileBody,
    make_server,
    vault_broker_payload,
    vault_broker_response,
)

# Shared fixtures from tests/conftest.py: fail loudly on an unmocked HTTP
# call, and isolate the process-global server-detection cache.
pytestmark = pytest.mark.usefixtures("no_network", "clear_detection_cache")


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
    monkeypatch.setattr(HTTP_GET, lambda *a, **k: response)
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
    monkeypatch.setattr(HTTP_GET, raise_get)
    assert authorizer._validate_health_endpoint("https://x.example.com/health") is False


# ---------------------------------------------------------------------------
# SDK-6: response bodies sanitized out of exception messages
# ---------------------------------------------------------------------------


def _platform_server(monkeypatch, vault_url="https://vault.example.com"):
    """Build a SecretServer wired to a platform authorizer, with
    requests.get mocked to serve a vault-broker response."""
    server = make_server("https://platform.example.com", "platform")

    def fake_get(url, *args, **kwargs):
        if "vaultbroker" in url:
            return vault_broker_response(vault_url)
        return FakeResponse(json_data={})

    monkeypatch.setattr(HTTP_GET, fake_get)
    return server


def test_vault_fetch_failure_truncates_body(monkeypatch):
    server = make_server("https://platform.example.com", "platform")
    huge_body = "x" * 5000

    monkeypatch.setattr(
        HTTP_GET,
        lambda *a, **k: FakeResponse(status_code=500, text=huge_body),
    )

    with pytest.raises(SecretServerError) as excinfo:
        server.ensure_vault_url()
    assert "...[truncated]" in str(excinfo.value)
    assert len(str(excinfo.value)) < len(huge_body)


def test_get_secret_json_decode_failure_has_no_body(monkeypatch):
    server = make_server("https://ss.example.com", "secret_server")
    secret_marker = "TOP-SECRET-VALUE"

    monkeypatch.setattr(
        HTTP_GET,
        lambda *a, **k: FakeResponse(status_code=200, text=secret_marker),
    )

    with pytest.raises(SecretServerError) as excinfo:
        server.get_secret(1, fetch_file_attachments=False)
    assert secret_marker not in str(excinfo.value)


def test_get_folder_json_decode_failure_is_truncated_not_omitted(monkeypatch):
    server = make_server("https://ss.example.com", "secret_server")

    monkeypatch.setattr(
        HTTP_GET,
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


# ---------------------------------------------------------------------------
# Health-check body forms: exactly the two shapes the products emit
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "json_data",
    [
        # Looser matches, briefly accepted during review and then reverted:
        # neither product emits them, and a string ``"true"`` or a bare
        # ``"Healthy"`` is what an error page or captive portal may produce.
        "Healthy",
        {"Healthy": "true"},
        {"Healthy": "false"},
        {"Healthy": 1},
        {"Healthy": None},
        # Other JSON shapes that are not the Secret Server object.
        ["Healthy"],
        1,
        0,
        {"healthy": True},
    ],
)
def test_health_check_rejects_other_json_shapes(monkeypatch, json_data):
    response = FakeResponse(status_code=200, json_data=json_data)
    assert _probe(monkeypatch, response) is False


def test_health_check_rejects_healthy_with_extra_text(monkeypatch):
    response = FakeResponse(status_code=200, text="Status: Healthy")
    assert _probe(monkeypatch, response) is False


# ---------------------------------------------------------------------------
# Review step 5: the insecure-URL warning is attributed to the caller
# ---------------------------------------------------------------------------


def _warning_basenames(record):
    import os

    return {os.path.basename(w.filename) for w in record}


def _this_file():
    import os

    return os.path.basename(__file__)


def test_direct_construction_warning_points_at_caller():
    with pytest.warns(UserWarning, match="does not use https") as record:
        AccessTokenAuthorizer(
            "tok", "http://direct.example.com", server_type="platform"
        )
    assert _warning_basenames(record) == {_this_file()}


def test_legacy_wrapper_warning_points_at_caller():
    """``SecretServerV0`` adds a frame between the caller and the warning; a
    fixed ``stacklevel`` reported a line inside ``server.py`` instead."""
    from delinea.secrets.server import SecretServerV0

    with pytest.warns(UserWarning, match="does not use https") as record:
        SecretServerV0("http://legacy.example.com", "user", "pass")

    assert _warning_basenames(record) == {_this_file()}
    assert "server.py" not in _warning_basenames(record)


def test_cloud_wrapper_warning_points_at_caller():
    from delinea.secrets.server import SecretServerCloud

    authorizer = AccessTokenAuthorizer(
        "tok", "https://platform.example.com", server_type="platform"
    )
    with pytest.warns(UserWarning, match="does not use https") as record:
        SecretServerCloud(authorizer=authorizer, base_url="http://cloud.example.com")

    assert _warning_basenames(record) == {_this_file()}


def test_domain_authorizer_warning_points_at_caller():
    from delinea.secrets.server import DomainPasswordGrantAuthorizer

    with pytest.warns(UserWarning, match="does not use https") as record:
        DomainPasswordGrantAuthorizer(
            "http://domain.example.com",
            "user",
            "example.com",
            "pass",
            server_type="secret_server",
        )

    assert _warning_basenames(record) == {_this_file()}


def test_https_wrapper_emits_no_warning(recwarn):
    from delinea.secrets.server import SecretServerV0

    recwarn.clear()
    SecretServerV0("https://legacy.example.com", "user", "pass")
    assert len(recwarn) == 0


# ---------------------------------------------------------------------------
# Review step 4: the vault-fetch error path, and capped body excerpts
# ---------------------------------------------------------------------------


def test_vault_fetch_failure_populates_response(monkeypatch):
    server = make_server("https://platform.example.com", "platform")
    response = FakeResponse(status_code=500, text="x" * 5000)

    monkeypatch.setattr(HTTP_GET, lambda *a, **k: response)

    with pytest.raises(SecretServerError) as excinfo:
        server.ensure_vault_url()
    err = excinfo.value
    assert err.response is response
    assert "...[truncated]" in err.message
    assert len(err.message) < 400


def test_vault_fetch_failure_excerpts_bytes_without_decoding(monkeypatch):
    server = make_server("https://platform.example.com", "platform")
    response = BytesOnlyResponse(b"<html>" + b"x" * 5_000_000)

    monkeypatch.setattr(HTTP_GET, lambda *a, **k: response)

    with pytest.raises(SecretServerError) as excinfo:
        server.ensure_vault_url()
    err = excinfo.value
    assert err.message.startswith("Failed to fetch vault details: HTTP 502: <html>")
    assert err.message.endswith("...[truncated]")
    assert len(err.message) < 400


def test_body_excerpt_marks_truncation_for_multibyte_bodies():
    """Slicing bytes before decoding must still leave enough characters to
    show the body ran over the limit. A ``limit + 1`` byte slice did not: a
    12 000-character UTF-8 page came back as 134 unmarked characters.
    """
    from delinea.secrets.server import _safe_body_excerpt_bytes

    excerpt = _safe_body_excerpt_bytes(("caf\u00e9 " * 3000).encode("utf-8"))
    assert excerpt.endswith("...[truncated]")
    assert excerpt.startswith("caf\u00e9")
    assert len(excerpt) < 300


def test_body_excerpt_leaves_short_multibyte_body_unmarked():
    from delinea.secrets.server import _safe_body_excerpt_bytes

    assert _safe_body_excerpt_bytes("caf\u00e9".encode("utf-8")) == "caf\u00e9"


def test_describe_response_reads_bytes_not_text():
    """``_describe_response`` runs on the 5xx and token-grant paths, so it must
    not decode and charset-sniff a whole multi-megabyte error page."""
    from delinea.secrets.server import _describe_response

    message = _describe_response(BytesOnlyResponse(b"<html>" + b"x" * 5_000_000))
    assert message.startswith("HTTP 502: <html>")
    assert message.endswith("...[truncated]")
    assert len(message) < 400


def test_health_check_unreadable_body_is_unhealthy(monkeypatch):
    """The guard around body inspection returns False rather than letting an
    unexpected error abort detection."""
    assert _probe(monkeypatch, HostileBody()) is False


def test_describe_response_keeps_a_latin1_tail_that_looks_utf8():
    """A Latin-1 body ending in a UTF-8 lead byte must not lose its tail.

    A non-final incremental decode buffers that byte and reports success, so
    the excerpt silently came back short with no truncation marker.
    """
    from delinea.secrets.server import _safe_body_excerpt_bytes

    body = "Erreur: acc\u00e8s refus\u00e9".encode("iso-8859-1")

    assert _safe_body_excerpt_bytes(body, encoding="ISO-8859-1") == (
        "Erreur: acc\u00e8s refus\u00e9"
    )
    assert _safe_body_excerpt_bytes(b"\xc3", encoding="ISO-8859-1") == "\u00c3"


@pytest.mark.parametrize(
    "declared",
    ["ISO-8859-1", "latin-1", "latin", "iso8859", "csisolatin1", "L1", "cp819"],
)
def test_describe_response_reads_utf8_declared_as_requests_latin1_default(
    declared,
):
    """``requests`` reports ISO-8859-1 for any ``text/*`` body with no charset.
    A UTF-8 error page from a proxy or IIS must not come back as mojibake
    because of that default, whichever Latin-1 alias was declared.
    """
    from delinea.secrets.server import _describe_response

    class Utf8ButDeclaredLatin1:
        status_code = 502
        ok = False
        encoding = declared  # what requests fills in, not the server
        content = "Fehler: Zugriff verweigert f\u00fcr n\u00e9".encode("utf-8")

        def json(self):
            raise ValueError("no JSON body")

    assert (
        _describe_response(Utf8ButDeclaredLatin1())
        == "HTTP 502: Fehler: Zugriff verweigert f\u00fcr n\u00e9"
    )


@pytest.mark.parametrize("wide", ["utf-32-le", "utf-32", "utf-16"])
def test_body_excerpt_keeps_truncation_marker_for_wide_encodings(wide):
    """A body that was cut must say so even when the cut bytes decode to
    ``limit`` characters or fewer: with a BOM (``utf-32``) the preamble
    eats four of the sliced bytes, so counting characters is not enough."""
    from delinea.secrets.server import _safe_body_excerpt_bytes

    body = ("x" * 12000).encode(wide)
    excerpt = _safe_body_excerpt_bytes(body, limit=200, encoding=wide)
    assert excerpt.endswith("...[truncated]")
    assert excerpt.startswith("x" * 200)
    assert excerpt.count("...[truncated]") == 1


def test_body_excerpt_has_no_marker_when_nothing_was_cut():
    from delinea.secrets.server import _safe_body_excerpt_bytes

    assert _safe_body_excerpt_bytes(b"short", limit=200) == "short"
    exact = ("y" * 200).encode("utf-32")  # 804 bytes: fits the slice exactly
    assert _safe_body_excerpt_bytes(exact, limit=200, encoding="utf-32") == "y" * 200


def test_describe_response_honours_declared_encoding():
    """A proxy's Latin-1 error page must read correctly, not as U+FFFD."""
    from delinea.secrets.server import _describe_response

    class Latin1Response:
        status_code = 500
        ok = False
        encoding = "iso-8859-1"
        content = "Erreur: acc\u00e8s refus\u00e9".encode("iso-8859-1")

        def json(self):
            raise ValueError("no JSON body")

    assert (
        _describe_response(Latin1Response())
        == "HTTP 500: Erreur: acc\u00e8s refus\u00e9"
    )


@pytest.mark.parametrize(
    "charset",
    [
        "not-a-real-charset",  # unknown codec -> LookupError
        "idna",  # registered codec that rejects errors="replace" -> UnicodeError
        "punycode",  # registered codec that rejects non-ASCII -> UnicodeDecodeError
        "",  # empty charset parameter
        5,  # not even a string
        "ut\x00f8",  # a NUL byte survives header parsing -> ValueError
        "\ud800",  # a lone surrogate -> UnicodeEncodeError from codecs.lookup
    ],
)
def test_describe_response_falls_back_to_utf8_for_unusable_encoding(charset):
    """``response.encoding`` is copied verbatim from the server's
    ``charset=`` parameter, so any codec name (or none) can arrive. None
    of them may escape ``_describe_response`` as a codec error."""
    from delinea.secrets.server import _describe_response

    class OddEncoding:
        status_code = 500
        ok = False
        encoding = charset
        content = b"Bad \xe9 gateway"  # one non-UTF-8 byte

        def json(self):
            raise ValueError("no JSON body")

    assert _describe_response(OddEncoding()) == "HTTP 500: Bad \ufffd gateway"


def test_process_error_with_hostile_charset_is_a_secret_server_error():
    """The whole path a proxy or WAF error page would take: a 5xx whose
    Content-Type names a non-text codec must still surface as the error
    callers are told to catch."""

    class IdnaError:
        status_code = 502
        ok = False
        encoding = "idna"
        content = b"\xff<html>Bad Gateway</html>"
        text = "<html>Bad Gateway</html>"

        def json(self):
            raise ValueError("no JSON body")

    with pytest.raises(SecretServerError) as excinfo:
        SecretServer.process(IdnaError())
    assert "Bad Gateway" in excinfo.value.message


def test_health_check_rejects_3xx_even_though_requests_calls_it_ok(monkeypatch):
    """``requests.Response.ok`` is true below 400; detection requires 2xx."""
    response = FakeResponse(status_code=304, text="Healthy")
    assert response.ok
    assert _probe(monkeypatch, response) is False


def _vault_with_url(url):
    return vault_broker_payload(url)


def test_vault_switch_logs_the_accepted_host(monkeypatch, caplog):
    """Every later API call carries the bearer token to this host, so the
    log line that announces the switch must say which host it is."""
    server = make_server("https://platform.example.com", "platform")
    monkeypatch.setattr(
        HTTP_GET,
        lambda *a, **k: vault_broker_response("https://user:pw@vault.example.com"),
    )
    with caplog.at_level("INFO", logger="delinea.secrets.server"):
        server.ensure_vault_url()
    switch = [
        r.getMessage() for r in caplog.records if "Switching base_url" in r.getMessage()
    ]
    assert switch == [
        "Switching base_url to platform vault connection URL at vault.example.com"
    ]
    assert "user:pw" not in caplog.text  # userinfo never reaches the log


def test_non_string_vault_url_is_reported_as_invalid(monkeypatch):
    server = make_server("https://platform.example.com", "platform")
    response = FakeResponse(json_data=_vault_with_url({"host": "evil.example.net"}))
    monkeypatch.setattr(HTTP_GET, lambda *a, **k: response)
    with pytest.raises(SecretServerError) as excinfo:
        server.ensure_vault_url()
    assert "not a valid https URL" in excinfo.value.message
    assert excinfo.value.response is response
    assert server.base_url == "https://platform.example.com"  # unchanged


@pytest.mark.parametrize(
    "payload",
    [
        {"vaults": [{"isDefault": True, "isActive": True, "connection": None}]},
        {"vaults": None},
        {"vaults": [None]},
        [],
        None,  # no JSON body at all: json() raises
        JSON_NULL,  # the JSON literal ``null``: json() returns None
        # ``connection.url`` present but not a string: must not reach
        # ``urlsplit`` and escape as a TypeError/AttributeError.
        _vault_with_url({"host": "evil.example.net"}),
        _vault_with_url(["https://evil.example.net"]),
        _vault_with_url(42),
        _vault_with_url(True),
        # A netloc with no host: ``urlsplit`` accepts it, ``requests`` would
        # raise InvalidURL on the first API call after the switch.
        _vault_with_url("https://@"),
        _vault_with_url("https://user:pw@"),
        # ``urlsplit`` itself raises ValueError for these.
        _vault_with_url("https://[oops"),
        _vault_with_url("https://a\u2100b/"),
    ],
)
def test_vault_payload_shape_errors_are_secret_server_errors(monkeypatch, payload):
    """A malformed vault-broker body raises the error callers are told to
    catch, never an AttributeError from inside the SDK."""
    server = make_server("https://platform.example.com", "platform")
    monkeypatch.setattr(
        HTTP_GET,
        lambda *a, **k: FakeResponse(json_data=payload),
    )
    with pytest.raises(SecretServerError):
        server.ensure_vault_url()
