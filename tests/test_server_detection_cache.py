"""Offline unit tests for the process-scoped server-detection cache on the
``Authorizer`` base class.

These tests are fully OFFLINE: the network is mocked by patching
``delinea.secrets.server.requests.get`` (the symbol the SDK actually calls
inside ``_validate_health_endpoint``). Unlike ``tests/test_server.py`` these
do NOT require live credentials.

The cache is process-global, so each test clears it via the
``Authorizer._clear_server_type_cache()`` hook (see the autouse fixture).
"""

import threading

import pytest

from delinea.secrets.server import (
    AccessTokenAuthorizer,
    Authorizer,
    PasswordGrantAuthorizer,
    SecretServerError,
)

SECRET_SERVER_HEALTH = "/api/v1/healthcheck"
PLATFORM_HEALTH = "/health"


class FakeResponse:
    """Minimal stand-in for a ``requests.Response`` as consumed by
    ``_validate_health_endpoint`` (reads ``.content`` and ``.json()``)."""

    def __init__(self, healthy):
        self._healthy = healthy
        self.content = b'{"Healthy": true}' if healthy else b"{}"

    def json(self):
        return {"Healthy": self._healthy}


def make_probe_counter(healthy_endpoints):
    """Return a (fake_get, counter) pair.

    ``fake_get`` replaces ``requests.get``. It returns a healthy
    ``FakeResponse`` only when the requested URL ends with one of
    ``healthy_endpoints`` (e.g. ``/health``); every other health probe gets an
    unhealthy response. ``counter`` is a mutable dict tracking how many times
    each health endpoint suffix was probed plus a total.
    """

    # "rounds" counts how many times a full detection probe sequence began,
    # i.e. how many times the FIRST endpoint of the pair (the secret_server
    # healthcheck) was hit. A platform detection issues two raw GETs per round
    # (healthcheck=unhealthy, then health=healthy); a cache hit issues zero, so
    # "rounds" is the meaningful "probe pair fired N times" metric.
    counter = {"total": 0, "rounds": 0, SECRET_SERVER_HEALTH: 0, PLATFORM_HEALTH: 0}

    def fake_get(url, *args, **kwargs):
        for suffix in (SECRET_SERVER_HEALTH, PLATFORM_HEALTH):
            if url.endswith(suffix):
                counter["total"] += 1
                counter[suffix] += 1
                if suffix == SECRET_SERVER_HEALTH:
                    counter["rounds"] += 1
                return FakeResponse(suffix in healthy_endpoints)
        # Any other GET (e.g. vault lookups) is not a health probe.
        return FakeResponse(False)

    return fake_get, counter


@pytest.fixture(autouse=True)
def clear_detection_cache():
    """The detection cache is process-global; clear before and after each test
    so cached entries cannot leak between tests."""
    Authorizer._clear_server_type_cache()
    yield
    Authorizer._clear_server_type_cache()


# Behavior 1: repeated construction with the same base_url probes once total.
def test_repeated_construction_probes_once(monkeypatch):
    base_url = "https://platform.example.com"
    fake_get, counter = make_probe_counter({PLATFORM_HEALTH})
    monkeypatch.setattr("delinea.secrets.server.requests.get", fake_get)

    instances = [AccessTokenAuthorizer("tok", base_url) for _ in range(20)]

    assert all(inst._server_type == "platform" for inst in instances)
    # The probe pair fires exactly once total across all 20 constructions.
    assert counter["rounds"] == 1
    assert counter[PLATFORM_HEALTH] == 1
    assert counter[SECRET_SERVER_HEALTH] == 1


# Behavior 2: cache is shared across different authorizer subclasses.
def test_cache_shared_across_subclasses(monkeypatch):
    base_url = "https://platform.example.com"
    fake_get, counter = make_probe_counter({PLATFORM_HEALTH})
    monkeypatch.setattr("delinea.secrets.server.requests.get", fake_get)

    AccessTokenAuthorizer("tok", base_url)
    grant = PasswordGrantAuthorizer(base_url, "user", "pass")
    try:
        # Triggers lazy detection in _refresh; the grant POST will fail offline
        # but we only care that detection used the cache.
        grant.get_access_token()
    except Exception:
        pass

    assert grant._server_type == "platform"
    # Detection probes fire once total across both authorizers.
    assert counter["rounds"] == 1


# Behavior 3: a cache hit still sets the per-instance _server_type attribute.
def test_cache_hit_sets_instance_attr(monkeypatch):
    base_url = "https://platform.example.com"
    fake_get, counter = make_probe_counter({PLATFORM_HEALTH})
    monkeypatch.setattr("delinea.secrets.server.requests.get", fake_get)

    AccessTokenAuthorizer("tok", base_url)  # populates the cache
    assert counter["rounds"] == 1
    probes_after_first = counter["total"]

    second = AccessTokenAuthorizer("tok", base_url)  # cache hit, no new probe
    assert second._server_type == "platform"
    assert counter["rounds"] == 1
    assert counter["total"] == probes_after_first


# Behavior 4: two distinct base_urls get independent, correct cache entries.
def test_two_distinct_base_urls(monkeypatch):
    ss_url = "https://secretserver.example.com"
    platform_url = "https://platform.example.com"

    def fake_get(url, *args, **kwargs):
        if url.startswith(ss_url) and url.endswith(SECRET_SERVER_HEALTH):
            return FakeResponse(True)
        if url.startswith(platform_url) and url.endswith(PLATFORM_HEALTH):
            return FakeResponse(True)
        return FakeResponse(False)

    monkeypatch.setattr("delinea.secrets.server.requests.get", fake_get)

    ss_auth = AccessTokenAuthorizer("tok", ss_url)
    platform_auth = AccessTokenAuthorizer("tok", platform_url)

    assert ss_auth._server_type == "secret_server"
    assert platform_auth._server_type == "platform"

    cache = Authorizer._server_type_cache
    assert cache[ss_url] == "secret_server"
    assert cache[platform_url] == "platform"
    assert len(cache) == 2


# Behavior 5: detection failure is NOT cached; a later healthy probe succeeds.
def test_failure_is_not_cached(monkeypatch):
    base_url = "https://unknown.example.com"

    # First: both probes unhealthy -> detection raises.
    unhealthy_get, _ = make_probe_counter(set())
    monkeypatch.setattr("delinea.secrets.server.requests.get", unhealthy_get)
    with pytest.raises(SecretServerError):
        AccessTokenAuthorizer("tok", base_url)

    assert base_url not in Authorizer._server_type_cache

    # Then: probes become healthy -> re-probe succeeds (failure was not cached).
    healthy_get, counter = make_probe_counter({PLATFORM_HEALTH})
    monkeypatch.setattr("delinea.secrets.server.requests.get", healthy_get)
    instance = AccessTokenAuthorizer("tok", base_url)

    assert instance._server_type == "platform"
    assert counter["total"] >= 1


# Behavior 6: concurrent construction is thread-safe and probes few times.
def test_concurrent_construction_thread_safe(monkeypatch):
    base_url = "https://platform.example.com"
    fake_get, counter = make_probe_counter({PLATFORM_HEALTH})
    monkeypatch.setattr("delinea.secrets.server.requests.get", fake_get)

    results = []
    errors = []
    start = threading.Event()

    def worker():
        start.wait()
        try:
            inst = AccessTokenAuthorizer("tok", base_url)
            results.append(inst._server_type)
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
    assert all(r == "platform" for r in results)
    # Probe count is a small constant: the probe pair fires at least once, and
    # is bounded by the number of threads even under a detection race (commonly
    # exactly 1).
    assert counter["rounds"] >= 1
    assert counter["rounds"] <= 20


# Behavior 7: an explicit server_type override skips detection entirely (no probe).
@pytest.mark.parametrize("server_type", ["platform", "secret_server"])
def test_explicit_server_type_skips_probe(monkeypatch, server_type):
    base_url = "https://anything.example.com"
    # Every health endpoint is unhealthy: if any probe fired, detection would
    # raise. It must not, because the override bypasses probing.
    fake_get, counter = make_probe_counter(set())
    monkeypatch.setattr("delinea.secrets.server.requests.get", fake_get)

    inst = AccessTokenAuthorizer("tok", base_url, server_type=server_type)

    assert inst._server_type == server_type
    assert counter["total"] == 0  # zero probes -> no WAF burst
    # The override seeds the shared cache for subsequent callers.
    assert Authorizer._server_type_cache[base_url] == server_type


# Behavior 8: the override is normalized (case/whitespace-insensitive).
def test_explicit_server_type_is_normalized(monkeypatch):
    fake_get, counter = make_probe_counter(set())
    monkeypatch.setattr("delinea.secrets.server.requests.get", fake_get)

    inst = AccessTokenAuthorizer(
        "tok", "https://x.example.com", server_type="  Platform "
    )

    assert inst._server_type == "platform"
    assert counter["total"] == 0


# Behavior 9: an invalid override raises and issues no probe.
def test_invalid_server_type_raises(monkeypatch):
    fake_get, counter = make_probe_counter({PLATFORM_HEALTH})
    monkeypatch.setattr("delinea.secrets.server.requests.get", fake_get)

    with pytest.raises(SecretServerError):
        AccessTokenAuthorizer("tok", "https://x.example.com", server_type="bogus")

    assert counter["total"] == 0


# Behavior 10: PasswordGrantAuthorizer with an override never probes in _refresh.
def test_password_grant_override_skips_detection(monkeypatch):
    base_url = "https://platform.example.com"
    fake_get, counter = make_probe_counter(set())
    monkeypatch.setattr("delinea.secrets.server.requests.get", fake_get)

    grant = PasswordGrantAuthorizer(base_url, "user", "pass", server_type="platform")
    assert grant._server_type == "platform"

    try:
        # The grant POST will fail offline, but detection must not have probed.
        grant.get_access_token()
    except Exception:
        pass

    assert counter["total"] == 0
    # Platform token endpoint was selected without any health probe.
    assert grant.token_path_uri == PasswordGrantAuthorizer.PLATFORM_TOKEN_PATH_URI


# Behavior 11: the cache is bounded; the least-recently-used entry is evicted.
def test_cache_is_bounded_lru(monkeypatch):
    fake_get, _ = make_probe_counter(set())
    monkeypatch.setattr("delinea.secrets.server.requests.get", fake_get)

    maxsize = Authorizer._SERVER_TYPE_CACHE_MAXSIZE

    # Fill exactly to capacity using the override path (no network needed).
    for i in range(maxsize):
        AccessTokenAuthorizer(
            "tok", f"https://host-{i}.example.com", server_type="platform"
        )
    assert len(Authorizer._server_type_cache) == maxsize

    first_key = "https://host-0.example.com"
    # Touch host-0 so it becomes most-recently-used and survives the next insert.
    Authorizer._get_cached_server_type(first_key)

    # One more distinct URL overflows the cache by one entry.
    AccessTokenAuthorizer("tok", "https://overflow.example.com", server_type="platform")

    assert len(Authorizer._server_type_cache) == maxsize
    assert first_key in Authorizer._server_type_cache  # survived (recently used)
    assert "https://host-1.example.com" not in Authorizer._server_type_cache  # evicted


# Behavior 12: the public clear-cache method forces re-detection.
def test_public_clear_cache(monkeypatch):
    base_url = "https://platform.example.com"
    fake_get, counter = make_probe_counter({PLATFORM_HEALTH})
    monkeypatch.setattr("delinea.secrets.server.requests.get", fake_get)

    AccessTokenAuthorizer("tok", base_url)
    assert counter["rounds"] == 1

    Authorizer.clear_server_type_cache()
    assert base_url not in Authorizer._server_type_cache

    AccessTokenAuthorizer("tok", base_url)  # cache empty -> probes again
    assert counter["rounds"] == 2
