"""Offline unit tests for the process-scoped server-detection cache.

The network is mocked by patching ``delinea.secrets.server.requests.get``, so
no live credentials are needed. ``clear_detection_cache`` isolates the cache.
"""

import threading

import pytest

from delinea.secrets.server import (
    _DETECTION_WAIT_TIMEOUT,
    DEFAULT_REQUEST_TIMEOUT,
    AccessTokenAuthorizer,
    Authorizer,
    PasswordGrantAuthorizer,
    SecretServerError,
)
from fakes import (
    HTTP_GET,
    HTTP_POST,
    TOKEN_FROM_FAKE_ENDPOINT,
    HostileBody,
    fake_token_post,
    health_response,
    join_all,
)

# Shared fixtures from tests/conftest.py: fail loudly on an unmocked HTTP
# call, and isolate the process-global server-detection cache.
pytestmark = pytest.mark.usefixtures("no_network", "clear_detection_cache")

SECRET_SERVER_HEALTH = "/api/v1/healthcheck"
PLATFORM_HEALTH = "/health"


def make_probe_counter(healthy_endpoints):
    """Return a (fake_get, counter) pair replacing ``requests.get``.

    ``fake_get`` answers healthy only for a URL ending in one of
    ``healthy_endpoints``; ``counter`` tracks probes per endpoint and in total.
    """

    # "rounds" counts probe sequences that began, i.e. hits on the FIRST
    # endpoint of the pair. A platform detection issues two GETs per round and
    # a cache hit none, so "rounds" is the "probe pair fired N times" metric.
    counter = {"total": 0, "rounds": 0, SECRET_SERVER_HEALTH: 0, PLATFORM_HEALTH: 0}

    def fake_get(url, *args, **kwargs):
        for suffix in (SECRET_SERVER_HEALTH, PLATFORM_HEALTH):
            if url.endswith(suffix):
                counter["total"] += 1
                counter[suffix] += 1
                if suffix == SECRET_SERVER_HEALTH:
                    counter["rounds"] += 1
                return health_response(suffix in healthy_endpoints)
        # Any other GET (e.g. vault lookups) is not a health probe.
        return health_response(False)

    return fake_get, counter


# Behavior 1: repeated construction with the same base_url probes once total.
def test_repeated_construction_probes_once(monkeypatch):
    base_url = "https://platform.example.com"
    fake_get, counter = make_probe_counter({PLATFORM_HEALTH})
    monkeypatch.setattr(HTTP_GET, fake_get)

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
    monkeypatch.setattr(HTTP_GET, fake_get)

    monkeypatch.setattr(HTTP_POST, fake_token_post)

    AccessTokenAuthorizer("tok", base_url)
    grant = PasswordGrantAuthorizer(base_url, "user", "pass")
    # Triggers lazy detection in _refresh, which must reuse the cached result.
    assert grant.get_access_token() == TOKEN_FROM_FAKE_ENDPOINT

    assert grant._server_type == "platform"
    # Detection probes fire once total across both authorizers.
    assert counter["rounds"] == 1


# Behavior 3: a cache hit still sets the per-instance _server_type attribute.
def test_cache_hit_sets_instance_attr(monkeypatch):
    base_url = "https://platform.example.com"
    fake_get, counter = make_probe_counter({PLATFORM_HEALTH})
    monkeypatch.setattr(HTTP_GET, fake_get)

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
            return health_response(True)
        if url.startswith(platform_url) and url.endswith(PLATFORM_HEALTH):
            return health_response(True)
        return health_response(False)

    monkeypatch.setattr(HTTP_GET, fake_get)

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
    monkeypatch.setattr(HTTP_GET, unhealthy_get)
    with pytest.raises(SecretServerError):
        AccessTokenAuthorizer("tok", base_url)

    assert base_url not in Authorizer._server_type_cache

    # Then: probes become healthy -> re-probe succeeds (failure was not cached).
    healthy_get, counter = make_probe_counter({PLATFORM_HEALTH})
    monkeypatch.setattr(HTTP_GET, healthy_get)
    instance = AccessTokenAuthorizer("tok", base_url)

    assert instance._server_type == "platform"
    assert counter["total"] >= 1


# Behavior 6: concurrent construction is thread-safe and probes few times.
def test_concurrent_construction_thread_safe(monkeypatch):
    base_url = "https://platform.example.com"
    fake_get, counter = make_probe_counter({PLATFORM_HEALTH})
    monkeypatch.setattr(HTTP_GET, fake_get)

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

    threads = [threading.Thread(target=worker, daemon=True) for _ in range(20)]
    for t in threads:
        t.start()
    start.set()
    join_all(threads)

    assert errors == []
    assert len(results) == 20
    assert all(r == "platform" for r in results)
    # No probe-count assertion on purpose: with an instantaneous fake probe a
    # count of one cannot fail even without single-flight. That property is
    # pinned deterministically by ``test_only_one_probe_is_ever_in_flight``.


# Behavior 7: an explicit server_type override skips detection entirely (no probe)
# and is per-instance only -- it must NOT seed the shared process cache.
@pytest.mark.parametrize("server_type", ["platform", "secret_server"])
def test_explicit_server_type_skips_probe(monkeypatch, server_type):
    base_url = "https://anything.example.com"
    # Every health endpoint is unhealthy: if any probe fired, detection would
    # raise. It must not, because the override bypasses probing.
    fake_get, counter = make_probe_counter(set())
    monkeypatch.setattr(HTTP_GET, fake_get)

    inst = AccessTokenAuthorizer("tok", base_url, server_type=server_type)

    assert inst._server_type == server_type
    assert counter["total"] == 0  # zero probes -> no WAF burst
    # The unverified override must NOT be written to the shared cache (otherwise
    # it could poison auto-detection for other callers using the same base_url).
    assert base_url not in Authorizer._server_type_cache


# Behavior 8: the override is normalized (case/whitespace-insensitive).
def test_explicit_server_type_is_normalized(monkeypatch):
    fake_get, counter = make_probe_counter(set())
    monkeypatch.setattr(HTTP_GET, fake_get)

    inst = AccessTokenAuthorizer(
        "tok", "https://x.example.com", server_type="  Platform "
    )

    assert inst._server_type == "platform"
    assert counter["total"] == 0


# Behavior 9: an invalid override raises and issues no probe.
def test_invalid_server_type_raises(monkeypatch):
    fake_get, counter = make_probe_counter({PLATFORM_HEALTH})
    monkeypatch.setattr(HTTP_GET, fake_get)

    with pytest.raises(SecretServerError):
        AccessTokenAuthorizer("tok", "https://x.example.com", server_type="bogus")

    assert counter["total"] == 0


# Behavior 10: PasswordGrantAuthorizer with an override never probes in _refresh.
def test_password_grant_override_skips_detection(monkeypatch):
    base_url = "https://platform.example.com"
    fake_get, counter = make_probe_counter(set())
    monkeypatch.setattr(HTTP_GET, fake_get)

    grant = PasswordGrantAuthorizer(base_url, "user", "pass", server_type="platform")
    assert grant._server_type == "platform"

    monkeypatch.setattr(HTTP_POST, fake_token_post)
    assert grant.get_access_token() == TOKEN_FROM_FAKE_ENDPOINT

    # The platform token endpoint was selected without any health probe.
    assert counter["total"] == 0
    # Platform token endpoint was selected without any health probe.
    assert grant.token_path_uri == PasswordGrantAuthorizer.PLATFORM_TOKEN_PATH_URI


# Behavior 11: the cache is bounded; the least-recently-used entry is evicted.
def test_cache_is_bounded_lru(monkeypatch):
    # Every base_url detects as platform (healthy /health) so each distinct URL
    # seeds one verified cache entry. Only verified detections populate the
    # shared cache, so the cache must be filled via detection (not overrides).
    fake_get, _ = make_probe_counter({PLATFORM_HEALTH})
    monkeypatch.setattr(HTTP_GET, fake_get)

    maxsize = Authorizer._SERVER_TYPE_CACHE_MAXSIZE

    # Fill exactly to capacity via auto-detection.
    for i in range(maxsize):
        AccessTokenAuthorizer("tok", f"https://host-{i}.example.com")
    assert len(Authorizer._server_type_cache) == maxsize

    first_key = "https://host-0.example.com"
    # Touch host-0 so it becomes most-recently-used and survives the next insert.
    cached, _flight, _is_leader = Authorizer._start_or_join_detection(first_key)
    assert cached == "platform"

    # One more distinct URL overflows the cache by one entry.
    AccessTokenAuthorizer("tok", "https://overflow.example.com")

    assert len(Authorizer._server_type_cache) == maxsize
    assert first_key in Authorizer._server_type_cache  # survived (recently used)
    assert "https://host-1.example.com" not in Authorizer._server_type_cache  # evicted


# Behavior 13: an unverified override must not poison auto-detection for a later
# caller that relies on probing for the same base_url.
def test_override_does_not_poison_autodetect(monkeypatch):
    base_url = "https://platform.example.com"
    # The server is really a platform (healthy /health); probing would detect it.
    fake_get, counter = make_probe_counter({PLATFORM_HEALTH})
    monkeypatch.setattr(HTTP_GET, fake_get)

    # First caller supplies a WRONG override and issues no probe.
    poisoner = AccessTokenAuthorizer("tok", base_url, server_type="secret_server")
    assert poisoner._server_type == "secret_server"
    assert counter["total"] == 0
    assert base_url not in Authorizer._server_type_cache  # not seeded

    # Second caller relies on auto-detection -> must probe and get the real type,
    # NOT the poisoned override value.
    detected = AccessTokenAuthorizer("tok", base_url)
    assert detected._server_type == "platform"
    assert counter["rounds"] == 1  # a real probe fired
    assert Authorizer._server_type_cache[base_url] == "platform"


# Behavior 12: the public clear-cache method forces re-detection.
def test_public_clear_cache(monkeypatch):
    base_url = "https://platform.example.com"
    fake_get, counter = make_probe_counter({PLATFORM_HEALTH})
    monkeypatch.setattr(HTTP_GET, fake_get)

    AccessTokenAuthorizer("tok", base_url)
    assert counter["rounds"] == 1

    Authorizer.clear_server_type_cache()
    assert base_url not in Authorizer._server_type_cache

    AccessTokenAuthorizer("tok", base_url)  # cache empty -> probes again
    assert counter["rounds"] == 2


# ---------------------------------------------------------------------------
# Review step 3: single-flight detection and one owner of the cache bound
# ---------------------------------------------------------------------------


def test_concurrent_distinct_urls_each_probe_once(monkeypatch):
    """The detection lock is per base_url, so unrelated URLs are not
    serialized into a single probe (nor probed once per thread)."""
    urls = ["https://one.example.com", "https://two.example.com"]
    fake_get, counter = make_probe_counter({PLATFORM_HEALTH})
    monkeypatch.setattr(HTTP_GET, fake_get)

    results = []
    errors = []
    start = threading.Event()

    def worker(base_url):
        def run():
            start.wait()
            try:
                results.append(AccessTokenAuthorizer("tok", base_url)._server_type)
            except Exception as exc:  # pragma: no cover - failure path
                errors.append(exc)

        return run

    threads = [
        threading.Thread(target=worker(urls[i % 2]), daemon=True) for i in range(20)
    ]
    for t in threads:
        t.start()
    start.set()
    join_all(threads)

    assert errors == []
    assert len(results) == 20
    assert all(r == "platform" for r in results)
    # Both URLs were detected (a lower bound that can fail); the upper bound
    # -- not one pair per thread -- is single-flight's job and is pinned by
    # ``test_only_one_probe_is_ever_in_flight``, not by timing here.
    assert counter["rounds"] >= 2


def test_subclass_maxsize_override_does_not_shrink_shared_cache(monkeypatch):
    """``_SERVER_TYPE_CACHE_MAXSIZE`` is resolved on ``Authorizer``, so a
    subclass cannot evict cached detections belonging to other authorizers."""
    fake_get, _counter = make_probe_counter({PLATFORM_HEALTH})
    monkeypatch.setattr(HTTP_GET, fake_get)

    class SmallCacheAuthorizer(AccessTokenAuthorizer):
        _SERVER_TYPE_CACHE_MAXSIZE = 1

    AccessTokenAuthorizer("tok", "https://keep-a.example.com")
    AccessTokenAuthorizer("tok", "https://keep-b.example.com")
    SmallCacheAuthorizer("tok", "https://small.example.com")

    cache = Authorizer._server_type_cache
    assert "https://keep-a.example.com" in cache
    assert "https://keep-b.example.com" in cache
    assert "https://small.example.com" in cache


def test_detection_flights_are_retired(monkeypatch):
    """The in-flight registry holds an entry only while a probe is running, so
    it is bounded by live concurrency, not by how many URLs were ever seen."""
    fake_get, _counter = make_probe_counter({PLATFORM_HEALTH})
    monkeypatch.setattr(HTTP_GET, fake_get)

    for i in range(Authorizer._SERVER_TYPE_CACHE_MAXSIZE + 10):
        AccessTokenAuthorizer("tok", f"https://flight-{i}.example.com")

    assert Authorizer._server_type_flights == {}


def test_detection_flight_is_retired_after_failure(monkeypatch):
    """A failed flight must not linger, or the next caller would join a spent
    one instead of re-probing."""
    fake_get, _counter = make_probe_counter(set())
    monkeypatch.setattr(HTTP_GET, fake_get)

    with pytest.raises(SecretServerError, match="Unable to detect server type"):
        AccessTokenAuthorizer("tok", "https://down.example.com")

    assert Authorizer._server_type_flights == {}


def test_clear_cache_clears_detections_and_leaves_no_flights(monkeypatch):
    fake_get, _counter = make_probe_counter({PLATFORM_HEALTH})
    monkeypatch.setattr(HTTP_GET, fake_get)

    AccessTokenAuthorizer("tok", "https://platform.example.com")
    assert Authorizer._server_type_cache

    Authorizer.clear_server_type_cache()
    assert not Authorizer._server_type_cache
    assert Authorizer._server_type_flights == {}


def test_failure_still_re_probes_under_single_flight(monkeypatch):
    """A failed probe is not cached, and the detection lock does not wedge the
    next attempt."""
    fake_get, counter = make_probe_counter(set())  # nothing healthy
    monkeypatch.setattr(HTTP_GET, fake_get)
    base_url = "https://down.example.com"

    for _ in range(2):
        with pytest.raises(SecretServerError, match="Unable to detect server type"):
            AccessTokenAuthorizer("tok", base_url)

    assert base_url not in Authorizer._server_type_cache
    assert counter["rounds"] == 2


def test_only_one_probe_is_ever_in_flight(monkeypatch):
    """Directly pin the single-flight property.

    Rather than infer it from a count a fast mock could reach by luck, this
    widens the probe window and asserts two are never in flight at once.
    """
    import time

    base_url = "https://platform.example.com"
    state = {"in_flight": 0, "max_in_flight": 0, "probes": 0}
    guard = threading.Lock()

    def fake_get(url, *args, **kwargs):
        with guard:
            state["in_flight"] += 1
            state["probes"] += 1
            state["max_in_flight"] = max(state["max_in_flight"], state["in_flight"])
        time.sleep(0.01)
        with guard:
            state["in_flight"] -= 1
        return health_response(url.endswith(PLATFORM_HEALTH))

    monkeypatch.setattr(HTTP_GET, fake_get)

    errors = []
    start = threading.Event()

    def worker():
        start.wait()
        try:
            AccessTokenAuthorizer("tok", base_url)
        except Exception as exc:  # pragma: no cover - failure path
            errors.append(exc)

    threads = [threading.Thread(target=worker, daemon=True) for _ in range(20)]
    for t in threads:
        t.start()
    start.set()
    join_all(threads)

    assert errors == []
    assert state["max_in_flight"] == 1
    # The winning thread probes secret_server then platform; nobody else probes.
    assert state["probes"] == 2


def test_failure_path_shares_one_probe_pair(monkeypatch):
    """A cohort hitting an unreachable base_url shares the leader's failure:
    one probe pair for everyone, not one per caller. Deterministic by
    construction: the probe is held until every thread has registered.
    """
    thread_count = 12
    guard = threading.Lock()
    registered = {"count": 0}
    all_registered = threading.Event()
    real_register = Authorizer._start_or_join_detection

    def counting_register(key):
        result = real_register(key)
        with guard:
            registered["count"] += 1
            if registered["count"] == thread_count:
                all_registered.set()
        return result

    monkeypatch.setattr(
        Authorizer, "_start_or_join_detection", staticmethod(counting_register)
    )

    state = {"probes": 0, "in_flight": 0, "max_in_flight": 0, "waited_ok": None}

    def unreachable(url, *args, **kwargs):
        with guard:
            state["probes"] += 1
            state["in_flight"] += 1
            state["max_in_flight"] = max(state["max_in_flight"], state["in_flight"])
        # Recorded, not asserted: an exception here would be swallowed by the
        # probe's own error handling and the test would pass vacuously.
        state["waited_ok"] = all_registered.wait(timeout=5)
        with guard:
            state["in_flight"] -= 1
        raise OSError("unreachable")

    monkeypatch.setattr(HTTP_GET, unreachable)

    failures = []
    start = threading.Event()

    def worker():
        start.wait()
        try:
            AccessTokenAuthorizer("tok", "https://down.example.com")
        except SecretServerError as exc:
            failures.append(exc)

    threads = [
        threading.Thread(target=worker, daemon=True) for _ in range(thread_count)
    ]
    for t in threads:
        t.start()
    start.set()
    join_all(threads)

    assert state["waited_ok"] is True, "not every thread registered on the flight"
    # Every caller learns that detection failed ...
    assert len(failures) == thread_count
    # ... from one shared probe pair, not one pair each, and never a burst.
    assert state["probes"] == 2
    assert state["max_in_flight"] == 1
    # Each caller gets its own exception carrying the leader's message and
    # chained to the leader's -- never the leader's instance itself, whose
    # traceback would otherwise be rewritten by every thread re-raising it.
    assert len({id(exc) for exc in failures}) == thread_count
    assert len({exc.message for exc in failures}) == 1
    assert sum(1 for exc in failures if exc.__cause__ is not None) == thread_count - 1


def test_health_body_error_falls_through_to_next_endpoint(monkeypatch):
    """A body that raises something other than ValueError means "unhealthy,
    try the next endpoint", never "abort detection"."""

    def fake_get(url, *args, **kwargs):
        if url.endswith(SECRET_SERVER_HEALTH):
            return HostileBody()
        return health_response(True)

    monkeypatch.setattr(HTTP_GET, fake_get)

    authorizer = AccessTokenAuthorizer("tok", "https://platform.example.com")
    assert authorizer._server_type == "platform"


def test_leader_interrupt_is_not_broadcast_to_waiters(monkeypatch):
    """A KeyboardInterrupt in the leader belongs to the leader. Waiters get an
    ordinary SecretServerError their handlers can catch, not a foreign
    interrupt raised in the middle of their own work."""
    thread_count = 6
    guard = threading.Lock()
    registered = {"count": 0}
    all_registered = threading.Event()
    real_register = Authorizer._start_or_join_detection

    def counting_register(key):
        result = real_register(key)
        with guard:
            registered["count"] += 1
            if registered["count"] == thread_count:
                all_registered.set()
        return result

    monkeypatch.setattr(
        Authorizer, "_start_or_join_detection", staticmethod(counting_register)
    )

    def interrupted_probe(url, *args, **kwargs):
        all_registered.wait(timeout=5)
        raise KeyboardInterrupt()

    monkeypatch.setattr(HTTP_GET, interrupted_probe)

    outcomes = []
    start = threading.Event()

    def worker():
        start.wait()
        try:
            AccessTokenAuthorizer("tok", "https://down.example.com")
        except BaseException as exc:  # the interrupt is the point of the test
            with guard:
                outcomes.append(exc)

    threads = [
        threading.Thread(target=worker, daemon=True) for _ in range(thread_count)
    ]
    for t in threads:
        t.start()
    start.set()
    join_all(threads)

    interrupts = [e for e in outcomes if isinstance(e, KeyboardInterrupt)]
    errors = [e for e in outcomes if isinstance(e, SecretServerError)]
    assert len(interrupts) == 1  # the leader, and only the leader
    assert len(errors) == thread_count - 1
    assert all("interrupted" in e.message for e in errors)
    assert Authorizer._server_type_flights == {}


def test_waiters_take_over_from_a_stalled_leader(monkeypatch):
    """A leader that outruns every bound a probe can have no longer strands the
    callers waiting on it: they time out, retire its flight and probe."""
    import time

    # 1 s: long enough that the taking-over waiter's two instant probes
    # cannot be pre-empted by a second timeout on a slow runner, short
    # enough to stay well inside the 5 s waiter join bound below.
    monkeypatch.setattr("delinea.secrets.server._DETECTION_WAIT_TIMEOUT", 1.0)
    key = "https://platform.example.com"
    release_leader = threading.Event()
    calls = {"n": 0}
    guard = threading.Lock()

    def fake_get(url, *args, **kwargs):
        with guard:
            calls["n"] += 1
        # Hang by thread identity, not by call ordinal: if the leader were
        # descheduled between registering its flight and probing, a waiter
        # could otherwise be the one that gets stuck.
        if threading.current_thread().name == "leader":
            # Longer than the waiters' join bound below, so the waiters can
            # only finish by taking over.
            release_leader.wait(timeout=30)
        return health_response(url.endswith(PLATFORM_HEALTH))

    monkeypatch.setattr(HTTP_GET, fake_get)

    results = {}

    def worker(name):
        def run():
            results[name] = AccessTokenAuthorizer("tok", key)._server_type

        return run

    leader = threading.Thread(target=worker("leader"), name="leader", daemon=True)
    leader.start()
    waiters = [threading.Thread(target=worker(f"w{i}"), daemon=True) for i in range(3)]
    try:
        deadline = time.monotonic() + 5
        while (
            key not in Authorizer._server_type_flights and time.monotonic() < deadline
        ):
            time.sleep(0.005)
        assert key in Authorizer._server_type_flights, "leader never registered"
        for t in waiters:
            t.start()
        join_all(waiters, timeout=5)
        assert not release_leader.is_set()
        assert all(results[f"w{i}"] == "platform" for i in range(3))
        # The leader's hung probe plus exactly one probe pair from the single
        # waiter that took over; the other two joined its flight.
        assert calls["n"] == 3
    finally:
        # Always let the leader go AND wait for it, so a failure here cannot
        # leak a thread that keeps probing (and writing the cache) into the
        # tests that run next. Once released it finishes within milliseconds.
        release_leader.set()
        join_all([leader])
    assert results["leader"] == "platform"
    assert Authorizer._server_type_flights == {}


def test_leader_sees_the_same_error_type_as_its_waiters(monkeypatch):
    """A probe failure that is not a SecretServerError reaches every caller
    as one: waiters via ``_shared_failure``, and the leader too, so the type a
    caller must catch does not depend on which thread won the registration."""

    def exploding_probe(self, base_url):
        raise RuntimeError("probe exploded")

    monkeypatch.setattr(Authorizer, "_probe_server_type", exploding_probe)
    with pytest.raises(SecretServerError) as excinfo:
        AccessTokenAuthorizer("tok", "https://x.example.com")
    assert isinstance(excinfo.value.__cause__, RuntimeError)
    assert "RuntimeError" in excinfo.value.message
    assert Authorizer._server_type_flights == {}
    assert "https://x.example.com" not in Authorizer._server_type_cache


def test_clear_cache_drops_a_stranded_flight():
    key = "https://stranded.example.com"
    _cached, _flight, is_leader = Authorizer._start_or_join_detection(key)
    assert is_leader and key in Authorizer._server_type_flights

    Authorizer.clear_server_type_cache()
    assert Authorizer._server_type_flights == {}


# ---------------------------------------------------------------------------
# Round 9: stale leaders, subclass errors, the waiter bound
# ---------------------------------------------------------------------------


def test_stale_leader_does_not_overwrite_a_cleared_cache(monkeypatch):
    """A probe that began before ``clear_server_type_cache`` must not write its
    answer back afterwards; only the flight still registered may cache."""
    import time

    key = "https://switched.example.com"
    release_leader = threading.Event()

    def fake_get(url, *args, **kwargs):
        if threading.current_thread().name == "leader":
            release_leader.wait(timeout=10)
            return health_response(url.endswith(SECRET_SERVER_HEALTH))  # old answer
        return health_response(url.endswith(PLATFORM_HEALTH))  # current answer

    monkeypatch.setattr(HTTP_GET, fake_get)
    results = {}
    leader = threading.Thread(
        target=lambda: results.update(
            leader=AccessTokenAuthorizer("tok", key)._server_type
        ),
        name="leader",
        daemon=True,
    )
    leader.start()
    try:
        deadline = time.monotonic() + 5
        while (
            key not in Authorizer._server_type_flights and time.monotonic() < deadline
        ):
            time.sleep(0.005)
        assert key in Authorizer._server_type_flights, "leader never registered"
        Authorizer.clear_server_type_cache()  # re-provisioned: forget everything
        assert AccessTokenAuthorizer("tok", key)._server_type == "platform"
        assert Authorizer._server_type_cache[key] == "platform"
    finally:
        release_leader.set()
        join_all([leader])
    assert results["leader"] == "secret_server"  # what it observed, for itself
    assert Authorizer._server_type_cache[key] == "platform"  # not overwritten
    assert Authorizer._server_type_flights == {}


def test_shared_failure_tolerates_a_subclass_with_its_own_constructor():
    """A probe override may raise a SecretServerError subclass whose __init__
    takes only a message; waiters must still get a shareable error."""

    class MessageOnly(SecretServerError):
        def __init__(self, message):
            super().__init__(message)

    shared = Authorizer._shared_failure(MessageOnly("probe said no"))
    assert isinstance(shared, SecretServerError)
    assert shared.message == "probe said no"


def test_waiter_bound_covers_connect_and_read_for_both_probes():
    """``requests`` applies its timeout per socket operation, so a live leader
    can spend two timeouts per probe; the waiter bound must allow for four."""
    assert _DETECTION_WAIT_TIMEOUT == 4 * DEFAULT_REQUEST_TIMEOUT + 5


def test_waiter_on_a_superseded_flight_takes_the_current_answer(monkeypatch):
    """A waiter whose leader was retired by a clear, and then failed, must not
    raise that stale failure while the newer detection's answer is cached."""
    import time

    key = "https://superseded.example.com"
    release_leader = threading.Event()
    joined = threading.Event()

    def fake_get(url, *args, **kwargs):
        if threading.current_thread().name == "leader":
            release_leader.wait(timeout=10)
            return health_response(False)  # the stale leader fails outright
        return health_response(url.endswith(PLATFORM_HEALTH))

    monkeypatch.setattr(HTTP_GET, fake_get)
    real_start = Authorizer._start_or_join_detection

    def recording_start(k):
        outcome = real_start(k)
        if threading.current_thread().name == "waiter" and outcome[1] is not None:
            joined.set()  # the waiter is now parked on the leader's flight
        return outcome

    monkeypatch.setattr(
        Authorizer, "_start_or_join_detection", staticmethod(recording_start)
    )
    results = {}

    def detect(name):
        try:
            results[name] = AccessTokenAuthorizer("tok", key)._server_type
        except SecretServerError as exc:
            results[name] = exc

    leader = threading.Thread(
        target=detect, args=("leader",), name="leader", daemon=True
    )
    waiter = threading.Thread(
        target=detect, args=("waiter",), name="waiter", daemon=True
    )
    leader.start()
    try:
        deadline = time.monotonic() + 5
        while (
            key not in Authorizer._server_type_flights and time.monotonic() < deadline
        ):
            time.sleep(0.005)
        assert key in Authorizer._server_type_flights, "leader never registered"
        waiter.start()
        assert joined.wait(timeout=5), "waiter never joined the leader's flight"
        Authorizer.clear_server_type_cache()  # retires the leader's flight
        assert AccessTokenAuthorizer("tok", key)._server_type == "platform"
    finally:
        release_leader.set()
        # Join only what was started: a failure before ``waiter.start()`` must
        # report itself, not a RuntimeError from joining an unstarted thread.
        join_all([t for t in (leader, waiter) if t.ident is not None])
    assert isinstance(results["leader"], SecretServerError)  # its own observation
    assert results["waiter"] == "platform"  # not the stale failure
