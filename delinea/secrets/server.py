"""The Delinea Secret Server SDK API facilitates access to the Secret Server
REST API using *OAuth2 Bearer Token* authentication.

Example:

    # connect to Secret Server
    secret_server = SecretServer(base_url, authorizer, api_path_uri='/api/v1')
    # or, for Secret Server Cloud
    secret_server = SecretServerCloud(tenant, authorizer, tld='com')

    # to get the secret as a ``dict``
    secret = secret_server.get_secret(123)
    # or, to use the dataclass
    secret = ServerSecret(**secret_server.get_secret(123))
"""

import codecs
import copy
import json
import logging
import math
import re
import sys
import warnings
from abc import ABC, abstractmethod
from collections import OrderedDict
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from threading import Event, Lock
from urllib.parse import parse_qsl, urlsplit, urlunsplit

import requests

logger = logging.getLogger(__name__)

# Applied to every HTTP call the SDK makes; ``requests`` has no default
# timeout, so an omitted value would let a stalled connection hang forever.
DEFAULT_REQUEST_TIMEOUT = 60

# Cap on how much of a server response body is echoed into an exception
# message, so a malformed/oversized response cannot flood logs and so
# exception text stays clearly distinguishable from a full response body.
_BODY_EXCERPT_LIMIT = 200
_TRUNCATION_MARKER = "...[truncated]"

# Cap on the server-supplied attachment filename echoed into a repr. Shorter
# than a body excerpt: it identifies the file in a log line, nothing more.
_FILENAME_EXCERPT_LIMIT = 60

# How long a caller waits on another thread's in-flight detection before
# probing itself. ``requests``' timeout is per socket operation, so a live
# leader may spend connect plus read on each of two probes: four, plus slack.
_DETECTION_WAIT_TIMEOUT = 4 * DEFAULT_REQUEST_TIMEOUT + 5

# Lifetime assumed for an access grant with no ``expires_in``. RFC 6749 makes
# the field RECOMMENDED, so both products send it and this covers only a
# non-conforming proxy; one hour is the conventional OAuth2 default.
_DEFAULT_GRANT_LIFETIME_SECONDS = 3600

# Ceiling on a grant lifetime. Beyond roughly this, ``now + timedelta``
# overflows ``datetime`` and every later call would raise OverflowError.
_MAX_GRANT_LIFETIME_SECONDS = 10 * 365 * 24 * 3600


def _with_query_flag(params, key, value):
    """``params`` plus ``key=value``, in any form ``requests`` accepts.

    The flag is sent once and wins; a non-mapping form stays a list of pairs,
    so repeated keys the caller relies on are not collapsed.
    """
    if params is None or isinstance(params, Mapping):
        return {**(params or {}), key: value}
    if isinstance(params, bytes):
        params = params.decode("utf-8", errors="replace")
    if isinstance(params, str):
        pairs = parse_qsl(params, keep_blank_values=True)
    else:
        pairs = list(params)
    return [(k, v) for k, v in pairs if k != key] + [(key, value)]


def _join_url(base, path):
    """Join ``base`` and ``path`` with exactly one slash between them.

    The one place that knows how a base URL and a path segment combine, so the
    token endpoint, API root, vault call and probes cannot drift apart.
    """
    return f"{base.rstrip('/')}/{path.strip('/')}"


def _caller_stacklevel():
    """Return the ``stacklevel`` of the first frame outside this module.

    Each wrapper adds a frame, so a constant aims the warning inside this file.
    TODO(python>=3.12): ``warnings.warn(skip_file_prefixes=...)`` replaces this.
    """
    level = 1
    try:
        frame = sys._getframe(1)  # the caller of this helper
    except ValueError:  # pragma: no cover - no caller frame
        return 2
    while frame is not None and frame.f_globals.get("__name__") == __name__:
        frame = frame.f_back
        level += 1
    return level


def _warn_if_insecure(base_url):
    """Warn when ``base_url`` does not use ``https``.

    Credentials and bearer tokens travel in plaintext otherwise; the warning is
    attributed to the caller. TODO(v4.0): reject non-https, with an opt-out.
    """
    try:
        scheme = urlsplit(base_url).scheme
    except ValueError as exc:  # unclosed IPv6 bracket, NFKC-changing netloc
        raise ValueError(f"base_url {base_url!r} is not a valid URL: {exc}") from exc
    if scheme.lower() != "https":
        warnings.warn(
            f"base_url {base_url!r} does not use https; credentials and "
            "bearer tokens will be sent unencrypted.",
            UserWarning,
            stacklevel=_caller_stacklevel(),
        )


def _safe_body_excerpt(text, limit=_BODY_EXCERPT_LIMIT):
    """Return a length-capped excerpt of a response body for use in error
    messages, marked when truncated so it's clearly not the full body."""
    if text is None:
        return ""
    text = str(text)
    if len(text) <= limit:
        return text
    return text[:limit] + _TRUNCATION_MARKER


def _safe_body_excerpt_bytes(content, limit=_BODY_EXCERPT_LIMIT, encoding=None):
    """Return a length-capped excerpt of a raw, undecoded response body.

    Slices ``4 * (limit + 1)`` bytes first and marks any body that was cut. A
    declared Latin-1 yields to valid UTF-8; an unusable codec falls back to it.
    """
    if not content:
        return ""
    if isinstance(content, str):
        return _safe_body_excerpt(content, limit)
    head = content[: 4 * (limit + 1)]
    truncated = len(head) < len(content)
    codec = encoding if isinstance(encoding, str) and encoding else "utf-8"
    try:
        canonical = codecs.lookup(codec).name
    except (LookupError, ValueError):
        # ``ValueError``: a NUL byte or a lone surrogate in the header value
        # (``codecs.lookup`` raises it before it gets to the registry).
        canonical = None
    text = None
    if canonical == "iso8859-1":
        try:
            # Strict UTF-8, tolerating a multi-byte sequence the slice above
            # cut in half. Final when nothing was cut, so a real Latin-1 body
            # ending in a lead byte falls back instead of losing its tail.
            decoder = codecs.getincrementaldecoder("utf-8")()
            text = decoder.decode(head, not truncated)
        except UnicodeDecodeError:
            text = None
    if text is None:
        try:
            text = head.decode(codec, errors="replace")
        except (LookupError, ValueError):  # ValueError covers UnicodeError
            text = head.decode("utf-8", errors="replace")
    excerpt = _safe_body_excerpt(text, limit)
    if truncated and not excerpt.endswith(_TRUNCATION_MARKER):
        excerpt += _TRUNCATION_MARKER
    return excerpt


def _required_records(data, key, what, response):
    """Return ``data[key]`` as a list of JSON objects, or raise.

    ``_get_json`` vouches for the body being an object; this vouches for the
    one key read out of it, so no ``KeyError`` escapes as the failure.
    """
    records = data.get(key)
    if not isinstance(records, list) or not all(
        isinstance(record, Mapping) for record in records
    ):
        raise SecretServerError(
            f"{what} did not return '{key}' as a list of objects", response
        )
    return records


def _record_ids(records, what, response):
    """Return the ``id`` of every record, or raise.

    ``_required_records`` vouches for each record being an object; this vouches
    for the one key read out of it, so a record missing ``id`` raises the
    ``SecretServerError`` these methods document instead of a bare ``KeyError``.
    """
    ids = []
    for record in records:
        if "id" not in record:
            raise SecretServerError(f"{what} returned a record with no 'id'", response)
        ids.append(record["id"])
    return ids


def _redirect_target(response):
    """A redirect's destination, capped and stripped of its query string.

    ``Location`` is server-controlled, and IIS appends a ``ReturnUrl`` echoing
    the path it intercepted; neither belongs in an error message or a log line.
    ``None`` when there is nothing usable to name.
    """
    try:
        location = response.headers.get("Location")
    except Exception:  # a response double, or headers that are not a mapping
        return None
    if not isinstance(location, str) or not location:
        return None
    try:
        parsed = urlsplit(location)
    except ValueError:  # unclosed IPv6 bracket, NFKC-changing netloc
        return None
    return _safe_body_excerpt(
        urlunsplit((parsed.scheme, parsed.netloc, parsed.path, "", ""))
    )


def _describe_response(response):
    """Build a sanitized, length-capped error message from a response.

    Reads ``.content`` rather than ``.text``, which would decode and
    charset-sniff the whole body to quote a couple of hundred characters.
    """
    try:
        content = response.content
    except Exception as exc:
        logger.debug(
            "Could not read response body for an error message: %s",
            type(exc).__name__,
        )
        content = b""
    excerpt = _safe_body_excerpt_bytes(
        content, encoding=getattr(response, "encoding", None)
    )
    message = f"HTTP {response.status_code}"
    return f"{message}: {excerpt}" if excerpt else message


def _validated_vault_url(url, response):
    """Return ``(hostname, url)`` for an https vault URL, or raise.

    ``hostname`` rather than ``netloc``: ``https://@`` has a netloc but no
    host, and would only fail later inside ``requests``.
    """
    try:
        parsed = urlsplit(url) if isinstance(url, str) else None
    except ValueError:  # unclosed IPv6 bracket, NFKC-changing netloc
        parsed = None
    if parsed is None or parsed.scheme != "https" or not parsed.hostname:
        raise SecretServerError(
            "Vault connection URL is not a valid https URL: "
            f"{_safe_body_excerpt(repr(url))}",
            response,
        )
    return parsed.hostname, url.rstrip("/")


class _DetectionFlight:
    """One in-progress server-type detection, shared by concurrent callers.

    The registering caller owns the probe; others wait on ``done``, then take
    ``server_type`` or raise ``error``. ``superseded``: retired before it ended.
    """

    __slots__ = ("done", "server_type", "error", "superseded")

    def __init__(self):
        self.done = Event()
        self.server_type = None
        self.error = None
        self.superseded = False


class FileAttachment(bytes):
    """The contents of a secret's file field, as the bytes the server sent.

    Keeps the ``requests.Response`` members a consumer of an earlier release
    read -- ``.content``, ``.text``, ``.encoding`` -- and no other.
    """

    # Class-level defaults: pickle protocols 0 and 1 rebuild through
    # ``copyreg._reconstructor``, not ``__new__``, so these keep ``.text``
    # working even if an instance is restored without its own attributes.
    encoding = None
    filename = None

    def __new__(cls, data, encoding=None, filename=None):
        attachment = super().__new__(cls, data)
        attachment.encoding = encoding
        attachment.filename = filename
        return attachment

    @property
    def content(self):
        """The attachment exactly as the server sent it, as plain ``bytes``."""
        return bytes(self)

    @property
    def text(self):
        """The attachment decoded as text, replacing undecodable bytes.

        A declared Latin-1 yields to valid UTF-8, because ``requests`` labels
        every charset-less ``text/*`` body Latin-1. So does an unusable codec.
        """
        codec = self.encoding if isinstance(self.encoding, str) else ""
        try:
            if codecs.lookup(codec or "utf-8").name == "iso8859-1":
                return self.decode("utf-8")
        except (LookupError, ValueError):  # unusable codec, or not valid UTF-8
            pass
        try:
            return self.decode(codec or "utf-8", errors="replace")
        except (LookupError, ValueError):  # ValueError covers UnicodeError
            return self.decode("utf-8", errors="replace")

    def __getnewargs__(self):
        # Pins the round trip: ``bytes`` happens to supply this, but no rule
        # of the model says so. The bytes are the only argument, so nothing
        # re-runs a subclass's ``__init__``; the state dict carries the rest.
        return (bytes(self),)

    def __repr__(self):
        # Bounded on purpose: an attachment can be megabytes, and ``bytes``'
        # own repr would put all of it into any log line holding a secret.
        # ``filename`` is server data: sliced, then escaped and capped.
        try:
            name = self.filename
            if not name:
                name = ""
            elif isinstance(name, (str, bytes)):
                name = repr(name[: _FILENAME_EXCERPT_LIMIT + 1])
            else:
                name = repr(name)[: _FILENAME_EXCERPT_LIMIT + 1]
        except Exception:  # only a hand-built filename can get here
            name = "<unprintable filename>"
        if name:
            name = f" {_safe_body_excerpt(name, _FILENAME_EXCERPT_LIMIT)}"
        return f"<{type(self).__name__}{name}: {len(self)} bytes>"

    def __str__(self):
        # ``bytes`` defines ``__str__`` itself, so overriding only ``__repr__``
        # would leave ``print`` and f-strings dumping the whole attachment.
        return repr(self)


@dataclass
class ServerSecret:
    # Based on https://gist.github.com/jaytaylor/3660565
    @staticmethod
    def snake_case(camel_cased):
        """Transform to snake case

        Transforms the keys of the given map from camelCase to snake_case.
        """
        return [
            (
                re.compile("([a-z0-9])([A-Z])")
                .sub(r"\1_\2", re.compile(r"(.)([A-Z][a-z]+)").sub(r"\1_\2", k))
                .lower(),
                v,
            )
            for (k, v) in camel_cased.items()
        ]

    @dataclass
    class Field:
        item_id: int
        field_id: int
        file_attachment_id: int
        field_description: str
        field_name: str
        filename: str
        # ``str`` for an ordinary field, a ``FileAttachment`` for a file field
        # fetched with ``fetch_file_attachments``.
        value: str
        slug: str

        def __init__(self, **kwargs):
            # The REST API returns attributes with camelCase names which we
            # replace with snake_case per Python conventions
            for k, v in ServerSecret.snake_case(kwargs):
                if k == "item_value":
                    k = "value"
                setattr(self, k, v)

    id: int
    folder_id: int
    secret_template_id: int
    site_id: int
    active: bool
    checked_out: bool
    check_out_enabled: bool
    name: str
    secret_template_name: str
    last_heart_beat_status: str
    last_heart_beat_check: datetime
    last_password_change_attempt: datetime
    fields: dict

    DEFAULT_DATETIME_FORMAT = "%Y-%m-%dT%H:%M:%S"

    def __init__(self, **kwargs):
        # The REST API returns attributes with camelCase names which we replace
        # with snake_case per Python conventions
        datetime_format = self.DEFAULT_DATETIME_FORMAT
        if "datetime_format" in kwargs:
            datetime_format = kwargs["datetime_format"]
        for k, v in self.snake_case(kwargs):
            if k in ["last_heart_beat_check", "last_password_change_attempt"]:
                # @dataclass does not marshal timestamps into datetimes automatically
                v = re.sub(r"\.[0-9]+$", "", v)
                v = datetime.strptime(v, datetime_format)
            setattr(self, k, v)
        self.fields = {
            item["slug"]: ServerSecret.Field(**item) for item in kwargs["items"]
        }


@dataclass
class ServerFolder:
    # Based on https://gist.github.com/jaytaylor/3660565
    @staticmethod
    def snake_case(camel_cased):
        """Transform to snake case

        Transforms the keys of the given map from camelCase to snake_case.
        """
        return [
            (
                re.compile("([a-z0-9])([A-Z])")
                .sub(r"\1_\2", re.compile(r"(.)([A-Z][a-z]+)").sub(r"\1_\2", k))
                .lower(),
                v,
            )
            for (k, v) in camel_cased.items()
        ]

    @dataclass
    class Field:
        item_id: int
        value: str
        slug: str

        def __init__(self, **kwargs):
            # The REST API returns attributes with camelCase names which we
            # replace with snake_case per Python conventions
            for k, v in ServerSecret.snake_case(kwargs):
                if k == "item_value":
                    k = "value"
                setattr(self, k, v)

    id: int
    folder_name: str
    folder_path: str
    parent_folder_id: int
    folder_type_id: int
    secret_policy_id: int
    inherit_secret_policy: bool
    inherit_permissions: bool
    child_folders: list
    secret_templates: list

    def __init__(self, **kwargs):
        # The REST API returns attributes with camelCase names which we replace
        # with snake_case per Python conventions
        for k, v in self.snake_case(kwargs):
            setattr(self, k, v)


def _expires_in_seconds(value):
    """``value`` as a finite float, or ``None`` when it is not a number.

    Booleans are not numbers here: ``True`` is not a one-second lifetime.
    """
    if isinstance(value, bool):
        return None
    try:
        seconds = float(value)
    except (TypeError, ValueError):
        return None
    return seconds if math.isfinite(seconds) else None


def _with_validated_expires_in(grant, response):
    """Return ``grant`` with a usable ``expires_in``, or raise.

    Missing or null defaults to ``_DEFAULT_GRANT_LIFETIME_SECONDS``; a value
    that is not finite raises here. Zero is honoured, and ``_refresh`` warns.
    """
    expires_in = grant.get("expires_in")
    if expires_in is None:
        logger.debug(
            "Access grant carried no expires_in; assuming a %ss lifetime.",
            _DEFAULT_GRANT_LIFETIME_SECONDS,
        )
        return {**grant, "expires_in": _DEFAULT_GRANT_LIFETIME_SECONDS}
    if _expires_in_seconds(expires_in) is None:
        raise SecretServerError(
            "Token endpoint returned a non-numeric expires_in: "
            f"{_safe_body_excerpt(repr(expires_in))}",
            response,
        )
    return grant


class SecretServerError(Exception):
    """An Exception that includes a message and the server response.

    ``message`` is always a string, never an object repr. ``.response`` is
    in-memory only: :meth:`__reduce__` drops it so a pickle carries no secret.
    """

    def __init__(self, message, response=None, *args, **kwargs):
        self.message = message
        self.response = response
        # Pass message through so str(exception) is populated for default
        # traceback/log output, not just the .message attribute.
        super().__init__(message, *args, **kwargs)

    def __reduce__(self):
        # Rebuild from the message alone, so ``response`` never reaches a pickle:
        # it holds the PreparedRequest, whose body is the OAuth2 grant and whose
        # headers carry the bearer token. Runtimes pickle exceptions unasked.
        return (type(self), (self.message,))


class SecretServerClientError(SecretServerError):
    """An Exception that represents a client error i.e. ``400``."""


class SecretServerServiceError(SecretServerError):
    """An Exception that represents a service error i.e. ``500``."""


class Authorizer(ABC):
    """Main abstract base class for all Authorizer access methods."""

    # Accepted values for an explicit ``server_type`` override and for cached
    # detections.
    VALID_SERVER_TYPES = ("secret_server", "platform")

    # Bounded LRU mapping a normalized base_url to its detected server type,
    # shared by every subclass so the probe pair fires once per URL per process.
    # A caller with a process per lookup should pass an explicit ``server_type``.
    _SERVER_TYPE_CACHE_MAXSIZE = 128
    _server_type_cache = OrderedDict()
    _server_type_cache_lock = Lock()
    # Detection probes currently in flight, keyed by normalized base_url. An
    # entry exists only while its probe runs, so this is bounded by live
    # concurrency rather than by the number of distinct URLs ever seen.
    _server_type_flights = {}

    @classmethod
    def _normalize_server_type(cls, server_type):
        """Validate and normalize an explicit ``server_type`` value.

        :raise :class:`SecretServerError` when ``server_type`` is not one of
                ``VALID_SERVER_TYPES``.
        """
        normalized = str(server_type).strip().lower()
        if normalized not in cls.VALID_SERVER_TYPES:
            raise SecretServerError(
                f"Invalid server_type {server_type!r}; expected one of "
                f"{cls.VALID_SERVER_TYPES}."
            )
        return normalized

    # Shared state below is addressed as ``Authorizer.*``, never ``cls.*``:
    # there is one process-wide cache for every subclass.
    @staticmethod
    def _start_or_join_detection(key):
        """Resolve ``key`` against the cache and the flight registry at once.

        Returns ``(cached, flight, is_leader)``; ``flight`` is ``None`` on a hit
        and ``is_leader`` owns the probe. One acquisition closes the race.
        """
        with Authorizer._server_type_cache_lock:
            cache = Authorizer._server_type_cache
            if key in cache:
                cache.move_to_end(key)
                return cache[key], None, False
            flight = Authorizer._server_type_flights.get(key)
            if flight is not None:
                return None, flight, False
            flight = _DetectionFlight()
            Authorizer._server_type_flights[key] = flight
            return None, flight, True

    @staticmethod
    def _retire_flight(key, flight):
        """Drop ``flight`` from the registry if it is still the one registered.

        Call with the cache lock held. False means a waiter that gave up on it,
        or ``clear_server_type_cache``, already replaced or removed it.
        """
        if Authorizer._server_type_flights.get(key) is flight:
            del Authorizer._server_type_flights[key]
            return True
        return False

    @staticmethod
    def _finish_detection(key, flight, server_type, error):
        """Publish a flight's outcome, cache a success, and retire the flight.

        Only the flight still registered may write the cache: a retired one is
        stale, and last-write-wins would resurrect an answer already discarded.
        """
        flight.server_type = server_type
        flight.error = error
        try:
            with Authorizer._server_type_cache_lock:
                current = Authorizer._retire_flight(key, flight)
                if current and server_type is not None:
                    cache = Authorizer._server_type_cache
                    cache[key] = server_type
                    cache.move_to_end(key)
                    while len(cache) > Authorizer._SERVER_TYPE_CACHE_MAXSIZE:
                        cache.popitem(last=False)
        finally:
            # Waiters are released whatever happened above, or they would
            # sit on the event until their own timeout.
            flight.done.set()

    @staticmethod
    def clear_server_type_cache():
        """Clear the process-scoped server-detection cache.

        Cached for the life of the process with no TTL, so this is the escape
        hatch for a re-provisioned ``base_url``. Flights are dropped too.
        """
        with Authorizer._server_type_cache_lock:
            Authorizer._server_type_cache.clear()
            for flight in Authorizer._server_type_flights.values():
                flight.superseded = True  # its outcome no longer counts
            Authorizer._server_type_flights.clear()

    @staticmethod
    def add_bearer_token_authorization_header(bearer_token, existing_headers=None):
        """Adds an HTTP `Authorization` header containing the `Bearer` token

        :param existing_headers: a ``dict`` containing the existing headers
        :return: a ``dict`` containing the `existing_headers` and the
                `Authorization` header
        :rtype: ``dict``
        """

        return {
            "Authorization": "Bearer " + bearer_token,
            **(existing_headers or {}),
        }

    def _perform_server_detection(self, base_url, server_type=None):
        """Resolve whether the server is Secret Server or Platform.

        An explicit ``server_type`` applies to this instance only: no probe, and
        never cached, being unverified. Otherwise the probe pair runs once.
        """
        if server_type is not None:
            # Per-instance only; intentionally NOT seeded into the shared cache
            # so an unverified override cannot poison auto-detection for others.
            self._server_type = self._normalize_server_type(server_type)
            return

        self._server_type = self._detect_server_type_once(base_url.rstrip("/"))

    def _detect_server_type_once(self, key):
        """Return the server type for ``key``, probing at most once per flight.

        Waiters take the leader's type, or raise their own copy of its error so
        no traceback is rewritten. Past ``_DETECTION_WAIT_TIMEOUT`` they lead.
        """
        while True:
            cached, flight, is_leader = self._start_or_join_detection(key)
            if cached is not None:
                return cached
            if is_leader:
                return self._lead_detection(key, flight)

            if flight.done.wait(timeout=_DETECTION_WAIT_TIMEOUT):
                if flight.error is None:
                    return flight.server_type
                if flight.superseded:
                    # A clear or a takeover made this failure stale; the cache
                    # or the newer flight holds the current answer.
                    continue
                raise self._shared_failure(flight.error) from flight.error

            logger.warning(
                "Server-type detection for %s did not finish within %ss; "
                "probing again from this thread.",
                key,
                _DETECTION_WAIT_TIMEOUT,
            )
            with Authorizer._server_type_cache_lock:
                if Authorizer._retire_flight(key, flight):
                    flight.superseded = True

    def _lead_detection(self, key, flight):
        """Run the probe for a flight this caller registered, then publish it."""
        server_type = None
        error = None
        try:
            server_type = self._probe_server_type(key)
            return server_type
        except Exception as exc:
            error = exc
            if isinstance(exc, SecretServerError):
                raise
            # Waiters receive ``_shared_failure(exc)``; the leader must not see a
            # different type for the same failure just because it won the flight
            # registration. Latent today: the probe swallows every Exception.
            raise self._shared_failure(exc) from exc
        except BaseException:
            # KeyboardInterrupt and SystemExit belong to this thread alone.
            # Waiters get an ordinary error they can handle, not a foreign
            # interrupt raised in the middle of their own work.
            error = SecretServerError(
                "Server type detection was interrupted before it completed."
            )
            raise
        finally:
            self._finish_detection(key, flight, server_type, error)

    @staticmethod
    def _shared_failure(error):
        """A waiter's own exception carrying the leader's failure."""
        if isinstance(error, SecretServerError):
            try:
                return type(error)(error.message, error.response)
            except TypeError:
                # A subclass with its own constructor still shares the failure,
                # as the base type.
                return SecretServerError(error.message, error.response)
        return SecretServerError(
            f"Server type detection failed: {type(error).__name__}"
        )

    def _probe_server_type(self, base_url):
        """Probe the health-check endpoints and return the detected type.

        :raise :class:`SecretServerError` when neither endpoint reports a
                healthy status.
        """
        redirects = []
        if self._validate_health_endpoint(
            _join_url(base_url, "/api/v1/healthcheck"), redirects
        ):
            return "secret_server"
        if self._validate_health_endpoint(_join_url(base_url, "/health"), redirects):
            return "platform"
        if redirects:
            # An intercepted probe is a deployment problem, not an unhealthy
            # server. Saying so, and naming the way out, saves the caller from
            # debugging a health check that was never reached.
            target = next((where for where in redirects if where), None)
            destination = f" to {target}" if target else ""
            raise SecretServerError(
                "Unable to detect server type: the health check was redirected"
                f"{destination} (likely a login page). Pass "
                "server_type='secret_server' or 'platform' to skip detection."
            )
        raise SecretServerError(
            "Unable to detect server type via health check endpoints."
        )

    def _validate_health_endpoint(self, url, redirects=None):
        """Validates if an endpoint returns healthy status.

        Requires a 2xx and one of the two shapes the products emit: a
        ``healthy`` key -- in any case -- that is boolean ``true`` in a JSON
        object, or a body that is exactly ``healthy``.

        A 3xx is never a health answer, so redirects are not followed; each one
        is recorded in ``redirects`` (when given) for the caller's error.
        """
        try:
            response = requests.get(
                url, timeout=DEFAULT_REQUEST_TIMEOUT, allow_redirects=False
            )
        except Exception as exc:
            logger.debug("Health probe to %s failed: %s", url, type(exc).__name__)
            return False

        if 300 <= response.status_code < 400:
            # Following this lands on a login page whose 200 would otherwise
            # read as "unhealthy", hiding the fact that IIS intercepted us.
            logger.debug("Health probe to %s was redirected; not a health answer.", url)
            if redirects is not None:
                redirects.append(_redirect_target(response))
            return False

        # Explicit 2xx: ``response.ok`` is true for anything under 400, which
        # would admit a 3xx a proxy answered with a healthy-looking body.
        if not 200 <= response.status_code < 300:
            return False

        try:
            return self._body_reports_healthy(response)
        except Exception as exc:
            # An unreadable body means "not healthy, try the next endpoint",
            # never "abort detection". The helper's narrow ``ValueError`` catch
            # is for the JSON parse; anything else must not end detection here.
            logger.debug(
                "Health body from %s was unreadable: %s", url, type(exc).__name__
            )
            return False

    @staticmethod
    def _body_reports_healthy(response):
        """Whether a 2xx health-check body reports a healthy server.

        A JSON object whose ``healthy`` key -- in any case -- is boolean
        ``true`` (Secret Server), or a body that is exactly ``healthy``
        (Platform). Anything else is not.
        """
        try:
            json_data = response.json()
        except ValueError:
            json_data = None

        if isinstance(json_data, Mapping):
            # Secret Server documents the key as ``healthy``; builds in the
            # field have also been seen sending ``Healthy``. Only the *key* is
            # matched caselessly -- the value stays strict, so ``"true"`` and
            # ``1`` remain unhealthy, and ``databaseHealthy`` is not this key.
            reported = [
                value
                for key, value in json_data.items()
                if isinstance(key, str) and key.casefold() == "healthy"
            ]
            return bool(reported) and all(value is True for value in reported)
        if json_data is not None:
            return False

        return response.text.strip().lower() == "healthy"

    @abstractmethod
    def get_access_token(self):
        """Returns the access_token from a Grant Request"""

    def headers(self, existing_headers=None):
        """Returns a dictionary containing headers for REST API calls"""
        return self.add_bearer_token_authorization_header(
            self.get_access_token(), existing_headers
        )


class AccessTokenAuthorizer(Authorizer):
    """Allows the use of a pre-existing access token to authorize REST API
    calls.
    """

    def get_access_token(self):
        return self.access_token

    # Same policy as PasswordGrantAuthorizer: a pickle leaves the process and
    # this holds a live bearer token. ``copy`` shares the reduce protocol, so
    # refusing that alone would break copy/deepcopy; both are defined below.

    def __copy__(self):
        clone = self.__class__.__new__(self.__class__)
        clone.__dict__.update(self.__dict__)
        return clone

    def __deepcopy__(self, memo):
        clone = self.__class__.__new__(self.__class__)
        memo[id(self)] = clone
        clone.__dict__.update(copy.deepcopy(self.__dict__, memo))
        return clone

    def __reduce__(self):
        raise TypeError(
            f"{self.__class__.__name__} holds a live bearer token and cannot be "
            "pickled. Construct one from configuration in the target process "
            "instead; use copy.deepcopy() for an in-memory copy."
        )

    def __init__(self, access_token, base_url, *, server_type=None):
        """
        :param server_type: optionally ``"secret_server"`` or ``"platform"`` to
                skip health-check detection entirely (no probe is issued).
        """
        self.access_token = access_token
        self.base_url = base_url.rstrip("/")
        _warn_if_insecure(self.base_url)
        if server_type is None:
            # No keyword, so a subclass that still overrides the original
            # one-argument hook keeps working.
            self._perform_server_detection(self.base_url)
        else:
            self._perform_server_detection(self.base_url, server_type=server_type)


class PasswordGrantAuthorizer(Authorizer):
    """Allows the use of a username and password to be used to authorize REST
    API calls.
    """

    TOKEN_PATH_URI = "/oauth2/token"
    PLATFORM_TOKEN_PATH_URI = "/identity/api/oauth2/token/xpmplatform"

    @staticmethod
    def get_access_grant(token_url, grant_request):
        """Gets an *OAuth2 Access Grant* by calling the Secret Server REST API
        ``token`` endpoint

        :raise :class:`SecretServerError` when the server returns anything
                other than a valid Access Grant
        """

        response = requests.post(
            token_url, grant_request, timeout=DEFAULT_REQUEST_TIMEOUT
        )

        try:  # TSS returns a 200 (OK) containing HTML for some error conditions
            # ``or b""``: ``.content`` is None when ``raw`` is, and
            # ``json.loads`` answers that with TypeError, not ValueError.
            grant = json.loads(SecretServer.process(response).content or b"")
        except ValueError:
            raise SecretServerError(
                "Token endpoint did not return a JSON access grant "
                f"({_describe_response(response)})",
                response,
            )

        # A 200 can also carry a JSON *error* body, or JSON that is not an object.
        # Reject those here, quoting the server's own explanation, rather than
        # storing them and failing later with a KeyError in get_access_token().
        token = grant.get("access_token") if isinstance(grant, Mapping) else None
        if not isinstance(token, str) or not token:
            detail = None
            if isinstance(grant, Mapping):
                detail = grant.get("error_description") or grant.get("error")
            if isinstance(detail, str) and detail:
                detail = _safe_body_excerpt(detail)
            else:
                detail = _describe_response(response)  # already capped
            raise SecretServerError(
                f"Token endpoint did not return an access grant: {detail}",
                response,
            )
        return _with_validated_expires_in(grant, response)

    def _grant_is_fresh(self, seconds_of_drift):
        """Whether the stored grant can be used without a token request.

        Safe to call unlocked: a half-written pair, a naive timestamp (the
        pre-2.1 convention) or a non-datetime one simply reads as stale.
        """
        grant = getattr(self, "access_grant", None)
        refreshed = getattr(self, "access_grant_refreshed", None)
        if grant is None or getattr(refreshed, "tzinfo", None) is None:
            return False
        validity = self._grant_validity_seconds(grant, seconds_of_drift)
        return refreshed + timedelta(seconds=validity) > datetime.now(timezone.utc)

    def _refresh(self, seconds_of_drift=300):
        """Refresh the *OAuth2 Access Grant* if it expires within `seconds_of_drift`.

        A fresh grant is used without taking ``_refresh_lock``, so callers are
        never stalled behind another thread's token request; one refresher.

        :raise :class:`SecretServerError` when the server returns anything other
               than a valid Access Grant
        """
        if self._grant_is_fresh(seconds_of_drift):
            return

        with self._refresh_lock:
            if self._grant_is_fresh(seconds_of_drift):
                return  # another thread refreshed while we waited

            # Detect the server type if not already resolved.
            if not hasattr(self, "_server_type"):
                self._perform_server_detection(self.base_url)

            # Decide token_path_uri if not provided.
            if not self.token_path_uri:
                # Resolved through ``self`` so a subclass that overrides either
                # constant -- the pre-existing extension point -- is honoured.
                self.token_path_uri = (
                    self.PLATFORM_TOKEN_PATH_URI
                    if self._server_type == "platform"
                    else self.TOKEN_PATH_URI
                )

            self.token_url = _join_url(self.base_url, self.token_path_uri)

            if self._server_type == "secret_server":
                grant_request = {
                    "username": self.username,
                    "password": self.password,
                    "grant_type": "password",
                }
                if self.domain:
                    grant_request["domain"] = self.domain
            else:
                grant_request = {
                    "client_id": self.username,
                    "client_secret": self.password,
                    "grant_type": "client_credentials",
                    "scope": "xpmheadless",
                }

            grant = self.get_access_grant(self.token_url, grant_request)
            lifetime = _expires_in_seconds(grant.get("expires_in"))
            if (
                lifetime is not None
                and lifetime < 1
                and not self._short_lifetime_warned
            ):
                # Once per authorizer, not once per call: with no reuse window
                # every API call is a token request, and a warning per call
                # would flood the log with the same message.
                self._short_lifetime_warned = True
                logger.warning(
                    "Access grant expires_in is %s; with no reuse window the token "
                    "will be re-requested on every API call until the server sends "
                    "a lifetime of at least one second.",
                    _safe_body_excerpt(repr(grant.get("expires_in"))),
                )
            # Ordinary assignments, so a subclass property or slot still works;
            # grant first, timestamp second, because ``_copy_with_fresh_lock``
            # snapshots unlocked and must not pair a stale grant with a new stamp.
            self.access_grant = grant
            self.access_grant_refreshed = datetime.now(timezone.utc)

    def __init__(
        self,
        base_url,
        username,
        password,
        token_path_uri=None,
        domain=None,
        *,
        server_type=None,
    ):
        """
        :param server_type: optionally ``"secret_server"`` or ``"platform"`` to
                skip health-check detection entirely (no probe is issued); the
                matching token endpoint is selected without probing.
        """
        self.base_url = base_url.rstrip("/")
        _warn_if_insecure(self.base_url)
        self.username = username
        self.password = password
        self.domain = domain
        self.token_path_uri = token_path_uri  # May be None, will decide in _refresh
        self.token_url = None
        self._short_lifetime_warned = False
        self._refresh_lock = Lock()
        # When an explicit type is given, resolve it now (no network) so the
        # lazy detection in _refresh is skipped and no probe is ever issued.
        if server_type is not None:
            self._perform_server_detection(self.base_url, server_type=server_type)

    @staticmethod
    def _grant_validity_seconds(access_grant, seconds_of_drift):
        """Seconds a grant is reused before a proactive refresh.

        ``seconds_of_drift`` before expiry, never sooner than half the lifetime.
        The non-numeric fallbacks matter only for a grant assigned by hand.
        """
        expires_in = _expires_in_seconds(
            access_grant.get("expires_in", _DEFAULT_GRANT_LIFETIME_SECONDS)
        )
        if expires_in is None or expires_in <= 0:
            return 0.0
        expires_in = min(expires_in, _MAX_GRANT_LIFETIME_SECONDS)
        return max(expires_in - seconds_of_drift, expires_in / 2)

    # Copying is supported, serialization is refused -- deliberately. ``copy``
    # hands out an independent authorizer with its own refresh lock; a pickle
    # would write the plaintext password and bearer token wherever it goes.

    def _copy_with_fresh_lock(self, deep, memo=None):
        clone = self.__class__.__new__(self.__class__)
        if memo is not None:
            memo[id(self)] = clone
        # Snapshot WITHOUT ``_refresh_lock``: taking it would deadlock a copy
        # made from code already holding it. ``dict()`` cannot tear, but can
        # land mid-publish, so an incomplete grant pair is dropped below.
        state = dict(self.__dict__)
        state.pop("_refresh_lock", None)
        if ("access_grant" in state) != ("access_grant_refreshed" in state):
            state.pop("access_grant", None)
            state.pop("access_grant_refreshed", None)
        for name, value in state.items():
            clone.__dict__[name] = copy.deepcopy(value, memo) if deep else value
        clone._refresh_lock = Lock()
        return clone

    def __copy__(self):
        return self._copy_with_fresh_lock(deep=False)

    def __deepcopy__(self, memo):
        return self._copy_with_fresh_lock(deep=True, memo=memo)

    def __reduce__(self):
        raise TypeError(
            f"{self.__class__.__name__} holds live credentials and cannot be "
            "pickled. Construct one from configuration in the target process "
            "instead; use copy.deepcopy() for an in-memory copy."
        )

    def get_access_token(self):
        self._refresh()
        return self.access_grant["access_token"]


class DomainPasswordGrantAuthorizer(PasswordGrantAuthorizer):
    """Allows domain access to be used to authorize REST API calls."""

    def __init__(
        self,
        base_url,
        username,
        domain,
        password,
        token_path_uri=None,
        *,
        server_type=None,
    ):
        super().__init__(
            base_url,
            username,
            password,
            token_path_uri=token_path_uri,
            domain=domain,
            server_type=server_type,
        )


class SecretServer:
    """A class that uses an *OAuth2 Bearer Token* to access the Secret Server
    REST API. It uses the and `Authorizer` to determine the Authorization
    method required to access the Secret Server at :attr:`base_url`.

    It gets an ``access_token`` that it uses to create an *HTTP Authorization
    Header* which it includes in each REST API call.
    """

    API_PATH_URI = "/api/v1"

    @staticmethod
    def process(response):
        """Process the response raising an error if the call was unsuccessful

        :return: the response if the call was successful
        :rtype: :class:`~requests.Response`
        :raises: :class:`SecretServerAccessError` when the caller does not have
                access to the secret
        :raises: :class:`SecretsAccessError` when the server responses with any
                other error
        """

        if response.status_code >= 200 and response.status_code < 300:
            return response
        if response.status_code >= 400 and response.status_code < 500:
            # Fallback used when the body is JSON but carries no recognized
            # message/error key, or is JSON that is not an object at all
            # (``null``, a number, a string, a list).
            message = f"HTTP {response.status_code}"
            try:
                content = json.loads(response.content or b"")
            except ValueError:
                # Keep the status and a sanitized body hint. The JSON parser's
                # own complaint gave messages like "Expecting value", dropping
                # the status code and any clue about what the server returned.
                message = _describe_response(response)
            else:
                if isinstance(content, Mapping):
                    if isinstance(content.get("message"), str):
                        message = content["message"]
                    elif isinstance(content.get("error"), str):
                        message = content["error"]
            raise SecretServerClientError(message, response)
        else:
            raise SecretServerServiceError(_describe_response(response), response)

    def headers(self):
        """Returns a dictionary containing HTTP headers."""
        return self.authorizer.headers()

    def __init__(
        self,
        base_url,
        authorizer: Authorizer,
        api_path_uri=API_PATH_URI,
    ):
        """
        :param base_url: The base URL e.g. ``https://localhost/SecretServer``
        :type base_url: str
        :param authorizer: The authorization method to be used
        :type authorizer: Authorizer
        :param api_path_uri: Defaults to ``/api/v1``
        :type api_path_uri: str
        """
        self.base_url = base_url.rstrip("/")
        # An authorizer built for this same URL already warned; a second
        # identical warning only ever shows up under ``-W always``.
        if getattr(authorizer, "base_url", None) != self.base_url:
            _warn_if_insecure(self.base_url)
        self.platform_url = self.base_url
        self.authorizer = authorizer
        self._api_path_uri = api_path_uri
        self._vault_url_fetched = False

    @property
    def api_url(self):
        return _join_url(self.base_url, self._api_path_uri)

    def ensure_vault_url(self):
        """For platform, fetch and set the vault URL before making API calls.

        Safe in any order relative to :meth:`headers`, which resolves the token
        and so makes a lazy authorizer learn its type. Remembered per instance.
        """
        if self._vault_url_fetched:
            return

        headers = None
        server_type = getattr(self.authorizer, "_server_type", None)
        if server_type is None:
            # A lazily detected authorizer learns its type while resolving the
            # token; resolve it once here rather than again in ``_get``.
            headers = self.headers()
            server_type = getattr(self.authorizer, "_server_type", None)
        if server_type != "platform":
            # Secret Server is addressed at base_url directly; nothing to switch.
            self._vault_url_fetched = True
            return
        if headers is None:
            headers = self.headers()

        vaults_endpoint = _join_url(self.platform_url, "/vaultbroker/api/vaults")
        resp = requests.get(
            vaults_endpoint, headers=headers, timeout=DEFAULT_REQUEST_TIMEOUT
        )
        if resp.status_code != 200:
            raise SecretServerError(
                f"Failed to fetch vault details: {_describe_response(resp)}", resp
            )
        try:
            data = resp.json()
        except Exception as ex:
            raise SecretServerError(f"Failed to parse vault details: {ex}", resp)
        vaults = data.get("vaults") if isinstance(data, Mapping) else None
        if not isinstance(vaults, list):
            raise SecretServerError(
                f"Vault details did not contain a 'vaults' list: {_describe_response(resp)}",
                resp,
            )
        for vault in vaults:
            if not isinstance(vault, Mapping):
                continue
            if not (vault.get("isDefault") and vault.get("isActive")):
                continue
            conn = vault.get("connection")
            url = conn.get("url") if isinstance(conn, Mapping) else None
            if not url:
                continue
            hostname, vault_url = _validated_vault_url(url, resp)
            # ``hostname`` rather than the URL: userinfo must not reach the log.
            logger.info(
                "Switching base_url to platform vault connection URL at %s", hostname
            )
            self.base_url = vault_url
            self._vault_url_fetched = True
            return
        raise SecretServerError(
            "No configured default and active vault found in vault details."
        )

    def _get(self, path, params=None):
        """Issue an authenticated ``GET`` for ``path`` under :attr:`api_url`.

        The single owner of the read contract: vault switch, headers, timeout
        and :meth:`process`. ``params`` takes any form ``requests`` accepts.
        """
        self.ensure_vault_url()
        return self.process(
            requests.get(
                _join_url(self.api_url, path),
                params=params,
                headers=self.headers(),
                timeout=DEFAULT_REQUEST_TIMEOUT,
            )
        )

    def _get_json(self, path, what, params=None, *, redact_body=False):
        """``_get`` plus JSON parsing; returns ``(data, response)``.

        A body that is not a JSON object raises :class:`SecretServerError`
        naming ``what``, response attached, body excerpted unless ``redact_body``.
        """
        response = self._get(path, params=params)
        try:
            data = json.loads(response.content or b"")
        except ValueError:
            problem = "did not return JSON"
        else:
            if isinstance(data, Mapping):
                return data, response
            problem = "did not return a JSON object"
        if redact_body:  # the body may be secret; the status never is
            detail = f": HTTP {response.status_code}"
        else:
            detail = f": {_describe_response(response)}"
        raise SecretServerError(f"{what} {problem}{detail}", response)

    def get_secret_json(self, id, query_params=None):
        """Gets a Secret from Secret Server

        :param id: the id of the secret
        :type id: int
        :param query_params: query parameters to pass to the endpoint
        :type query_params: dict
        :return: a JSON formatted string representation of the secret
        :rtype: ``str``
        :raise: :class:`SecretServerAccessError` when the caller does not have
                permission to access the secret
        :raise: :class:`SecretServerError` when the REST API call fails for
                any other reason
        """
        return self._get(f"/secrets/{id}", params=query_params).text

    def get_folder_json(self, id, query_params=None, get_all_children=True):
        """Gets a Folder from Secret Server

        :param id: the id of the folder
        :type id: int
        :param query_params: query parameters to pass to the endpoint
        :type query_params: dict
        :return: a JSON formatted string representation of the folder
        :rtype: ``str``
        :raise: :class:`SecretServerAccessError` when the caller does not have
                permission to access the folder
        :raise: :class:`SecretServerError` when the REST API call fails for
                any other reason
        """
        if get_all_children:
            # A copy of the caller's params with the flag sent once and winning,
            # in whatever form ``requests`` accepts.
            query_params = _with_query_flag(query_params, "getAllChildren", "true")
        return self._get(f"/folders/{id}", params=query_params).text

    def get_secret(self, id, fetch_file_attachments=True, query_params=None):
        """Gets a secret

        :param id: the id of the secret
        :type id: int
        :param fetch_file_attachments: whether or not to fetch file attachments
                                       and replace itemValue with the contents
                                       for each item (field), automatically
        :type fetch_file_attachments: bool
        :param query_params: query parameters to pass to the endpoint
        :type query_params: dict
        :return: a ``dict`` representation of the secret
        :rtype: ``dict``
        :raise: :class:`SecretServerAccessError` when the caller does not have
                permission to access the secret
        :raise: :class:`SecretServerError` when the REST API call fails for
                any other reason
        """

        # The secrets endpoint: never echo its body into an error message,
        # since it may contain secret field values.
        secret, secret_response = self._get_json(
            f"/secrets/{id}", "Secret endpoint", params=query_params, redact_body=True
        )

        if fetch_file_attachments:
            # Each attachment goes through _get, which rebuilds headers: a lock
            # and a comparison unless a refresh is due. Refreshing mid-burst
            # beats sending the rest an expired token and failing them with 401.
            items = _required_records(
                secret, "items", "Secret endpoint", secret_response
            )
            for item in items:
                if item.get("fileAttachmentId"):
                    slug = item.get("slug")
                    if not isinstance(slug, str) or not slug:
                        raise SecretServerError(
                            "Secret endpoint returned a file field with no 'slug'",
                            secret_response,
                        )
                    response = self._get(
                        f"/secrets/{id}/fields/{slug}", params=query_params
                    )
                    item["itemValue"] = FileAttachment(
                        response.content or b"",
                        encoding=getattr(response, "encoding", None),
                        filename=item.get("filename"),
                    )
        return secret

    def get_folder(self, id, query_params=None, get_all_children=False):
        """Gets a folder

        :param id: the id of the folder
        :type id: int
        :param getAllChildren: Whether to retrieve all child folders of the requested folder
        :type fetch_file_attachments: bool
        :param query_params: query parameters to pass to the endpoint
        :type query_params: dict
        :return: a ``dict`` representation of the folder
        :rtype: ``dict``
        :raise: :class:`SecretServerAccessError` when the caller does not have
                permission to access the folder
        :raise: :class:`SecretServerError` when the REST API call fails for
                any other reason
        """

        if get_all_children:
            query_params = _with_query_flag(query_params, "getAllChildren", "true")
        folder, _ = self._get_json(
            f"/folders/{id}", "Folder endpoint", params=query_params
        )
        return folder

    def get_secret_by_path(self, secret_path, fetch_file_attachments=True):
        """Gets a secret by path

        :param secret_path: full path of the secret
        :type secret_path: str
        :param fetch_file_attachments: whether or not to fetch file attachments
                                       and replace itemValue with the contents
                                       for each item (field), automatically
        :type fetch_file_attachments: bool
        :return: a ``dict`` representation of the secret
        :rtype: ``dict``
        """
        path = "\\" + re.sub(r"[\\/]+", r"\\", secret_path).lstrip("\\").rstrip("\\")

        params = {"secretPath": path}
        return self.get_secret(
            id=0,
            fetch_file_attachments=fetch_file_attachments,
            query_params=params,
        )

    def get_folder_by_path(self, folder_path, get_all_children=True):
        """Gets a folder by path

        :param folder_path: full path of the folder
        :type folder_path: str
        :return: a ``dict`` representation of the folder
        :rtype: ``dict``
        """
        path = "\\" + re.sub(r"[\\/]+", r"\\", folder_path).lstrip("\\").rstrip("\\")

        params = {"folderPath": path}
        return self.get_folder(
            id=0,
            get_all_children=get_all_children,
            query_params=params,
        )

    def search_secrets(self, query_params=None):
        """Get Secrets from Secret Server

        :param query_params: query parameters to pass to the endpoint
        :type query_params: dict
        :return: a JSON formatted string representation of the secrets
        :rtype: ``str``
        :raise: :class:`SecretServerAccessError` when the caller does not have
                permission to access the secret
        :raise: :class:`SecretServerError` when the REST API call fails for
                any other reason
        """
        return self._get("/secrets", params=query_params).text

    def lookup_folders(self, query_params=None):
        """Lookup Folders from Secret Server

        :param query_params: query parameters to pass to the endpoint
        :type query_params: dict
        :return: a JSON formatted string representation of the folders, containing only id and name
        :rtype: ``str``
        :raise: :class:`SecretServerAccessError` when the caller does not have
                permission to access the secret
        :raise: :class:`SecretServerError` when the REST API call fails for
                any other reason
        """
        return self._get("/folders/lookup", params=query_params).text

    def get_secret_ids_by_folderid(self, folder_id):
        """Gets a list of secrets ids by folder_id

        :param folder_id: the id of the folder
        :type id: int
        :return: a ``list`` of the secret id's
        :rtype: ``list``
        :raise: :class:`SecretServerAccessError` when the caller does not have
                permission to access the secret
        :raise: :class:`SecretServerError` when the REST API call fails for
                any other reason
        """
        params = {"filter.folderId": folder_id}
        total_response = self._get("/secrets/search-total", params=params)
        try:
            params["take"] = int(total_response.text)
        except ValueError:
            raise SecretServerError(
                f"Unexpected non-numeric secrets count from search-total: "
                f"{_safe_body_excerpt(total_response.text)}",
                total_response,
            )
        secrets, response = self._get_json("/secrets", "Secrets search", params=params)

        return _record_ids(
            _required_records(secrets, "records", "Secrets search", response),
            "Secrets search",
            response,
        )

    def get_child_folder_ids_by_folderid(self, folder_id):
        """Gets a list of child folder ids by folder_id
        :param folder_id: the id of the folder
        :type id: int
        :return: a ``list`` of the child folder id's
        :rtype: ``list``
        :raise: :class:`SecretServerAccessError` when the caller does not have
                permission to access the secret
        :raise: :class:`SecretServerError` when the REST API call fails for
                any other reason
        """
        params = {
            "filter.parentFolderId": folder_id,
            "filter.limitToDirectDescendents": True,
        }
        params["take"] = 1

        lookup, lookup_response = self._get_json(
            "/folders/lookup", "Folder lookup", params=params
        )
        total = lookup.get("total")
        if isinstance(total, bool) or not isinstance(total, int):
            raise SecretServerError(
                "Folder lookup did not return an integer 'total': "
                f"{_safe_body_excerpt(repr(total))}",
                lookup_response,
            )
        if total == 0:
            return []
        params["take"] = total
        page, response = self._get_json(
            "/folders/lookup", "Folder lookup", params=params
        )
        records = _required_records(page, "records", "Folder lookup", response)
        return _record_ids(records, "Folder lookup", response)


class SecretServerV0(SecretServer):
    """A class that uses an *OAuth2 Bearer Token* to access the Secret Server
    REST API. It uses the :attr:`username` and :attr:`password` to access the
    Secret Server at :attr:`base_url`.

    It gets an ``access_token`` that it uses to create an *HTTP Authorization
    Header* which it includes in each REST API call.

    This class maintains backwards compatibility with v0.0.5
    """

    def __init__(
        self,
        base_url,
        username,
        password,
        api_path_uri=SecretServer.API_PATH_URI,
        token_path_uri=None,
        *,
        server_type=None,
    ):
        """
        :param server_type: optionally ``"secret_server"`` or ``"platform"`` to
                skip health-check detection, as on the authorizers.
        """
        super().__init__(
            base_url,
            PasswordGrantAuthorizer(
                base_url, username, password, token_path_uri, server_type=server_type
            ),
            api_path_uri,
        )


class SecretServerCloud(SecretServer):
    """A class that uses bearer token authentication to access the Secret
    Server Cloud REST API.

    It uses :attr:`tenant`, :attr:`tld` with :attr:`SERVER_URL_TEMPLATE`,
    to create request URLs.

    It uses the :attr:`username` and :attr:`password` to get an access_token
    from Secret Server Cloud which it uses to make calls to the REST API.
    """

    DEFAULT_TLD = "com"
    URL_TEMPLATE = "https://{}.secretservercloud.{}"

    def __init__(self, tenant=None, authorizer=None, tld=DEFAULT_TLD, base_url=None):
        if authorizer is None or not isinstance(authorizer, Authorizer):
            raise ValueError(
                "authorizer must be provided and must be of type Authorizer"
            )
        if tenant:
            url = self.URL_TEMPLATE.format(tenant, tld)
        elif base_url:
            url = base_url.rstrip("/")
        else:
            raise ValueError("Must provide either tenant or base_url")
        super().__init__(url, authorizer)
