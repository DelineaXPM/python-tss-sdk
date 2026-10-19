"""Offline unit tests for the Phase 4 housekeeping fixes (see PR #98).

Covers thread-safe refresh, timezone-aware expiry, mutable default arguments,
``get_folder_json`` with no params, attachment bytes and non-numeric totals.
"""

import copy
import json
import pickle
import threading
import warnings
from datetime import datetime, timedelta, timezone

import pytest
import requests

from delinea.secrets.server import (
    AccessTokenAuthorizer,
    Authorizer,
    FileAttachment,
    PasswordGrantAuthorizer,
    SecretServer,
    SecretServerClientError,
    SecretServerError,
    SecretServerV0,
)
from fakes import (
    HTTP_GET,
    HTTP_POST,
    AttachmentResponse,
    EncodinglessResponse,
    FakeResponse,
    fake_token_post,
    health_response,
    join_all,
    make_grant_authorizer,
    make_server,
    vault_broker_response,
)

# Shared fixtures from tests/conftest.py: fail loudly on an unmocked HTTP
# call, and isolate the process-global server-detection cache.
pytestmark = pytest.mark.usefixtures("no_network", "clear_detection_cache")


# ---------------------------------------------------------------------------
# 4.1 / 4.2: thread-safe, UTC-aware token refresh
# ---------------------------------------------------------------------------


def test_refresh_is_thread_safe_and_grants_once(monkeypatch):
    """20 threads on a fresh authorizer must grant exactly once: the first in
    holds ``_refresh_lock`` while it fetches, the rest then find a valid grant.
    The fetch is held open so they pile up; an instant fake hid a missing lock.
    """
    import time

    grant_calls = {"count": 0}

    def fake_get_access_grant(token_url, grant_request):
        grant_calls["count"] += 1
        time.sleep(0.05)
        return {"access_token": f"tok-{grant_calls['count']}", "expires_in": 1200}

    auth = make_grant_authorizer()
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

    threads = [threading.Thread(target=worker, daemon=True) for _ in range(20)]
    for t in threads:
        t.start()
    start.set()
    join_all(threads)

    assert errors == []
    assert len(results) == 20
    # No thread must observe a torn/partial access_grant.
    assert all(r == results[0] for r in results)
    assert grant_calls["count"] == 1


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
    auth = make_grant_authorizer()
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
        calls.append((url, kwargs.get("params")))
        return FakeResponse(json_data={"id": 1})

    monkeypatch.setattr(HTTP_GET, fake_get)

    server = make_server("https://ss.example.com", "secret_server")

    # No query_params, default get_all_children=True: must not raise TypeError.
    result = server.get_folder_json(1)
    assert result == '{"id": 1}'
    url, params = calls[-1]
    assert url.endswith("/folders/1")
    assert params == {"getAllChildren": "true"}


# ---------------------------------------------------------------------------
# 4.5: file-attachment itemValue is the file, not a Response object
# ---------------------------------------------------------------------------


# Passed as a field's encoding to get a response object that has none.
_NO_ENCODING = object()

# The one-file secret most of these tests want.
_ONE_FILE = ("file-slug", b"file-bytes", None, None)


class _InitAttachment(FileAttachment):
    """A subclass whose ``__init__`` alone takes an argument of its own.

    Rebuilding through ``__new__`` must not re-run it. At module level so
    ``pickle`` can find it by name.
    """

    def __new__(cls, data, extra=None, **kwargs):
        return super().__new__(cls, data, **kwargs)

    def __init__(self, data, extra, **kwargs):
        self.extra = extra


class _TaggedAttachment(FileAttachment):
    """An attachment subclass with an attribute of its own.

    At module level so ``pickle`` can find it by name.
    """

    def __new__(cls, data, tag=None, **kwargs):
        attachment = super().__new__(cls, data, **kwargs)
        attachment.tag = tag
        return attachment


def _attachment_server(monkeypatch, files, seen=None, statuses=None):
    """Build a server whose secret has the given file fields and a password.

    ``files`` holds ``(slug, content, filename, encoding)`` per file; ``seen``
    records ``(slug, params)`` per request, ``"secret"`` for the body itself.
    """
    fields = []
    for index, (slug, content, filename, encoding) in enumerate(files, start=11):
        field = {"fileAttachmentId": index, "slug": slug, "itemValue": None}
        if filename is not None:
            field["filename"] = filename
        fields.append((field, content, encoding))
    password = {"fileAttachmentId": 0, "slug": "password", "itemValue": "p@ss"}

    def fake_get(url, *args, **kwargs):
        for field, content, encoding in fields:
            if not url.endswith(f"/fields/{field['slug']}"):
                continue
            if seen is not None:
                seen.append((field["slug"], kwargs.get("params")))
            status = (statuses or {}).get(field["slug"], 200)
            if status != 200:
                return FakeResponse(status_code=status, json_data={"message": "no"})
            if encoding is _NO_ENCODING:
                return EncodinglessResponse(content)
            return AttachmentResponse(content, encoding=encoding)
        if seen is not None:
            seen.append(("secret", kwargs.get("params")))
        items = [field for field, _, _ in fields] + [password]
        return FakeResponse(json_data={"id": 7, "items": items})

    monkeypatch.setattr(HTTP_GET, fake_get)
    return make_server("https://ss.example.com", "secret_server")


def _fetch_attachment(monkeypatch, content, encoding=None, filename=None):
    files = [("file-slug", content, filename, encoding)]
    server = _attachment_server(monkeypatch, files)
    secret = server.get_secret(1, fetch_file_attachments=True)
    return secret["items"][0]["itemValue"]


def test_file_attachment_item_value_is_the_file_bytes(monkeypatch):
    """Never the ``Response``: its repr used to be what got stored."""
    item_value = _fetch_attachment(monkeypatch, b"file-bytes")

    assert isinstance(item_value, bytes)
    assert isinstance(item_value, FileAttachment)
    assert item_value == b"file-bytes"


def test_file_attachment_exposes_content_and_text(monkeypatch):
    """The two accessors consumers of the old ``Response`` already call."""
    item_value = _fetch_attachment(monkeypatch, b"file-bytes")

    assert item_value.content == b"file-bytes"
    assert type(item_value.content) is bytes
    assert item_value.text == "file-bytes"


def test_binary_file_attachment_is_written_back_byte_for_byte(monkeypatch, tmp_path):
    """The Ansible community.general tss flow: read ``.content``, write "wb".

    These bytes are not valid UTF-8, so the previous ``.text`` lost them.
    """
    png = b"\x89PNG\r\n\x1a\n\xff\xfe\x00binary"

    item_value = _fetch_attachment(monkeypatch, png)

    destination = tmp_path / "1_file-slug"
    with open(destination, "wb") as handle:
        handle.write(item_value.content)
    assert destination.read_bytes() == png


def test_file_attachment_text_falls_back_to_the_declared_latin_1(monkeypatch):
    """Not valid UTF-8, so the strict attempt fails and Latin-1 is used."""
    item_value = _fetch_attachment(
        monkeypatch, "caf\u00e9".encode("iso-8859-1"), encoding="iso-8859-1"
    )

    assert item_value.text == "caf\u00e9"


def test_file_attachment_text_decodes_a_declared_multibyte_charset(monkeypatch):
    """A charset the server really declared must be honoured as given."""
    item_value = _fetch_attachment(
        monkeypatch, "caf\u00e9".encode("utf-16"), encoding="utf-16"
    )

    assert item_value.text == "caf\u00e9"


def test_attachment_response_without_an_encoding_attribute(monkeypatch):
    """The call site reads it with ``getattr``, so a missing one is ``None``."""
    assert not hasattr(EncodinglessResponse(b""), "encoding")

    item_value = _fetch_attachment(monkeypatch, b"file-bytes", encoding=_NO_ENCODING)

    assert item_value.encoding is None
    assert item_value.text == "file-bytes"


@pytest.mark.parametrize("declared", ["ISO-8859-1", "latin1", "cp819", "8859"])
def test_file_attachment_text_prefers_utf8_over_a_declared_latin_1(
    monkeypatch, declared
):
    """``requests`` labels every charset-less ``text/*`` body Latin-1.

    Taking that at face value turns a UTF-8 text attachment into mojibake,
    whichever of the codec's many aliases the server happened to send.
    """
    item_value = _fetch_attachment(
        monkeypatch, "caf\u00e9".encode("utf-8"), encoding=declared
    )

    assert item_value.text == "caf\u00e9"


def test_file_attachment_text_replaces_what_the_declared_charset_rejects(monkeypatch):
    """``errors="replace"`` on the declared codec, not a silent UTF-8 retry."""
    item_value = _fetch_attachment(
        monkeypatch, "caf\u00e9".encode("utf-8"), encoding="ascii"
    )

    assert item_value.text == "caf\ufffd\ufffd"


def test_attachment_with_an_unreadable_body_is_empty_not_a_crash(monkeypatch):
    """``Response.content`` is ``None`` when ``raw`` is, which ``process``
    does not screen; the ``.text`` this replaced returned ``""`` there.
    """
    item_value = _fetch_attachment(monkeypatch, None)

    assert item_value == b""
    assert item_value.text == ""


def test_file_attachment_text_survives_a_non_string_declared_charset(monkeypatch):
    """``bytes.decode`` raises ``TypeError``, not ``LookupError``, on these."""
    item_value = _fetch_attachment(monkeypatch, b"file-bytes", encoding=b"utf-8")

    assert item_value.text == "file-bytes"


def test_zero_byte_attachment_is_an_empty_attachment(monkeypatch):
    """Empty, not missing: falsy as bytes, so callers must test the id."""
    item_value = _fetch_attachment(monkeypatch, b"", filename="empty.txt")

    assert isinstance(item_value, FileAttachment)
    assert item_value.content == b""
    assert item_value.text == ""
    assert not item_value
    assert repr(item_value) == "<FileAttachment 'empty.txt': 0 bytes>"


def test_file_attachment_text_survives_an_unusable_declared_charset(monkeypatch):
    """An unknown codec falls back to UTF-8 rather than raising at access."""
    item_value = _fetch_attachment(
        monkeypatch, "caf\u00e9".encode("utf-8"), encoding="not-a-real-codec"
    )

    assert item_value.text == "caf\u00e9"


def test_file_attachment_text_replaces_undecodable_bytes(monkeypatch):
    """``.text`` must not raise on a binary attachment; ``.content`` is exact."""
    item_value = _fetch_attachment(monkeypatch, b"\xff\xfe\x00")

    assert "\ufffd" in item_value.text
    assert item_value.content == b"\xff\xfe\x00"


def test_file_attachment_repr_withholds_the_contents(monkeypatch):
    """``bytes``' own repr would put a whole attachment in any log line.

    The released SDK stored a ``Response``, whose repr also withheld it.
    """
    item_value = _fetch_attachment(
        monkeypatch, b"super-secret-key-material", filename="id_rsa"
    )

    for rendered in (repr(item_value), str(item_value), f"{item_value}"):
        assert "secret-key-material" not in rendered
        assert "id_rsa" in rendered
        assert "25 bytes" in rendered


def test_file_attachment_is_constructible_with_bytes_alone():
    """Both keyword arguments are optional, as any carrier should be."""
    attachment = FileAttachment(b"z")

    assert attachment == b"z"
    assert attachment.encoding is None
    assert attachment.filename is None
    assert repr(attachment) == "<FileAttachment: 1 bytes>"


def test_file_attachment_repr_escapes_a_control_character_in_a_filename(monkeypatch):
    """Short enough to survive the cap, so escaping is what is under test.

    An unescaped filename would put raw ANSI into a terminal reading the log.
    """
    item_value = _fetch_attachment(monkeypatch, b"z", filename="\x1b[31mboom.txt")

    rendered = repr(item_value)
    assert "\x1b" not in rendered
    assert "\\x1b" in rendered
    assert rendered.endswith("boom.txt': 1 bytes>")


def test_file_attachment_repr_survives_an_unprintable_filename():
    """Only reachable by hand, but a repr that raises breaks every log call."""

    class Hostile:
        def __repr__(self):
            raise RuntimeError("boom")

    attachment = FileAttachment(b"z", filename=Hostile())

    assert repr(attachment) == "<FileAttachment <unprintable filename>: 1 bytes>"


def test_file_attachment_repr_caps_a_hostile_filename(monkeypatch):
    """``filename`` is server data: the one unbounded part of a bounded repr."""
    item_value = _fetch_attachment(
        monkeypatch, b"file-bytes", filename="a" * 30 + "\n\x1b[31m" + "a" * 470 + "'"
    )

    rendered = repr(item_value)
    assert len(rendered) < 120
    assert rendered.startswith("<FileAttachment 'a")
    assert rendered.endswith("...[truncated]: 10 bytes>")
    assert "\x1b" not in rendered


def test_file_attachment_survives_copy_and_pickle(monkeypatch):
    """Both rebuild through ``__new__``, so the attributes must come back."""
    item_value = _fetch_attachment(
        monkeypatch, b"file-bytes", encoding="iso-8859-1", filename="notes.txt"
    )

    for clone in (
        copy.copy(item_value),
        copy.deepcopy(item_value),
        pickle.loads(pickle.dumps(item_value)),
    ):
        assert isinstance(clone, FileAttachment)
        assert clone.content == b"file-bytes"
        assert clone.text == "file-bytes"
        assert clone.encoding == "iso-8859-1"
        assert clone.filename == "notes.txt"


def test_file_attachment_subclass_keeps_its_own_attributes():
    """``__getnewargs__`` passes only the bytes, so the default reduce still
    carries the instance dict and a subclass is not cut down.
    """
    tagged = _TaggedAttachment(b"z", tag="keepme", filename="n.bin")

    for clone in (
        copy.copy(tagged),
        copy.deepcopy(tagged),
        pickle.loads(pickle.dumps(tagged)),
    ):
        assert isinstance(clone, _TaggedAttachment)
        assert clone.tag == "keepme"
        assert clone.filename == "n.bin"


def test_file_attachment_rebuild_does_not_re_run_init():
    """Copy and pickle go through ``__new__``, never the constructor.

    Calling the class instead would re-run a subclass's ``__init__`` with
    only the bytes, which the default reduce this pins never does.
    """
    original = _InitAttachment(b"z", "kept", filename="n.bin")

    for clone in (
        copy.copy(original),
        copy.deepcopy(original),
        pickle.loads(pickle.dumps(original)),
    ):
        assert clone.extra == "kept"
        assert clone.filename == "n.bin"


def test_file_attachment_survives_losing_its_own_attributes():
    """Pickle protocols 0 and 1 rebuild without ``__new__``, so the class
    defaults are what keep ``.text`` from raising ``AttributeError``.
    """
    attachment = FileAttachment(b"z", encoding="utf-8", filename="n.bin")
    del attachment.encoding
    del attachment.filename

    assert attachment.text == "z"
    assert repr(attachment) == "<FileAttachment: 1 bytes>"


def test_file_attachment_repr_names_the_actual_class():
    """A subclass must not be logged under the base class's name."""
    assert repr(_TaggedAttachment(b"z")) == "<_TaggedAttachment: 1 bytes>"


# The two bodies ``json.loads`` answers with something other than
# ``JSONDecodeError``: ``None`` gives ``TypeError``, non-UTF-8 bytes give
# ``UnicodeDecodeError``. Every reader must treat both as "not JSON".
_UNREADABLE_BODIES = [None, b'{"a": "caf\xe9"}']


class _UnreadableBody:
    """A response whose body no JSON reader can parse.

    ``.content`` is ``None`` when ``requests`` has no ``raw`` stream; the
    other shape is a body that is not valid UTF-8.
    """

    encoding = None

    def __init__(self, status_code, content=None):
        self.status_code = status_code
        self.ok = status_code < 400
        self.content = content

    def json(self):
        raise AssertionError("no reader may call .json() on a response body")


@pytest.mark.parametrize("body", _UNREADABLE_BODIES, ids=["none", "not-utf8"])
def test_a_body_that_cannot_be_read_at_all_raises_secret_server_error(
    monkeypatch, body
):
    """``get_secret`` documents ``SecretServerError`` as its only failure."""
    monkeypatch.setattr(HTTP_GET, lambda *args, **kwargs: _UnreadableBody(200, body))
    server = make_server("https://ss.example.com", "secret_server")

    with pytest.raises(SecretServerError) as raised:
        server.get_secret(1)

    assert "Secret endpoint did not return JSON: HTTP 200" in str(raised.value)


@pytest.mark.parametrize("body", _UNREADABLE_BODIES, ids=["none", "not-utf8"])
def test_a_client_error_with_no_readable_body_raises_cleanly(monkeypatch, body):
    """``process`` parses a 4xx body as JSON, so it meets the same bodies.

    A bare ``TypeError`` is not what ``:raise:`` promises the caller.
    """
    monkeypatch.setattr(HTTP_GET, lambda *args, **kwargs: _UnreadableBody(403, body))
    server = make_server("https://ss.example.com", "secret_server")

    with pytest.raises(SecretServerError) as raised:
        server.get_secret(1)

    assert "HTTP 403" in str(raised.value)


@pytest.mark.parametrize("body", _UNREADABLE_BODIES, ids=["none", "not-utf8"])
def test_a_token_response_with_no_readable_body_raises_cleanly(monkeypatch, body):
    """The token parser reads ``.content`` too, with the same two traps."""
    monkeypatch.setattr(HTTP_POST, lambda *args, **kwargs: _UnreadableBody(200, body))
    authorizer = make_grant_authorizer()

    with pytest.raises(SecretServerError) as raised:
        authorizer.get_access_token()

    assert "did not return a JSON access grant" in str(raised.value)


def test_file_attachment_without_a_filename_still_reprs(monkeypatch):
    """``filename`` is absent from the item dict for some templates."""
    item_value = _fetch_attachment(monkeypatch, b"file-bytes")

    assert item_value.filename is None
    assert repr(item_value) == "<FileAttachment: 10 bytes>"


def test_unfetched_file_attachment_is_left_alone(monkeypatch):
    """``fetch_file_attachments=False`` must not build a carrier at all."""
    server = _attachment_server(monkeypatch, [_ONE_FILE])

    secret = server.get_secret(1, fetch_file_attachments=False)

    assert secret["items"][0]["itemValue"] is None


def test_ordinary_field_values_are_not_overwritten(monkeypatch):
    """The loop keys off a truthy ``fileAttachmentId``, not the key's presence.

    Every item carries the key, 0 for a field that is not a file.
    """
    server = _attachment_server(monkeypatch, [_ONE_FILE])

    secret = server.get_secret(1, fetch_file_attachments=True)

    assert secret["items"][1]["itemValue"] == "p@ss"


def test_each_read_parses_its_own_items(monkeypatch):
    """``get_secret`` mutates what it returns, so it must not be shared.

    A second read of the same secret cannot see the first read's values.
    """
    server = _attachment_server(monkeypatch, [_ONE_FILE])

    first = server.get_secret(1, fetch_file_attachments=True)
    first["items"][1]["itemValue"] = "clobbered"
    second = server.get_secret(1, fetch_file_attachments=True)

    assert second["items"][1]["itemValue"] == "p@ss"


@pytest.mark.parametrize("slug", [None, "", 42], ids=["absent", "empty", "int"])
def test_a_file_field_with_no_usable_slug_raises(monkeypatch, slug):
    """``slug`` builds the field URL, so an unusable one cannot be fetched.

    An empty one would fetch the fields collection; indexing a missing one
    would leave a ``KeyError`` where the API promises its own error.
    """
    item = {"fileAttachmentId": 42, "filename": "f.txt"}
    if slug is not None:
        item["slug"] = slug
    body = FakeResponse(json_data={"id": 7, "items": [item]})

    monkeypatch.setattr(HTTP_GET, lambda *args, **kwargs: body)
    server = make_server("https://ss.example.com", "secret_server")

    with pytest.raises(SecretServerError) as raised:
        server.get_secret(1)

    assert "file field with no 'slug'" in str(raised.value)
    # The secret's own response, not a field's: no field was ever fetched.
    assert raised.value.response is body


def test_a_secret_with_no_items_is_returned_unchanged(monkeypatch):
    """An empty list is a valid answer, not a malformed body."""
    monkeypatch.setattr(
        HTTP_GET, lambda *a, **k: FakeResponse(json_data={"id": 7, "items": []})
    )
    server = make_server("https://ss.example.com", "secret_server")

    assert server.get_secret(1) == {"id": 7, "items": []}


def test_an_empty_folder_returns_no_secret_ids(monkeypatch):
    """The same for ``records``: an empty folder is not a malformed body."""

    def fake_get(url, *args, **kwargs):
        if url.endswith("/secrets/search-total"):
            return FakeResponse(text="0")
        return FakeResponse(json_data={"records": []})

    monkeypatch.setattr(HTTP_GET, fake_get)
    server = make_server("https://ss.example.com", "secret_server")

    assert server.get_secret_ids_by_folderid(2) == []


# ``_required_records`` vouches that each record is an object; the ``id`` read
# out of it needs the same guard, or a bare ``KeyError`` escapes the
# ``SecretServerError`` these methods document as their only failure.
def test_a_secrets_search_record_with_no_id_raises(monkeypatch):
    def fake_get(url, *args, **kwargs):
        if url.endswith("/secrets/search-total"):
            return FakeResponse(text="1")
        return FakeResponse(json_data={"records": [{"name": "no-id-here"}]})

    monkeypatch.setattr(HTTP_GET, fake_get)
    server = make_server("https://ss.example.com", "secret_server")

    with pytest.raises(SecretServerError) as raised:
        server.get_secret_ids_by_folderid(2)

    assert "no 'id'" in str(raised.value)


def test_a_folder_lookup_record_with_no_id_raises(monkeypatch):
    """``get_child_folder_ids_by_folderid`` reads the same key the same way."""
    monkeypatch.setattr(
        HTTP_GET,
        lambda *args, **kwargs: FakeResponse(
            json_data={"total": 1, "records": [{"name": "x"}]}
        ),
    )
    server = make_server("https://ss.example.com", "secret_server")

    with pytest.raises(SecretServerError) as raised:
        server.get_child_folder_ids_by_folderid(2)

    assert "no 'id'" in str(raised.value)


def test_an_item_without_a_file_attachment_id_is_left_alone(monkeypatch):
    """Absent, not zero: the key is missing for some templates.

    Indexing it would raise ``KeyError`` out of a ``SecretServerError`` API.
    """

    def fake_get(url, *args, **kwargs):
        items = [{"slug": "password", "itemValue": "p@ss"}]
        return FakeResponse(json_data={"id": 7, "items": items})

    monkeypatch.setattr(HTTP_GET, fake_get)
    server = make_server("https://ss.example.com", "secret_server")

    secret = server.get_secret(1, fetch_file_attachments=True)

    assert secret["items"][0]["itemValue"] == "p@ss"


@pytest.mark.parametrize(
    "items",
    ["not-a-list", [1, 2], [{"slug": "a"}, "not-an-object"], 42],
    ids=["string", "numbers", "mixed", "int"],
)
def test_a_secret_whose_items_are_not_objects_raises(monkeypatch, items):
    """``_get_json`` vouches for the body; the key read out of it needs the
    same, or a malformed payload escapes as whatever indexing it happens to
    raise -- ``TypeError`` or ``AttributeError``, never the documented error.
    """

    body = FakeResponse(json_data={"id": 7, "items": items})

    monkeypatch.setattr(HTTP_GET, lambda *args, **kwargs: body)
    server = make_server("https://ss.example.com", "secret_server")

    with pytest.raises(SecretServerError) as raised:
        server.get_secret(1)

    assert "did not return 'items' as a list of objects" in str(raised.value)
    assert raised.value.response is body


def test_each_attachment_is_fetched_from_its_own_field(monkeypatch):
    """One request per file field, each value paired with its own slug."""
    seen = []
    files = [
        ("first", b"AAA", "a.bin", None),
        ("second", b"BBBB", "b.bin", None),
    ]
    server = _attachment_server(monkeypatch, files, seen=seen)

    items = server.get_secret(1, fetch_file_attachments=True)["items"]

    assert [item["itemValue"] for item in items[:2]] == [b"AAA", b"BBBB"]
    assert [item["itemValue"].filename for item in items[:2]] == ["a.bin", "b.bin"]
    assert [slug for slug, _ in seen] == ["secret", "first", "second"]


def test_query_params_reach_the_secret_body_and_every_field(monkeypatch):
    """Both the secret body and every field fetch get the caller's params."""
    seen = []
    server = _attachment_server(monkeypatch, [_ONE_FILE], seen=seen)

    server.get_secret(1, query_params={"autoComment": "why"})

    assert seen == [
        ("secret", {"autoComment": "why"}),
        ("file-slug", {"autoComment": "why"}),
    ]


def test_get_secret_by_path_forwards_the_path_and_the_flag(monkeypatch):
    """The path travels as a query parameter, and the flag is not overridden."""
    seen = []
    server = _attachment_server(monkeypatch, [_ONE_FILE], seen=seen)

    secret = server.get_secret_by_path("/a/b/", fetch_file_attachments=False)

    assert secret["items"][0]["itemValue"] is None
    assert seen == [("secret", {"secretPath": "\\a\\b"})]


def test_a_failing_attachment_fetch_raises(monkeypatch):
    """A 4xx on one field must not be swallowed, nor stored as the file.

    Bypassing ``process`` would write the error body to disk downstream.
    """
    seen = []
    files = [("first", b"AAA", None, None), ("second", b"BBBB", None, None)]
    server = _attachment_server(monkeypatch, files, seen=seen, statuses={"second": 403})

    with pytest.raises(SecretServerError):
        server.get_secret(1, fetch_file_attachments=True)

    # The first field really was served, so the failure was mid-loop.
    assert [slug for slug, _ in seen] == ["secret", "first", "second"]


# ---------------------------------------------------------------------------
# 4.6: non-numeric search-total body is rejected, not silently propagated
# ---------------------------------------------------------------------------


def test_non_numeric_search_total_raises(monkeypatch):
    def fake_get(url, *args, **kwargs):
        if url.endswith("/secrets/search-total"):
            return FakeResponse(text="not-a-number")
        return FakeResponse(json_data={"records": []})

    monkeypatch.setattr(HTTP_GET, fake_get)

    server = make_server("https://ss.example.com", "secret_server")

    with pytest.raises(SecretServerError, match="non-numeric"):
        server.get_secret_ids_by_folderid(1)


def test_numeric_search_total_still_works(monkeypatch):
    def fake_get(url, *args, **kwargs):
        if url.endswith("/secrets/search-total"):
            return FakeResponse(text="2")
        return FakeResponse(json_data={"records": [{"id": 1}, {"id": 2}]})

    monkeypatch.setattr(HTTP_GET, fake_get)

    server = make_server("https://ss.example.com", "secret_server")

    assert server.get_secret_ids_by_folderid(1) == [1, 2]


# ---------------------------------------------------------------------------
# Review step 1: authorizers stay picklable / deep-copyable with the lock
# ---------------------------------------------------------------------------


def _grant_authorizer():
    return make_grant_authorizer(password="SuperSecret123")


def test_password_grant_authorizer_deep_copies_with_its_own_lock():
    import copy

    auth = _grant_authorizer()
    clone = copy.deepcopy(auth)

    assert clone is not auth
    assert clone.base_url == auth.base_url
    assert clone._server_type == "secret_server"
    assert clone.password == auth.password
    assert clone._refresh_lock is not auth._refresh_lock


def test_password_grant_authorizer_shallow_copies_with_its_own_lock():
    import copy

    auth = _grant_authorizer()
    clone = copy.copy(auth)

    assert clone is not auth
    assert clone.username == auth.username
    assert clone._refresh_lock is not auth._refresh_lock


@pytest.mark.parametrize("copier", ["copy", "deepcopy"])
def test_copy_does_not_wait_for_an_in_progress_refresh(copier):
    """A copy must not take ``_refresh_lock``: it would block behind a detection
    plus token request, and deadlock when made from code already under the lock.
    Taken mid-refresh, the clone carries no half-written grant.
    """
    import copy

    auth = _grant_authorizer()
    in_grant = threading.Event()
    release = threading.Event()

    held = {}

    def slow_grant(token_url, grant_request):
        in_grant.set()
        held["released_in_time"] = release.wait(timeout=10)
        return {"access_token": "orig-tok", "expires_in": 1200}

    auth.get_access_grant = slow_grant
    refresher = threading.Thread(target=auth.get_access_token, daemon=True)
    refresher.start()
    assert in_grant.wait(timeout=10)
    try:
        clone = getattr(copy, copier)(auth)
        # The copy must return while the refresh still holds the lock. One
        # that took the lock would arrive here only after slow_grant's wait
        # gave up, then pass everything below; this assertion catches that.
        assert refresher.is_alive(), "copy returned only after the refresh ended"
        assert "released_in_time" not in held
    finally:
        release.set()
        join_all([refresher])
    assert held["released_in_time"] is True

    assert not hasattr(clone, "access_grant")
    assert not hasattr(clone, "access_grant_refreshed")
    clone.get_access_grant = lambda *a, **k: {
        "access_token": "clone-tok",
        "expires_in": 1200,
    }
    assert clone.get_access_token() == "clone-tok"
    assert auth.get_access_token() == "orig-tok"


def test_refresh_publishes_through_ordinary_attribute_assignment():
    """A subclass may turn ``access_grant`` into a slot or a property; the
    grant must reach it. Publishing through ``__dict__`` bypassed both."""

    seen = []

    class Observing(PasswordGrantAuthorizer):
        @property
        def access_grant(self):
            try:
                return self.__dict__["_grant"]
            except KeyError:  # behave like an unset attribute before first refresh
                raise AttributeError("access_grant") from None

        @access_grant.setter
        def access_grant(self, value):
            if value is not None:  # tolerate a future None-initialising __init__
                seen.append(value["access_token"])
            self.__dict__["_grant"] = value

    class Slotted(PasswordGrantAuthorizer):
        __slots__ = ("access_grant",)

    for cls in (Observing, Slotted):
        auth = cls("https://ss.example.com", "u", "p", server_type="secret_server")
        auth.get_access_grant = lambda *a, **k: {
            "access_token": "tok",
            "expires_in": 1200,
        }
        assert auth.get_access_token() == "tok"
        assert auth.access_grant["access_token"] == "tok"
    assert seen == ["tok"]


def test_copy_from_inside_a_refresh_callback_does_not_deadlock():
    """An overridden ``get_access_grant`` (or a framework deep-copying an
    object graph from one) runs under ``_refresh_lock``; copying the
    authorizer there must return, not hang the thread forever."""
    import copy

    auth = _grant_authorizer()
    seen = {}

    def copying_grant(token_url, grant_request):
        seen["shallow"] = copy.copy(auth)
        seen["deep"] = copy.deepcopy({"auth": auth, "n": 1})["auth"]
        return {"access_token": "tok", "expires_in": 1200}

    auth.get_access_grant = copying_grant
    result = []
    worker = threading.Thread(
        target=lambda: result.append(auth.get_access_token()), daemon=True
    )
    worker.start()
    join_all([worker], timeout=5)  # fails, instead of hanging, on a deadlock
    assert result == ["tok"]
    assert seen["shallow"]._refresh_lock is not auth._refresh_lock
    assert seen["deep"]._refresh_lock is not auth._refresh_lock


@pytest.mark.parametrize("present", ["access_grant", "access_grant_refreshed"])
def test_copy_drops_a_half_written_grant_pair(present):
    """``_refresh`` writes the grant, then its timestamp. A snapshot taken
    between the two must not produce a clone that raises AttributeError
    on every call; the incomplete pair is dropped and the clone refreshes."""
    import copy

    auth = _grant_authorizer()
    # Reproduce the half-written state directly; the real window is one
    # bytecode wide and cannot be hit deterministically from a test.
    if present == "access_grant":
        auth.__dict__["access_grant"] = {"access_token": "orphan", "expires_in": 1200}
    else:
        auth.__dict__["access_grant_refreshed"] = datetime.now(timezone.utc)

    clone = copy.copy(auth)
    assert not hasattr(clone, "access_grant")
    assert not hasattr(clone, "access_grant_refreshed")
    clone.get_access_grant = lambda *a, **k: {
        "access_token": "fresh",
        "expires_in": 1200,
    }
    assert clone.get_access_token() == "fresh"
    # The original is left exactly as it was.
    assert present in auth.__dict__


def test_deep_copied_authorizer_refreshes_independently():
    """The copy has its own grant state and lock; refreshing it must neither
    require nor disturb the original."""
    import copy

    auth = _grant_authorizer()
    clone = copy.deepcopy(auth)
    clone.get_access_grant = lambda token_url, grant_request: {
        "access_token": "clone-tok",
        "expires_in": 1200,
    }

    assert clone.get_access_token() == "clone-tok"
    assert not hasattr(auth, "access_grant")


def test_deepcopy_of_container_holding_authorizer_preserves_identity_semantics():
    """``memo`` bookkeeping: the same authorizer referenced twice in one
    structure deep-copies to a single clone, as for any other object."""
    import copy

    auth = _grant_authorizer()
    pair = copy.deepcopy([auth, auth])

    assert pair[0] is pair[1]
    assert pair[0] is not auth


def test_password_grant_authorizer_refuses_to_pickle():
    """A pickle leaves the process carrying the plaintext password, so it is
    refused with an actionable error. This replaces an accidental ``TypeError:
    cannot pickle '_thread.lock'`` that also broke ``copy.deepcopy``.
    """
    import pickle

    auth = _grant_authorizer()
    with pytest.raises(TypeError, match="holds live credentials") as excinfo:
        pickle.dumps(auth)
    assert "copy.deepcopy" in str(excinfo.value)


def test_access_token_authorizer_refuses_to_pickle():
    """The same policy for the other credential holder: a pre-issued bearer
    token must not be written to a disk cache or a worker pipe either."""
    import copy
    import pickle

    auth = AccessTokenAuthorizer(
        "bearer-secret-token", "https://ss.example.com", server_type="secret_server"
    )
    for protocol in range(pickle.HIGHEST_PROTOCOL + 1):
        with pytest.raises(TypeError, match="live bearer token"):
            pickle.dumps(auth, protocol=protocol)
    # In-memory copies still work: there is no lock to worry about here.
    assert copy.copy(auth).get_access_token() == "bearer-secret-token"
    assert copy.deepcopy(auth).get_access_token() == "bearer-secret-token"


def _response_for(method, url, **kwargs):
    """A real ``requests.Response`` with a real ``PreparedRequest``.

    Built locally: preparing a request issues no I/O, so this stays offline
    while reproducing exactly what the SDK attaches to an error.
    """
    response = requests.Response()
    response.status_code = 400
    response._content = b'{"error":"invalid_grant"}'
    response.request = requests.Request(method, url, **kwargs).prepare()
    return response


PASSWORD = "pickle-probe-password"
BEARER = "pickle-probe-bearer-token"


@pytest.mark.parametrize("error_type", [SecretServerError, SecretServerClientError])
def test_pickled_error_carries_no_grant_credentials(error_type):
    """The token-endpoint response holds the grant as its request body, so
    pickling an error that kept it would write the password wherever the
    pickle goes. A process pool does that unasked, to propagate a failure.
    """
    import pickle

    response = _response_for(
        "POST",
        "https://ss.example.com/oauth2/token",
        data={"username": "svc", "password": PASSWORD, "grant_type": "password"},
    )
    assert PASSWORD in response.request.body  # the leak exists to be stopped

    error = error_type("Token endpoint rejected the grant", response)
    blob = pickle.dumps(error)
    assert PASSWORD.encode() not in blob
    assert b"oauth2/token" not in blob

    revived = pickle.loads(blob)
    assert type(revived) is error_type
    assert revived.message == "Token endpoint rejected the grant"
    assert str(revived) == str(error)
    assert revived.response is None
    # In-memory use is untouched: ``.response`` is documented API.
    assert error.response is response
    assert error.response.status_code == 400


def test_pickled_error_carries_no_bearer_token():
    """Every API error attaches a response whose request carries the
    Authorization header."""
    import pickle

    response = _response_for(
        "GET",
        "https://ss.example.com/api/v1/secrets/1",
        headers={"Authorization": f"Bearer {BEARER}"},
    )
    assert BEARER in response.request.headers["Authorization"]
    error = SecretServerError("HTTP 400: bad request", response)
    assert BEARER.encode() not in pickle.dumps(error)


def test_shared_failure_still_rebuilds_with_its_response():
    """``_shared_failure`` reconstructs an error as ``type(e)(message,
    response)``. The pickle change must not disturb that constructor.
    """
    original = SecretServerClientError(
        "client boom", _response_for("GET", "https://ss.example.com/api/v1/x")
    )
    shared = Authorizer._shared_failure(original)
    assert type(shared) is SecretServerClientError
    assert shared.message == original.message
    assert shared.response is original.response


def test_pickle_refusal_never_emits_the_password():
    """Belt and braces: no pickle protocol may produce bytes for this object."""
    import pickle

    auth = _grant_authorizer()
    for protocol in range(pickle.HIGHEST_PROTOCOL + 1):
        with pytest.raises(TypeError):
            pickle.dumps(auth, protocol=protocol)


def test_domain_authorizer_inherits_copy_and_pickle_behaviour():
    import copy
    import pickle

    from delinea.secrets.server import DomainPasswordGrantAuthorizer

    auth = DomainPasswordGrantAuthorizer(
        "https://ss.example.com",
        "user",
        "example.com",
        "pass",
        server_type="secret_server",
    )
    clone = copy.deepcopy(auth)
    assert clone.domain == "example.com"
    assert clone._refresh_lock is not auth._refresh_lock
    with pytest.raises(TypeError, match="DomainPasswordGrantAuthorizer"):
        pickle.dumps(auth)


# ---------------------------------------------------------------------------
# Review step 1: get_folder_json accepts every params form requests accepts
# ---------------------------------------------------------------------------


def _folder_server(monkeypatch, calls):
    """Records ``(url, params)`` for every GET."""

    def fake_get(url, *args, **kwargs):
        calls.append((url, kwargs.get("params")))
        return FakeResponse(json_data={"id": 1})

    monkeypatch.setattr(HTTP_GET, fake_get)
    return make_server("https://ss.example.com", "secret_server")


@pytest.mark.parametrize(
    "params",
    ["take=5", b"take=5", [("take", "5")], {"take": 5}],
)
def test_get_folder_json_accepts_any_params_form(monkeypatch, params):
    """A mapping stays a mapping; every other form becomes a list of pairs, so
    repeated keys survive. Either way the flag is sent exactly once. The old
    ``dict()`` coercion raised ValueError on a query string or pairs."""
    calls = []
    server = _folder_server(monkeypatch, calls)
    server.get_folder_json(1, query_params=params)
    url, sent = calls[-1]
    assert url.endswith("/folders/1")
    as_dict = sent if isinstance(sent, dict) else dict(sent)
    assert as_dict["getAllChildren"] == "true"
    assert str(as_dict["take"]) == "5"
    assert len(sent) == 2  # no duplicate key in either form


def test_get_folder_json_does_not_mutate_caller_params(monkeypatch):
    calls = []
    server = _folder_server(monkeypatch, calls)
    params = {"take": 5}
    server.get_folder_json(1, query_params=params)
    assert params == {"take": 5}


def test_get_folder_json_string_params_passthrough_without_children(monkeypatch):
    calls = []
    server = _folder_server(monkeypatch, calls)
    server.get_folder_json(1, query_params="take=5", get_all_children=False)
    url, sent = calls[-1]
    assert url.endswith("/folders/1")
    assert sent == "take=5"


# ---------------------------------------------------------------------------
# Review step 2: non-JSON folder lookup body is excerpted, not echoed
# ---------------------------------------------------------------------------


def test_child_folder_lookup_non_json_is_excerpted(monkeypatch):
    responses = [
        FakeResponse(json_data={"total": 3}),
        FakeResponse(text="<html>" + "x" * 500),
    ]

    def fake_get(url, *args, **kwargs):
        return responses.pop(0)

    monkeypatch.setattr(HTTP_GET, fake_get)
    server = make_server("https://ss.example.com", "secret_server")

    with pytest.raises(SecretServerError) as excinfo:
        server.get_child_folder_ids_by_folderid(7)
    err = excinfo.value
    assert err.message.startswith("Folder lookup did not return JSON: HTTP 200: <html>")
    assert err.message.endswith("...[truncated]")
    assert len(err.message) < 300


# ---------------------------------------------------------------------------
# Review step 4: one request helper, one access token per API call
# ---------------------------------------------------------------------------


def _grant_server(monkeypatch, fake_get, server_type, base_url):
    """A SecretServer over a PasswordGrantAuthorizer, counting token POSTs.

    Counting POSTs measures how often the password is sent, not how often
    ``get_access_token()`` is called, which is free while the grant is valid.
    """
    posts = {"count": 0}

    def counting_post(url, *args, **kwargs):
        posts["count"] += 1
        return fake_token_post(url, *args, **kwargs)

    monkeypatch.setattr(HTTP_GET, fake_get)
    monkeypatch.setattr(HTTP_POST, counting_post)
    authorizer = PasswordGrantAuthorizer(
        base_url, "user", "pass", server_type=server_type
    )
    return SecretServer(base_url, authorizer), posts


def test_platform_calls_reuse_one_token_grant(monkeypatch):
    """Across the vault-broker lookup and two API calls the password is sent
    to the token endpoint exactly once."""

    def fake_get(url, *args, **kwargs):
        if "vaultbroker" in url:
            return vault_broker_response()
        return FakeResponse(json_data={"id": 1})

    server, posts = _grant_server(
        monkeypatch, fake_get, "platform", "https://platform.example.com"
    )

    server.get_secret_json(1)
    server.get_secret_json(2)
    assert posts["count"] == 1
    assert server.base_url == "https://vault.example.com"


def test_attachment_burst_reuses_one_token_grant(monkeypatch):
    """Each attachment rebuilds headers so a refresh can happen mid-burst if
    one is due, but with a valid grant that costs no token POST at all."""
    secret_body = json.dumps(
        {
            "items": [
                {"fileAttachmentId": 11, "slug": "a", "itemValue": None},
                {"fileAttachmentId": 12, "slug": "b", "itemValue": None},
                {"fileAttachmentId": 13, "slug": "c", "itemValue": None},
            ]
        }
    )

    def fake_get(url, *args, **kwargs):
        if "/fields/" in url:
            return AttachmentResponse(b"file-contents")
        return FakeResponse(text=secret_body)

    server, posts = _grant_server(
        monkeypatch, fake_get, "secret_server", "https://ss.example.com"
    )

    secret = server.get_secret(1)
    assert [item["itemValue"] for item in secret["items"]] == [b"file-contents"] * 3
    assert posts["count"] == 1


def test_attachment_fetch_refreshes_an_expired_grant_mid_burst(monkeypatch):
    """The point of per-attachment headers: a grant that expires between
    attachments is refreshed, not sent expired to fail with 401."""
    from datetime import timedelta

    secret_body = json.dumps(
        {
            "items": [
                {"fileAttachmentId": 11, "slug": "a", "itemValue": None},
                {"fileAttachmentId": 12, "slug": "b", "itemValue": None},
            ]
        }
    )
    tokens_seen = []

    def fake_get(url, *args, **kwargs):
        if "/fields/" in url:
            tokens_seen.append(kwargs["headers"]["Authorization"])
            if url.endswith("/fields/a"):
                # Expire the grant on the server's clock between attachments.
                server.authorizer.access_grant_refreshed -= timedelta(hours=1)
            return AttachmentResponse(b"file-contents")
        return FakeResponse(text=secret_body)

    server, posts = _grant_server(
        monkeypatch, fake_get, "secret_server", "https://ss.example.com"
    )

    server.get_secret(1)
    # One grant for the secret + first attachment, a fresh one for the second.
    assert posts["count"] == 2
    assert len(tokens_seen) == 2


def test_ensure_vault_url_resolves_lazy_detection_itself(monkeypatch):
    """Called directly, before any API call, ``ensure_vault_url`` must still
    switch to the vault URL for a PasswordGrantAuthorizer that has not yet
    detected its server type -- not silently do nothing."""

    def fake_get(url, *args, **kwargs):
        if "vaultbroker" in url:
            return vault_broker_response("https://vault.example.com")
        # Health probes: platform is healthy, Secret Server is not.
        return health_response(url.endswith("/health"))

    monkeypatch.setattr(HTTP_GET, fake_get)
    monkeypatch.setattr(HTTP_POST, fake_token_post)

    authorizer = PasswordGrantAuthorizer("https://platform.example.com", "user", "pass")
    server = SecretServer("https://platform.example.com", authorizer)
    assert not hasattr(authorizer, "_server_type")

    server.ensure_vault_url()
    assert authorizer._server_type == "platform"
    assert server.base_url == "https://vault.example.com"


def test_ensure_vault_url_is_a_no_op_after_the_first_resolution(monkeypatch):
    gets = []

    def fake_get(url, *args, **kwargs):
        gets.append(url)
        return FakeResponse(json_data={"id": 1})

    monkeypatch.setattr(HTTP_GET, fake_get)
    server = make_server("https://ss.example.com", "secret_server")

    server.ensure_vault_url()
    server.ensure_vault_url()
    server.get_secret_json(1)
    # No vault-broker call for Secret Server, and the API call still went out.
    assert gets == ["https://ss.example.com/api/v1/secrets/1"]


@pytest.mark.parametrize(
    "call,expected_params",
    [
        (lambda s: s.search_secrets(), None),
        (lambda s: s.search_secrets(query_params={"a": "b"}), {"a": "b"}),
        (lambda s: s.lookup_folders(), None),
        (lambda s: s.lookup_folders(query_params={"a": "b"}), {"a": "b"}),
        (lambda s: s.get_secret_json(1), None),
        (lambda s: s.get_secret_json(1, query_params={"a": "b"}), {"a": "b"}),
    ],
)
def test_read_paths_pass_params_through_unchanged(monkeypatch, call, expected_params):
    """Collapsing the ``if query_params is None`` twin branches into a single
    call must not change what reaches ``requests``."""
    seen = []

    def fake_get(url, *args, **kwargs):
        seen.append(kwargs.get("params"))
        return FakeResponse(json_data={"records": []})

    monkeypatch.setattr(HTTP_GET, fake_get)
    server = make_server("https://ss.example.com", "secret_server")

    call(server)
    assert seen[-1] == expected_params


def test_read_paths_target_the_same_urls_as_before(monkeypatch):
    """``_get`` joins the path under ``api_url`` exactly as the inlined
    f-strings did."""
    seen = []

    def fake_get(url, *args, **kwargs):
        seen.append(url)
        return FakeResponse(json_data={"total": 0, "records": []})

    monkeypatch.setattr(HTTP_GET, fake_get)
    server = make_server("https://ss.example.com", "secret_server")
    api = "https://ss.example.com/api/v1"

    server.get_secret_json(5)
    server.get_folder_json(6, get_all_children=False)
    server.search_secrets()
    server.lookup_folders()
    server.get_child_folder_ids_by_folderid(9)

    assert seen == [
        f"{api}/secrets/5",
        f"{api}/folders/6",
        f"{api}/secrets",
        f"{api}/folders/lookup",
        f"{api}/folders/lookup",
    ]


def test_get_folder_json_flag_wins_over_caller_getallchildren(monkeypatch):
    """Carrying the flag in the URL sent the key twice when the caller also
    passed it; the flag must win and appear once, as on main."""
    calls = []
    server = _folder_server(monkeypatch, calls)
    caller = {"getAllChildren": "false", "take": 1}
    server.get_folder_json(1, query_params=caller)
    url, sent = calls[-1]
    assert "getAllChildren" not in url
    assert sent == {"getAllChildren": "true", "take": 1}
    assert caller == {"getAllChildren": "false", "take": 1}


@pytest.mark.parametrize(
    "body",
    [
        FakeResponse(text="<html>blocked</html>"),
        FakeResponse(json_data=[]),
        FakeResponse(json_data={"count": 1}),
    ],
)
def test_child_folder_total_shape_errors_are_secret_server_errors(monkeypatch, body):
    """Every shape a folder lookup can come back in is a SecretServerError."""
    monkeypatch.setattr(HTTP_GET, lambda *a, **k: body)
    server = make_server("https://ss.example.com", "secret_server")
    with pytest.raises(SecretServerError, match="Folder lookup did not return"):
        server.get_child_folder_ids_by_folderid(7)


# ---------------------------------------------------------------------------
# Round 9: refresh fast path, legacy hooks, one warning per wrapper
# ---------------------------------------------------------------------------


def test_fresh_grant_is_used_without_taking_the_refresh_lock():
    """A thread holding a valid token must not wait behind another thread's
    token request. The lock is held by the test; the call must still return."""
    auth = make_grant_authorizer()
    auth.access_grant = {"access_token": "still-good", "expires_in": 1200}
    auth.access_grant_refreshed = datetime.now(timezone.utc)
    got = []
    assert auth._refresh_lock.acquire(timeout=1)
    try:
        worker = threading.Thread(
            target=lambda: got.append(auth.get_access_token()), daemon=True
        )
        worker.start()
        join_all([worker], timeout=2)
    finally:
        auth._refresh_lock.release()
    assert got == ["still-good"]


def test_refresh_with_a_stale_grant_still_serialises_behind_the_lock():
    """The fast path applies only to a fresh grant; a stale one takes the lock
    so there is still exactly one refresher."""
    auth = make_grant_authorizer()
    auth.access_grant = {"access_token": "expired", "expires_in": 1200}
    auth.access_grant_refreshed = datetime.now(timezone.utc) - timedelta(seconds=5000)
    auth.get_access_grant = lambda *a, **k: {"access_token": "new", "expires_in": 1200}
    assert auth._refresh_lock.acquire(timeout=1)
    try:
        worker = threading.Thread(target=auth.get_access_token, daemon=True)
        worker.start()
        worker.join(0.3)
        assert worker.is_alive(), "a stale grant must wait for the refresh lock"
    finally:
        auth._refresh_lock.release()
    join_all([worker], timeout=2)
    assert auth.get_access_token() == "new"


def test_subclass_overriding_the_one_argument_detection_hook_still_works():
    """Before ``server_type`` existed, overriding ``_perform_server_detection``
    was the only way to skip the probes; that override must keep constructing."""

    class NoProbe(AccessTokenAuthorizer):
        def _perform_server_detection(self, base_url):
            self._server_type = "platform"

    assert NoProbe("tok", "https://x.example.com")._server_type == "platform"


def test_legacy_wrapper_emits_one_insecure_warning_even_under_always():
    """``SecretServerV0`` builds an authorizer and a client for one URL; only
    one of them may warn, or ``-W always`` shows the same line twice."""
    with warnings.catch_warnings(record=True) as record:
        warnings.simplefilter("always")
        SecretServerV0(
            "http://legacy.example.com", "u", "p", server_type="secret_server"
        )
    insecure = [w for w in record if "does not use https" in str(w.message)]
    assert len(insecure) == 1


def test_client_still_warns_for_its_own_insecure_url():
    """Suppression applies only when the authorizer already covered the same
    URL; a different insecure client URL is still reported."""
    with warnings.catch_warnings(record=True) as record:
        warnings.simplefilter("always")
        authorizer = AccessTokenAuthorizer(
            "tok", "http://auth.example.com", server_type="platform"
        )
        SecretServer("http://api.example.com", authorizer)
    insecure = [
        str(w.message) for w in record if "does not use https" in str(w.message)
    ]
    assert len(insecure) == 2
