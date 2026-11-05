# The Delinea Secret Server Python SDK


[![Code style: black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)

![PyPI Version](https://img.shields.io/pypi/v/python-tss-sdk) ![License](https://img.shields.io/github/license/DelineaXPM/python-tss-sdk) ![Python Versions](https://img.shields.io/pypi/pyversions/python-tss-sdk)


The [Delinea](https://delinea.com/) [Secret Server](https://delinea.com/products/secret-server/) Python SDK contains classes that interact with Secret Server via their REST APIs.

## Authentication Support

This SDK supports both Secret Server and Platform authentication. You can use the same authorizer classes for both systems and instantiate either a Secret Server or Platform client as needed. For Secret Server, you need to create an application user with the required permissions for authentication. For Platform, you need to create a service user with the appropriate permissions for authentication.

## Install

```shell
python -m pip install python-tss-sdk
```

## Secret Server Authentication

There are three ways in which you can authorize the `SecretServer` and `SecretServerCloud` classes to fetch secrets.

- Password Authorization (with `PasswordGrantAuthorizer`)
- Domain Authorization (with `DomainPasswordGrantAuthorizer`)
- Access Token Authorization (with `AccessTokenAuthorizer`)

### HTTPS is required

Every `base_url` must use `https`. A plaintext URL raises `ValueError` at
construction, before any request is issued:

```python
AccessTokenAuthorizer(token, "http://hostname/SecretServer")
# ValueError: base_url 'http://hostname/SecretServer' does not use https;
# credentials and bearer tokens would be sent unencrypted. Pass
# allow_http=True to accept that for a lab or test server.
```

For a lab or test server, pass `allow_http=True`. It is keyword-only, and it
downgrades the rejection to a `UserWarning` rather than silencing it:

```python
url = "http://localhost/SecretServer"
authorizer = AccessTokenAuthorizer(token, url, allow_http=True)
server = SecretServer(url, authorizer)  # inherits the opt-out from the authorizer
```

`SecretServer` and `SecretServerCloud` inherit `allow_http` from the authorizer
when both were built for the same URL, so a single-URL setup states it once.
Pass it explicitly on the client when the two URLs differ.

The opt-out covers only the URL *you* supply. The Platform vault connection URL
returned by the vault broker must always be `https`, whatever `allow_http` says —
otherwise a compromised broker could downgrade every call that follows it.

> **Upgrading from 2.0.1:** this is a breaking change. 2.0.1 only warned on
> `http://`, and a `UserWarning` is invisible under the default filter after its
> first firing. If you point the SDK at a plaintext lab server, add
> `allow_http=True`; if you point it at production, the rejection is telling you
> something worth fixing.

### Usage


#### Password Authorization

If using traditional `username` and `password` authentication to log in to your Secret Server either directly or through Platform, you can pass the `PasswordGrantAuthorizer` into the `SecretServer` class at instantiation. The `PasswordGrantAuthorizer` requires a `base_url`, `username`, and `password`. It optionally takes a `token_path_uri`, but defaults to `/oauth2/token` or `/identity/api/oauth2/token/xpmplatform`, depending on whether a secret server or platform is used for authentication. It also optionally takes a `server_type` (`"secret_server"` or `"platform"`) to skip automatic server-type detection — see [Server-Type Detection](#server-type-detection).

##### With Secret Server
```python
from delinea.secrets.server import PasswordGrantAuthorizer

authorizer = PasswordGrantAuthorizer("https://hostname/SecretServer", os.getenv("myusername"), os.getenv("password"))
```

##### With Platform

```python
from delinea.secrets.server import PasswordGrantAuthorizer

authorizer = PasswordGrantAuthorizer("https://platform.delinea.app", os.getenv("myusername"), os.getenv("password"))
```

#### Domain Authorization

To use a domain credential, use the `DomainPasswordGrantAuthorizer`. It requires a `base_url`, `username`, `domain`, and `password`. It optionally takes a `token_path_uri`, but defaults to `/oauth2/token`, and a `server_type` (see [Server-Type Detection](#server-type-detection)). It is applicable only when authentication is done using a secret server.

```python
from delinea.secrets.server import DomainPasswordGrantAuthorizer

authorizer = DomainPasswordGrantAuthorizer("https://hostname/SecretServer", os.getenv("myusername"), os.getenv("mydomain"), os.getenv("password"))
```

#### Access Token Authorization

If you already have an `access_token` of Secret Server or Platform user, you can pass directly via the `AccessTokenAuthorizer`. The `AccessTokenAuthorizer` requires a `access_token` and `base_url`. It optionally takes a `server_type` (see [Server-Type Detection](#server-type-detection)).

> **Upgrading from 2.0.0:** the second positional parameter changed from `server_type` to `base_url` in 2.0.1, which shipped as a patch release and did not document the change. Code written for 2.0.0 as `AccessTokenAuthorizer(token, "secret_server")` still runs on 2.0.1, but silently uses `"secret_server"` as the base URL. Since 3.0.0 `server_type` is keyword-only, so that call raises `TypeError` instead of failing quietly.

##### With Secret Server
```python
from delinea.secrets.server import AccessTokenAuthorizer

authorizer = AccessTokenAuthorizer("AgJ1slfZsEng9bKsssB-tic0Kh8I...", "https://hostname/SecretServer")
```

##### With Platform

```python
from delinea.secrets.server import AccessTokenAuthorizer

authorizer = AccessTokenAuthorizer("AgJ1slfZsEng9bKsssB-tic0Kh8I...", "https://platform.delinea.app")
```

#### Server-Type Detection

Unless given an explicit `server_type`, an authorizer detects whether the `base_url` points at a Secret Server or a Platform instance by probing its health-check endpoints (`/api/v1/healthcheck` then `/health`). `AccessTokenAuthorizer` probes when it is constructed; `PasswordGrantAuthorizer` and `DomainPasswordGrantAuthorizer` probe on their first token request, so constructing one does not validate the URL. The result is cached per `base_url` for the lifetime of the process, so the probe pair normally fires once per `base_url`. `SecretServerV0` accepts the same `server_type` keyword and passes it to the authorizer it builds.

You can skip detection entirely by passing an explicit `server_type` of either `"secret_server"` or `"platform"`. When supplied, no health-check probe is issued. The parameter is **keyword-only** — write `server_type="platform"`, never positionally — on every class that accepts it. Skipping detection is recommended whenever the probes cannot get through, or are simply not wanted:

- Callers that run each lookup in a fresh, short-lived process (for example, some Ansible lookup-plugin runtimes). A fresh process cannot benefit from the in-process cache, and the repeated unauthenticated probes can be rate-limited to `403` by the Delinea Platform WAF.
- On-premises deployments where IIS intercepts the anonymous probe and answers `302` to a login page — see [When detection fails](#when-detection-fails).

```python
from delinea.secrets.server import AccessTokenAuthorizer

# No health-check probe is issued; the type is used directly.
authorizer = AccessTokenAuthorizer(
    "AgJ1slfZsEng9bKsssB-tic0Kh8I...",
    "https://platform.delinea.app",
    server_type="platform",
)
```

An explicit `server_type` applies only to the instance that supplies it and is never written to the shared cache, so it cannot affect auto-detection for other authorizers. If a `base_url` is ever re-provisioned to a different server type while a long-lived process is running, call `Authorizer.clear_server_type_cache()` to force re-detection.

##### When detection fails

If neither health-check endpoint reports a healthy server, the SDK raises `SecretServerError` before any credentials are sent.

Probes are never followed across a redirect, because a login page returning `200` would otherwise be read as an unhealthy server and hide the real cause. When a probe is redirected the error says so and names the destination:

```text
Unable to detect server type: the health check was redirected to
https://hostname/Login.aspx (likely a login page). Pass
server_type='secret_server' or 'platform' to skip detection.
```

This is most often IIS sending the anonymous request to `Login.aspx` because site-level Windows Authentication or a forms-auth `<location>` rule catches `/api/*`. Passing an explicit `server_type` is the immediate fix. The health-check endpoint is meant to be anonymous, so a redirect is also worth raising with whoever owns the IIS configuration.

## Secret Server Cloud

The SDK API requires an `Authorizer` and either a `tenant` or a `base_url`. In the case of plaform authentication, only a `base_url` is supported.

`tenant` simplifies the configuration when using Secret Server Cloud by assuming the default folder structure and creating the _base URL_ from a template that takes the `tenant` and an optional top-level domain (TLD) that defaults to `com`, as parameters.

### Useage

Instantiate the `SecretServerCloud` class with `tenant` or `base_url`, along with an `Authorizer` (when providing `tenant`, yoou may optionally include a `tld`). To retrieve a secret, pass an integer `id` to `get_secret()` which will return the secret as a `dict`.

##### With Secret Server
```python
from delinea.secrets.server import SecretServerCloud

secret_server = SecretServerCloud(tenant=tenant, authorizer=authorizer)

secret = secret_server.get_secret(os.getenv("TSS_SECRET_ID"))

serverSecret = ServerSecret(**secret)

print(f"username: {serverSecret.fields['username'].value}\npassword: {serverSecret.fields['password'].value}")
```

##### With Platform

```python
from delinea.secrets.server import SecretServerCloud

secret_server = SecretServerCloud(authorizer=authorizer, base_url="https://platform.delinea.app")

secret = secret_server.get_secret(os.getenv("TSS_SECRET_ID"))

serverSecret = ServerSecret(**secret)

print(f"username: {serverSecret.fields['username'].value}\npassword: {serverSecret.fields['password'].value}")
```

The SDK API also contains a `Secret` `@dataclass` containing a subset of the Secret's attributes and a dictionary of all the fields keyed by the Secret's `slug`.

## Initializing SecretServer

### Useage

> NOTE: In v1.0.0 `SecretServer` replaces `SecretServerV1`. However, `SecretServerV0` is available to use instead, for backwards compatibility with v0.0.5 and v0.0.6.

To instantiate the `SecretServer` class, it requires a `base_url`, an `Authorizer` object (see above), and an optional `api_path_uri` (defaults to `"/api/v1"`)

##### With Secret Server
```python
from delinea.secrets.server import SecretServer

secret_server = SecretServer("https://hostname/SecretServer", authorizer=authorizer)
```

##### With Platform

```python
from delinea.secrets.server import SecretServer

secret_server = SecretServer(base_url="https://platform.delinea.app", authorizer=authorizer)
```

Secrets can be fetched using the `get_secret` method, which takes an integer `id` of the secret and returns a `dict`:

```python
secret = secret_server.get_secret(os.getenv("TSS_SECRET_ID"))

serverSecret = ServerSecret(**secret)

print(f"username: {serverSecret.fields['username'].value}\npassword: {serverSecret.fields['password'].value}")
```

Alternatively, you can use pass the json to `ServerSecret` which returns a `dataclass` object representation of the secret:

```shell
from delinea.secrets.server import ServerSecret

secret = ServerSecret(**secret_server.get_secret(os.getenv("TSS_SECRET_ID")))

username = secret.fields['username'].value
```

It is also now possible to fetch a secret by the secrets `path` using the `get_secret_by_path` method on the `SecretServer` object. This, too, returns a `dict`.

```python
secret = secret_server.get_secret_by_path(r"TSS_SECRET_PATH")

serverSecret = ServerSecret(**secret)

print(f"username: {serverSecret.fields['username'].value}\npassword: {serverSecret.fields['password'].value}")
```

> Note: Add a try-except block to the code to get more detailed error messages.

```python
from delinea.secrets.server import SecretServerError

try:
    # code...
except SecretServerError as e:
    print(e.message)
```

> Note: The `path` must be the full folder path and name of the secret.

### File Attachments

`get_secret()` and `get_secret_by_path()` fetch file attachments by default.
Every field with a non-zero `fileAttachmentId` gets its `itemValue` replaced
with a `FileAttachment` (importable from `delinea.secrets.server`): the file's
bytes, plus `.content`, `.text` and `.encoding`. Releases up to 2.0.1 stored
the `requests.Response` there, so every other member of it — `.status_code`,
`.json()`, `.headers`, `.ok`, `.iter_content()` — now raises `AttributeError`.
`.text` prefers a strict UTF-8 decode when the server declares Latin-1, which
`requests` reports for any `text/*` body with no charset. `.filename` and
`.encoding` carry what the server sent, or `None`.

```python
import os
import pathlib

secret = secret_server.get_secret(os.getenv("TSS_SECRET_ID"))
downloads = pathlib.Path("downloads")
downloads.mkdir(parents=True, exist_ok=True)

for item in secret["items"]:
    if item.get("fileAttachmentId"):
        # `filename` is server data: name the file yourself rather than
        # joining it into a path, and do not rely on the key being present.
        target = downloads / f"{secret['id']}_{item['slug']}"
        target.write_bytes(item["itemValue"].content)
```

Use `.content` for any attachment, and `.text` only for one you know is text.
An empty attachment is falsy, like any empty `bytes`, so test
`item.get("fileAttachmentId")` rather than the value itself. Some templates
omit that key entirely, which is why the example reads it with `.get`.

Treat the value as read-once. Every `bytes` operation on it — slicing,
concatenation, `.strip()` — returns plain `bytes` and drops `.filename`,
`.encoding` and `.text`, and two attachments with identical contents compare
equal whatever their filenames. Copy what you need out before transforming.

`repr()` of a `FileAttachment` reports its size, not its contents, so an
attachment cannot leak through a log line. The secret's other field values are
ordinary strings, so never log the secret itself. `json.dumps()` of a fetched
secret raises on the bytes: pass `fetch_file_attachments=False` for JSON.

## Using Self-Signed Certificates

When using a self-signed certificate for SSL, the `REQUESTS_CA_BUNDLE` environment variable should be set to the path of the certificate (in `.pem` format). This will negate the need to ignore SSL certificate verification, which makes your application vunerable. Please reference the [`requests` documentation](https://docs.python.org/3/library/ssl.html) for further details on the `REQUESTS_CA_BUNDLE` environment variable, should you require it.

## Create a Build Environment (optional)

The SDK requires [Python 3.10](https://www.python.org/downloads/) or higher.

First, ensure Python is in `$PATH`, then run:

```shell
# Clone the repo
git clone https://github.com/DelineaXPM/python-tss-sdk
cd python-tss-sdk

# Create a virtual environment
python -m venv venv
. venv/bin/activate

# Install dependencies (runtime + test/build tooling)
python -m pip install --upgrade "pip>=26.2"
pip install -r requirements-dev.txt
```

Most of the suite runs offline and needs no credentials or network access:

```shell
pytest tests/test_security_phase1.py tests/test_security_phase2.py \
       tests/test_security_phase4.py tests/test_server_detection_cache.py
```

Valid credentials are required to run the live integration tests in `tests/test_server.py`. The credentials should be stored in environment variables or in a `.env` file:

```shell
export TSS_USERNAME=myusername
export TSS_PASSWORD=mysecretpassword
export TSS_TENANT=mytenant
export TSS_SECRET_ID=42
export TSS_SECRET_PATH=\Test Secrets\SecretName
export TSS_FOLDER_ID=1
export TSS_FOLDER_PATH=\Test Secrets
```

The tests assume that the user associated with the specified `TSS_USERNAME` and `TSS_PASSWORD` can read the secret to be fetched, and that the Secret itself contains `username` and `password` fields.

To run the tests with `tox`:

```shell
tox
```

To build the package, use [Flit](https://flit.readthedocs.io/en/latest/):

```shell
flit build
```
