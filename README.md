# The Thycotic Secret Server Python SDK

![PyPI Version](https://img.shields.io/pypi/v/python-tss-sdk) ![License](https://img.shields.io/github/license/thycotic/python-tss-sdk) ![Python Versions](https://img.shields.io/pypi/pyversions/python-tss-sdk)

The [Thycotic](https://thycotic.com/) [Secret Server](https://thycotic.com/products/secret-server/) Python SDK contains classes that interact with Secret Server via the REST API.

## Install

```shell
python -m pip install python-tss-sdk
```

## Secret Server Cloud

The SDK API requires a `username`, `password`, and a `tenant`.

`tenant` simplifies the configuration when using Secret Server Cloud by assuming the default folder structure and creating the _base URL_ from a template that takes the `tenant` and an optional top-level domain (TLD) that defaults to `com`, as parameters.

### Use

Instantiate the `SecretServerCloud` class with `tenant` , `username` and `password` and (optionally include a `tld`). To retrieve a secret, pass an integer `id` to `get_secret()` which will return the secret as a JSON encoded string.

```python
from thycotic.secrets.server import SecretServerCloud

secret_server = SecretServerCloud("mytenant", "myusername", "mypassword")

secret = secret_server.get_secret(1)
```

The SDK API also contains a `Secret` `@dataclass` containing a subset of the Secret's attributes and a dictionary of all the fields keyed by the Secret's `slug`.

## Secret Server

There are two ways in which you can authorize the `SecretServer` class to fetch secrets.

- Password Authorization (with `PasswordGrantAuthorizer`)
- Domain Authorization (with `DomainPasswordGrantAuthorizer`)

### Usage

#### Password Authorization

If using traditional `username` and `password` authentication to log in to your Secret Server, you can pass the `PasswordGrantAuthorizer` in into the `SecretServer` class at instantiation. The `PasswordGrantAuthorizer` requires a `token_url`, `username`, and `password`.

```python
from thycotic.secrets.server import PasswordGrantAuthorizer

authorizer = PasswordGrantAuthorizer("https://hostname/SecretServer", "myusername", "mypassword")
```

#### Domain Authorization

To use a domain credential, use the `DomainPasswordGrantAuthorizer`. It requires a `token_url`, `username`, `domain`, and `password`.

```python
from thycotic.secrets.server import DomainPasswordGrantAuthorizer

authorizer = DomainPasswordGrantAuthorizer("https://hostname/SecretServer", "myusername", "mydomain", "mypassword")
```

### Initializing SecretServer

_NOTE: In v0.0.6 `SecretServerV1` replaces `SecretServer`. However, `SecretServer` is still available for backwards compatibility with v0.0.5 and earlier. In version 0.1.0, the current implementation will be deprecated and `SecretServerV1` will become `SecretServer`._

To instantiate the `SecretServerV1` class, it requires a `base_url`, `authorizer` object (see above), and an optional `api_path_uri` (defaults to `"/api/v1"`)

```python
from thycotic.secrets.server import ServerSecretV1

secret_server = SecretServerV1("https://hostname/SecretServer", my_authorizer)
```

Secrets can be fetched using the `get_secret` method, which takes an integer `id` of the secret:

```python
secret = secret_server.get_secret(1)

print(f"username: {secret.fields['username'].value}\npassword: {secret.fields['password'].value}")
```

## Create a Build Environment (optional)

The SDK requires [Python 3.6](https://www.python.org/downloads/) or higher, and the [Requests](https://2.python-requests.org/en/master/) library.

First, ensure Python 3.6 is in `$PATH` then run:

```shell
git clone https://github.com/thycotic/python-tss-sdk
cd python-tss-sdk
python -m venv venv
. venv/bin/activate
pip install -r requirements.txt
```

Both `example.py` and the unit tests pull the settings from a JSON file.

```python
with open('server_config.json') as f:
    config = json.load(f)
```

They also assume that the user associated with the specified `username` and `password` can read the secret with ID `1`, and that the Secret itself contains `username` and `password` fields.

Create `server_config.json`:

```json
{
  "username": "app_user",
  "password": "Passw0rd!",
  "tenant": "mytenant"
}
```

Finally, run `pytest`, then build the package:

```shell
pytest

# Build
flit build
```
