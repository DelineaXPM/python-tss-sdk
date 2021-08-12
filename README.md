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

There are three ways in which you can authorize the `SecretServer` class to fetch secrets.

- Password Authorization (with `PasswordGrantAuthorizer`)
- Domain Authorization (with `DomainPasswordGrantAuthorizer`)
- Access Token Authorization (with `AccessTokenAuthorizer`)

### Usage

#### Password Authorization

If using traditional `username` and `password` authentication to log in to your Secret Server, you can pass the `PasswordGrantAuthorizer` into the `SecretServer` class at instantiation. The `PasswordGrantAuthorizer` requires a `base_url`, `username`, and `password`. It optionally takes a `token_path_uri`, but defaults to `/oauth2/token`.

```python
from thycotic.secrets.server import PasswordGrantAuthorizer

authorizer = PasswordGrantAuthorizer("https://hostname/SecretServer", "myusername", "mypassword")
```

#### Domain Authorization

To use a domain credential, use the `DomainPasswordGrantAuthorizer`. It requires a `base_url`, `username`, `domain`, and `password`. It optionally takes a `token_path_uri`, but defaults to `/oauth2/token`.

```python
from thycotic.secrets.server import DomainPasswordGrantAuthorizer

authorizer = DomainPasswordGrantAuthorizer("https://hostname/SecretServer", "myusername", "mydomain", "mypassword")
```

#### Access Token Authorization

If you already have an `access_token`, you can pass directly via the `AccessTokenAuthorizer`.

```python
from thycotic.secrets.server import AccessTokenAuthorizer

authorizer = AccessTokenAuthorizer("AgJ1slfZsEng9bKsssB-tic0Kh8I...")
```

### Initializing SecretServer

> NOTE: In v1.0.0 `SecretServer` replaces `SecretServerV1`. However, `SecretServerV0` is available to use instead, for backwards compatibility with v0.0.5 and v0.0.6.

To instantiate the `SecretServer` class, it requires a `base_url`, `authorizer` object (see above), and an optional `api_path_uri` (defaults to `"/api/v1"`)

```python
from thycotic.secrets.server import SecretServer

secret_server = SecretServer("https://hostname/SecretServer", my_authorizer)
```

Secrets can be fetched using the `get_secret` method, which takes an integer `id` of the secret and, returns a `json` object:

```python
secret = secret_server.get_secret(1)

print(f"username: {secret.fields['username'].value}\npassword: {secret.fields['password'].value}")
```

Alternatively, you can use pass the json to `ServerSecret` which returns a `dataclass` object representation of the secret:

```shell
from thycotic.secrets.server import ServerSecret

secret = ServerSecret(**secret_server.get_secret(1))

username = secret.fields['username'].value
```

## Create a Build Environment (optional)

The SDK requires [Python 3.6](https://www.python.org/downloads/) or higher.

First, ensure Python is in `$PATH`, then run:

```shell
# Clone the repo
git clone https://github.com/thycotic/python-tss-sdk
cd python-tss-sdk

# Create a virtual environment
python -m venv venv
. venv/bin/activate

# Install dependencies
python -m pip install --upgrade pip
pip install -r requirements.txt
```

Valid credentials are required to run the unit tests. The credentials should be stored in environment variables or in a `.env` file:

```shell
export TSS_USERNAME=myusername
export TSS_PASSWORD=mysecretpassword
export TSS_TENANT=mytenant
```

The tests assume that the user associated with the specified `TSS_USERNAME` and `TSS_PASSWORD` can read the secret with ID `1`, and that the Secret itself contains `username` and `password` fields.

> Note: The secret ID can be changed manually in `test_server.py` to a secret ID that the user can access.

To run the tests with `tox`:

```shell
tox
```

To build the package, use [Flit](https://flit.readthedocs.io/en/latest/):

```shell
flit build
```
