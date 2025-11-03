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

### Usage


#### Password Authorization

If using traditional `username` and `password` authentication to log in to your Secret Server either directly or through Platform, you can pass the `PasswordGrantAuthorizer` into the `SecretServer` class at instantiation. The `PasswordGrantAuthorizer` requires a `base_url`, `username`, and `password`. It optionally takes a `token_path_uri`, but defaults to `/oauth2/token` or `/identity/api/oauth2/token/xpmplatform`, depending on whether a secret server or platform is used for authentication.

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

To use a domain credential, use the `DomainPasswordGrantAuthorizer`. It requires a `base_url`, `username`, `domain`, and `password`. It optionally takes a `token_path_uri`, but defaults to `/oauth2/token`. It is applicable only when authentication is done using a secret server.

```python
from delinea.secrets.server import DomainPasswordGrantAuthorizer

authorizer = DomainPasswordGrantAuthorizer("https://hostname/SecretServer", os.getenv("myusername"), os.getenv("mydomain"), os.getenv("password"))
```

#### Access Token Authorization

If you already have an `access_token` of Secret Server or Platform user, you can pass directly via the `AccessTokenAuthorizer`. The `AccessTokenAuthorizer` requires a `access_token` and `base_url`.

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

## Secret Server Cloud

The SDK API requires an `Authorizer` and either a `tenant` or a `base_url`. In the case of plaform authentication, only a `base_url` is supported.

`tenant` simplifies the configuration when using Secret Server Cloud by assuming the default folder structure and creating the _base URL_ from a template that takes the `tenant` and an optional top-level domain (TLD) that defaults to `com`, as parameters.

### Useage

Instantiate the `SecretServerCloud` class with `tenant` or `base_url`, along with an `Authorizer` (when providing `tenant`, yoou may optionally include a `tld`). To retrieve a secret, pass an integer `id` to `get_secret()` which will return the secret as a JSON encoded string.

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

Secrets can be fetched using the `get_secret` method, which takes an integer `id` of the secret and, returns a `json` object:

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

It is also now possible to fetch a secret by the secrets `path` using the `get_secret_by_path` method on the `SecretServer` object. This, too, returns a `json` object.

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

## Using Self-Signed Certificates

When using a self-signed certificate for SSL, the `REQUESTS_CA_BUNDLE` environment variable should be set to the path of the certificate (in `.pem` format). This will negate the need to ignore SSL certificate verification, which makes your application vunerable. Please reference the [`requests` documentation](https://docs.python.org/3/library/ssl.html) for further details on the `REQUESTS_CA_BUNDLE` environment variable, should you require it.

## Create a Build Environment (optional)

The SDK requires [Python 3.8](https://www.python.org/downloads/) or higher.

First, ensure Python is in `$PATH`, then run:

```shell
# Clone the repo
git clone https://github.com/DelineaXPM/python-tss-sdk
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
