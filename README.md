# The Thycotic Secret Server Python SDK

The [Thycotic](https://thycotic.com/)
[Secret Server](https://thycotic.com/products/secret-server/)
Python SDK contains classes that interact with Secret Server via the REST API.

## Install

```shell
python -m pip install python-tss-sdk
```

## Settings

The SDK API requires a `username` and `password`, and either a `base_url` or `tenant`.

`tenant` simplifies the configuration when using Secret Server Cloud by assuming
the default folder structure and creating the base URL from a template that takes
the `tenant` and an optional top-level domain (TLD) that defaults to `com`, as
parameters.

When `base_url` is used, the default `api_path_uri` and `token_path_uri` may be
overridden. The defaults values are `/api/v1` and `/oauth2/token`,
respectively.

## Use

Simply instantiate `SecretServer` or `SecretServerCloud`:

```python
from thycotic.secrets.server import SecretServer

secret_server = SecretServer("https://hostname/SecretServer", "myusername", "mypassword")
```

Or:

```python
from thycotic.secrets.server import SecretServerCloud

secret_server = SecretServerCloud("mytenant", "myusername", "mypassword")
```

Then pass an integer `id` to `get_secret()` which will return the secret as a JSON
encoded string. The SDK API also contains a `Secret` `@dataclass` containing
a subset of the Secret's attributes and a dictionary of all the fields keyed
by the Secret's `slug`.

```python
from thycotic.secrets.dataclasses import Secret

secret = ServerSecret(**secret_server.get_secret(1))

print(f"username: {secret.fields['username'].value}\npassword: {secret.fields['password'].value}")
```

## Create a Build Environment (optional)

The SDK requires [Python 3.6](https://www.python.org/downloads/) or higher,
and the [Requests](https://2.python-requests.org/en/master/) library.

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

They also assume that the user associated with the specified `username` and `password`
can read the secret with ID `1`, and that the Secret itself contains `username` and
`password` fields.

Create `server_config.json`:

```json
{
    "username": "app_user",
    "password": "Passw0rd!",
    "tenant": "mytenant"
}
```

Finally, run `pytest` then build the package:

```shell
pytest
python setup.py bdist
```
