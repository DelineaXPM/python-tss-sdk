import json
import pytest

from thycotic.secrets.server import PasswordGrantAuthorizer, SecretServerCloud


@pytest.fixture
def server_json():
    with open("test_server.json") as f:
        return json.load(f)


@pytest.fixture
def secret_server(server_json):
    return SecretServerCloud(**server_json)


@pytest.fixture
def authorizer(server_json):
    return PasswordGrantAuthorizer(
        f"https://{server_json['tenant']}.secretservercloud.com/oauth2/token",
        server_json["username"],
        server_json["password"],
    )
