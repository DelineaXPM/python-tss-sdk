import pytest

from thycotic.secrets.server import (
    SecretServer,
    SecretServerCloud,
    SecretServerAccessError,
    SecretServerError,
    ServerSecret,
)


def test_bad_url(server_json):
    bad_server = SecretServer(
        f"https://{server_json['tenant']}.secretservercloud.com/nonexistent",
        server_json["username"],
        server_json["password"],
    )
    with pytest.raises(SecretServerError):
        bad_server.get_secret(1)


def secret_server(json):
    return SecretServerCloud(**json)


def test_token_url(server_json):
    assert (
        secret_server(server_json).token_url
        == f"https://{server_json['tenant']}.secretservercloud.com/oauth2/token"
    )


def test_api_url(server_json):
    assert (
        secret_server(server_json).api_url
        == f"https://{server_json['tenant']}.secretservercloud.com/api/v1"
    )


def test_get_secret(server_json):
    assert ServerSecret(**secret_server(server_json).get_secret(1)).id == 1


def test_get_nonexistent_secret(server_json):
    with pytest.raises(SecretServerAccessError):
        secret_server(server_json).get_secret(1000)
