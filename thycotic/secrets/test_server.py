import pytest

from thycotic.secrets.server import (
    AccessTokenAuthorizer,
    SecretServer,
    SecretServerV1,
    SecretServerAccessError,
    SecretServerError,
    ServerSecret,
)


def test_bad_url(server_json, authorizer):
    bad_server = SecretServer(
        f"https://{server_json['tenant']}.secretservercloud.com/nonexistent",
        server_json["username"],
        server_json["password"],
    )
    with pytest.raises(SecretServerError):
        bad_server.get_secret(1)


def test_base_url(server_json):
    assert SecretServer(
        f"https://{server_json['tenant']}.secretservercloud.com/",
        server_json["username"],
        server_json["password"],
    )


def test_token_url(server_json, authorizer):
    assert (
        authorizer.token_url
        == f"https://{server_json['tenant']}.secretservercloud.com/oauth2/token"
    )


def test_api_url(secret_server, server_json):
    assert (
        secret_server.api_url
        == f"https://{server_json['tenant']}.secretservercloud.com/api/v1"
    )


def test_access_token_authorizer(server_json, authorizer):
    assert SecretServerV1(
        f"https://{server_json['tenant']}.secretservercloud.com/",
        AccessTokenAuthorizer(authorizer.get_access_token()),
    ).get_secret(1)["id"] == 1


def test_server_secret(secret_server):
    assert ServerSecret(**secret_server.get_secret(1)).id == 1


def test_nonexistent_secret(secret_server):
    with pytest.raises(SecretServerAccessError):
        secret_server.get_secret(1000)
