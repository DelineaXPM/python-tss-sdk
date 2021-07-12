import pytest

from thycotic.secrets.server import (
    AccessTokenAuthorizer,
    SecretServer,
    SecretServerV1,
    SecretServerClientError,
    SecretServerError,
    ServerSecret,
)


def test_bad_url(env_vars):
    bad_server = SecretServer(
        f"https://{env_vars['tenant']}.secretservercloud.com/nonexistent",
        env_vars["username"],
        env_vars["password"],
    )
    with pytest.raises(SecretServerError):
        bad_server.get_secret(1)


def test_base_url(env_vars):
    assert SecretServer(
        f"https://{env_vars['tenant']}.secretservercloud.com/",
        env_vars["username"],
        env_vars["password"],
    )


def test_token_url(env_vars, authorizer):
    assert (
        authorizer.token_url
        == f"https://{env_vars['tenant']}.secretservercloud.com/oauth2/token"
    )


def test_api_url(secret_server, env_vars):
    assert (
        secret_server.api_url
        == f"https://{env_vars['tenant']}.secretservercloud.com/api/v1"
    )


def test_access_token_authorizer(env_vars, authorizer):
    assert SecretServerV1(
        f"https://{env_vars['tenant']}.secretservercloud.com/",
        AccessTokenAuthorizer(authorizer.get_access_token()),
    ).get_secret(1)["id"] == 1


def test_server_secret(secret_server):
    assert ServerSecret(**secret_server.get_secret(1)).id == 1


def test_nonexistent_secret(secret_server):
    with pytest.raises(SecretServerClientError):
        secret_server.get_secret(1000)
