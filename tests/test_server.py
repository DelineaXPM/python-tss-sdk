import pytest

from delinea.secrets.server import (
    AccessTokenAuthorizer,
    SecretServer,
    SecretServerClientError,
    SecretServerError,
    ServerSecret,
)


def test_bad_url(env_vars, authorizer):
    bad_server = SecretServer(
        f"https://{env_vars['tenant']}.secretservercloud.com/nonexistent",
        authorizer,
    )
    with pytest.raises(SecretServerError):
        bad_server.get_secret(env_vars["secret_id"])


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
    assert SecretServer(
        f"https://{env_vars['tenant']}.secretservercloud.com/",
        AccessTokenAuthorizer(authorizer.get_access_token()),
    ).get_secret(env_vars["secret_id"])["id"] == int(env_vars["secret_id"])


def test_server_secret(env_vars, secret_server):
    assert ServerSecret(**secret_server.get_secret(env_vars["secret_id"])).id == int(
        env_vars["secret_id"]
    )


def test_server_secret_by_path(env_vars, secret_server):
    assert ServerSecret(
        **secret_server.get_secret_by_path(env_vars["secret_path"])
    ).id == int(env_vars["secret_id"])


def test_nonexistent_secret(secret_server):
    with pytest.raises(SecretServerClientError):
        secret_server.get_secret(1000)


def test_server_secret_ids_by_folderid(env_vars, secret_server):
    assert type(secret_server.get_secret_ids_by_folderid(env_vars["folder_id"])) is list
