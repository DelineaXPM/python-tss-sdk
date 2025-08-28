import pytest

from delinea.secrets.server import (
    AccessTokenAuthorizer,
    SecretServer,
    SecretServerClientError,
    SecretServerError,
    ServerSecret,
    ServerFolder,
)


def test_bad_url(env_vars, authorizer):
    bad_server = SecretServer(
        f"https://{env_vars['tenant']}.secretservercloud.com/nonexistent",
        authorizer,
    )
    with pytest.raises(SecretServerError):
        bad_server.get_secret(env_vars["secret_id"])


def test_token_url(env_vars, authorizer):
    authorizer.get_access_token()
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


def test_server_folder_by_path(env_vars, secret_server):
    assert ServerFolder(
        **secret_server.get_folder_by_path(env_vars["folder_path"])
    ).id == int(env_vars["folder_id"])


def test_nonexistent_secret(secret_server):
    with pytest.raises(SecretServerClientError):
        secret_server.get_secret(1000)


def test_nonexistent_folder(secret_server):
    with pytest.raises(SecretServerClientError):
        secret_server.get_folder(1000)


def test_server_secret_ids_by_folderid(env_vars, secret_server):
    assert type(secret_server.get_secret_ids_by_folderid(env_vars["folder_id"])) is list


def test_server_child_folder_ids_by_folderid(env_vars, secret_server):
    assert (
        type(secret_server.get_child_folder_ids_by_folderid(env_vars["folder_id"]))
        is list
    )

def test_platform_bad_url(platform_env_vars, platform_authorizer):
    bad_server = SecretServer(
        f"{platform_env_vars['base_url']}/nonexistent",
        platform_authorizer,
    )
    with pytest.raises(SecretServerError):
        bad_server.get_secret(platform_env_vars["secret_id"])

def test_platform_token_url(platform_env_vars, platform_authorizer):
    platform_authorizer.get_access_token()
    assert (
        platform_authorizer.token_url
        == f"{platform_env_vars['base_url']}/identity/api/oauth2/token/xpmplatform"
    )

def test_platform_api_url(platform_server, platform_env_vars):
    assert (
        platform_server.api_url
        == f"{platform_env_vars['base_url']}/api/v1"
    )

def test_platform_access_token_authorizer(platform_env_vars, platform_authorizer):
    assert SecretServer(
        platform_env_vars["base_url"],
        AccessTokenAuthorizer(platform_authorizer.get_access_token(), 'platform'),
    ).get_secret(platform_env_vars["secret_id"])["id"] == int(platform_env_vars["secret_id"])

def test_platform_server_secret(platform_env_vars, platform_server):
    assert ServerSecret(**platform_server.get_secret(platform_env_vars["secret_id"])).id == int(
        platform_env_vars["secret_id"]
    )

def test_platform_server_secret_by_path(platform_env_vars, platform_server):
    assert ServerSecret(
        **platform_server.get_secret_by_path(platform_env_vars["secret_path"])
    ).id == int(platform_env_vars["secret_id"])

def test_platform_server_folder_by_path(platform_env_vars, platform_server):
    assert ServerFolder(
        **platform_server.get_folder_by_path(platform_env_vars["folder_path"])
    ).id == int(platform_env_vars["folder_id"])

def test_platform_nonexistent_secret(platform_server):
    with pytest.raises(SecretServerClientError):
        platform_server.get_secret(1000)

def test_platform_nonexistent_folder(platform_server):
    with pytest.raises(SecretServerClientError):
        platform_server.get_folder(1000)

def test_platform_server_secret_ids_by_folderid(platform_env_vars, platform_server):
    assert type(platform_server.get_secret_ids_by_folderid(platform_env_vars["folder_id"])) is list

def test_platform_server_child_folder_ids_by_folderid(platform_env_vars, platform_server):
    assert (
        type(platform_server.get_child_folder_ids_by_folderid(platform_env_vars["folder_id"]))
        is list
    )
