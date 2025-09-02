import os
import pytest
from dotenv import load_dotenv
from delinea.secrets.server import PasswordGrantAuthorizer, SecretServerCloud

load_dotenv()


@pytest.fixture
def env_vars():
    return {
        "username": os.getenv("TSS_USERNAME"),
        "password": os.getenv("TSS_PASSWORD"),
        "tenant": os.getenv("TSS_TENANT"),
        "secret_id": os.getenv("TSS_SECRET_ID"),
        "secret_path": os.getenv("TSS_SECRET_PATH"),
        "folder_id": os.getenv("TSS_FOLDER_ID"),
        "folder_path": os.getenv("TSS_FOLDER_PATH"),
    }


@pytest.fixture
def platform_env_vars():
    return {
        "username": os.getenv("TSS_PLATFORM_USERNAME"),
        "password": os.getenv("TSS_PLATFORM_PASSWORD"),
        "base_url": os.getenv("TSS_PLATFORM_BASE_URL"),
        "secret_id": os.getenv("TSS_SECRET_ID"),
        "secret_path": os.getenv("TSS_SECRET_PATH"),
        "folder_id": os.getenv("TSS_FOLDER_ID"),
        "folder_path": os.getenv("TSS_FOLDER_PATH"),
    }


@pytest.fixture
def authorizer(env_vars):
    return PasswordGrantAuthorizer(
        f"https://{env_vars['tenant']}.secretservercloud.com",
        env_vars["username"],
        env_vars["password"],
    )


@pytest.fixture
def platform_authorizer(platform_env_vars):
    from delinea.secrets.server import PasswordGrantAuthorizer

    return PasswordGrantAuthorizer(
        platform_env_vars["base_url"],
        platform_env_vars["username"],
        platform_env_vars["password"],
    )


@pytest.fixture
def secret_server(env_vars, authorizer):
    return SecretServerCloud(env_vars["tenant"], authorizer)


@pytest.fixture
def platform_server(platform_env_vars, platform_authorizer):
    from delinea.secrets.server import SecretServer

    return SecretServer(platform_env_vars["base_url"], platform_authorizer)
