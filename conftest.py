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
    }


@pytest.fixture
def authorizer(env_vars):
    return PasswordGrantAuthorizer(
        f"https://{env_vars['tenant']}.secretservercloud.com",
        env_vars["username"],
        env_vars["password"],
    )


@pytest.fixture
def secret_server(env_vars, authorizer):
    return SecretServerCloud(env_vars["tenant"], authorizer)
