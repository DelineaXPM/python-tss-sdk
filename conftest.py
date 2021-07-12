import os
import pytest

from thycotic.secrets.server import PasswordGrantAuthorizer, SecretServerCloud


@pytest.fixture
def env_vars():
    return {
        "username": os.getenv("tss_username"),
        "password": os.getenv("tss_password"),
        "tenant": os.getenv("tss_tenant"),
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
    return SecretServerCloud(env_vars['tenant'], authorizer)
