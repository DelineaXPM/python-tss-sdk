import os
from conftest import secret_server

from delinea.secrets.server import (
    SecretServer,
    SecretServerCloud,
    SecretServerError,
    PasswordGrantAuthorizer,
    ServerSecret,
)

if __name__ == "__main__":
    tenant = os.getenv("TSS_TENANT")
    base_url = f"https://{tenant}.secretservercloud.com"
    authorizer = PasswordGrantAuthorizer(
        base_url,
        os.getenv("TSS_USERNAME"),
        os.getenv("TSS_PASSWORD"),
    )

    secret_server_cloud = SecretServerCloud(tenant=tenant, authorizer=authorizer)

    try:
        secret = secret_server_cloud.get_secret(os.getenv("TSS_SECRET_ID"))
        serverSecret = ServerSecret(**secret)
        print(
            f"""username: {serverSecret.fields['username'].value}
                password: {serverSecret.fields['password'].value}
                template: {serverSecret.secret_template_name}"""
        )
    except SecretServerError as error:
        print(error.response.text)
