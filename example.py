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
        # Never print secret values; mask them in any console/log output.
        print(f"""username: {serverSecret.fields['username'].value}
                password: ********
                template: {serverSecret.secret_template_name}""")
    except SecretServerError as error:
        # ``.response`` is None for errors raised before or without an HTTP
        # response (e.g. server-type detection failure); ``.message`` is
        # always populated and already excludes any full response body.
        print(error.message)
        if error.response is not None:
            print(f"HTTP {error.response.status_code}")
