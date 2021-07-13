import os

from thycotic.secrets.server import (
    SecretServerCloud,
    SecretServerError,
)

if __name__ == "__main__":

    creds = {
        "username": os.getenv("TSS_USERNAME"),
        "password": os.getenv("TSS_PASSWORD"),
        "tenant": os.getenv("TSS_TENTANT"),
    }

    secret_server = SecretServerCloud(**creds)

    try:
        secret = secret_server.get_secret(1)
        print(
            f"""username: {secret.fields['username'].value}
                password: {secret.fields['password'].value}
                template: {secret.secret_template_name}"""
        )
    except SecretServerError as error:
        print(error.response.text)
