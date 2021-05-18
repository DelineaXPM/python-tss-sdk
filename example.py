import json

from thycotic.secrets.dataclasses import ServerSecret
from thycotic.secrets.server import (
    SecretServerAccessError,
    SecretServerCloud,
    SecretServerError,
)

if __name__ == "__main__":
    with open("test_server.json") as f:
        secret_server = SecretServerCloud(**json.load(f))
    try:
        secret = ServerSecret(**secret_server.get_secret(1))
        print(
            f"""username: {secret.fields['username'].value}
password: {secret.fields['password'].value}
template: {secret.secret_template_name}"""
        )
    except SecretServerAccessError as error:
        print(error.message)
    except SecretServerError as error:
        print(error.response.text)
