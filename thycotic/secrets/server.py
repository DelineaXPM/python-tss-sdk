""" The Thycotic Secret Server Python SDK API

    Provides access to the Secret Server REST API using OAuth2 bearer token authentication.

    Typical usage:
        secret_server = SecretServer(
            <base_url: str>,
            <username: str>,
            <password: str>,
            [api_path_uri: :attr:`SecretServer.API_PATH_URI`,
            [token_path_uri: :attr:`SecretServer.TOKEN_PATH_URI`])
        secret = Secret.from_json(secret_server.get_secret(1))

    There is also a variant class for Secret Server Cloud:
        secret_server = SecretServerCloud(
            <tenant: str>,
            <username: str>,
            <password: str>,
            [tld: :attr:`SecretServerCloud.DEFAULT_TLD`])"""

import json
import requests

from datetime import datetime, timedelta


class SecretServerError(Exception):
    """ An Exception that includes a message and the server response """

    def __init__(self, message, response=None, *args, **kwargs):
        self.message = message
        super().__init__(*args, **kwargs)


class SecretServerAccessError(SecretServerError):
    """ An Exception that represents a 40x response"""


class SecretServer:
    """ A class that uses bearer token authentication to access the Secret Server
    REST API.

    Uses the :attr:`username` and :attr:`password` to access the Secret Server
    at :attr:`base_url`.

    It gets an access_token which it uses to create an HTTP Authorization header
    which it adds to each REST API call.
    """

    API_PATH_URI = "/api/v1"
    TOKEN_PATH_URI = "/oauth2/token"

    @staticmethod
    def process(response):
        """ Process the response raising an error if the call was unsuccessful

        :return: the response if the call was successful
        :rtype: :class:~requests.Response
        :raises: :class:`SecretServerAccessError` when the caller does not have
                access to the secret
        :raises: :class:`SecretsAccessError` when the server responses with any
                other error"""

        if response.status_code >= 200 and response.status_code < 300:
            return response
        if response.status_code >= 400 and response.status_code < 500:
            content = json.loads(response.content)
            message = "unknown error response"

            if "message" in content:
                message = content["message"]
            elif "error" in content and isinstance(content["error"], str):
                message = content["error"]
            raise SecretServerAccessError(message, response)
        raise SecretServerError(response)

    @classmethod
    def _get_access_grant(cls, token_url, username, password):
        """Gets an OAuth2 Access Grant by calling the Secret Server REST API
        ``token`` endpoint

        :raise :class:`SecretServerError` when the server returns anything other
               than a valid Access Grant"""

        response = requests.post(
            token_url,
            data={
                "username": username,
                "password": password,
                "grant_type": "password",
            },
        )

        try:  # TSS returns a 200 (OK) containing HTML for some error conditions
            return json.loads(cls.process(response).content)
        except json.JSONDecodeError:
            raise SecretServerError(response)

    def __init__(
        self,
        base_url,
        username,
        password,
        api_path_uri=API_PATH_URI,
        token_path_uri=TOKEN_PATH_URI,
    ):
        """
        :param base_url: The base URL e.g. ``http://localhost/SecretServer``
        :type base_url: str
        :param username: The username to authenticate as
        :type username: str
        :param password: The pasword to authenticate with
        :type password: str
        :param api_path_uri: Defaults to ``/api/v1``
        :type api_path_uri: string
        :param token_path_uri: Defaults to ``/oauth2/token``
        :type token_path_uri: str"""

        self.base_url = base_url.rstrip("/")
        self.username = username
        self.password = password
        self.api_url = f"{base_url}/{api_path_uri.strip('/')}"
        self.token_url = f"{base_url}/{token_path_uri.strip('/')}"

    def _refresh_access_grant(self, seconds_of_drift=300):
        """Refreshes the OAuth2 Access Grant if it has expired or will in the next
        `seconds_of_drift` seconds.

        :raise :class:`SecretsVaultError` when the server returns anything other
               than a valid Access Grant"""

        if (
            hasattr(self, "access_grant")
            and self.access_grant_refreshed
            + timedelta(seconds=self.access_grant["expires_in"] + seconds_of_drift)
            > datetime.now()
        ):
            return
        else:
            self.access_grant = self._get_access_grant(
                self.token_url, self.username, self.password
            )
            self.access_grant_refreshed = datetime.now()

    def _add_authorization_header(self, existing_headers={}):
        """Adds an HTTP `Authorization` header containing the `Bearer` token

        :param existing_headers: a ``dict`` containing the existing headers
        :return: a ``dict`` containing the `existing_headers` and the
                `Authorization` header
        :rtype: dict"""

        return {
            "Authorization": f"Bearer {self.access_grant['access_token']}",
            **existing_headers,
        }

    def get_secret(self, id):
        """Gets a secret

        :param secret_path: the path to the secret
        :type secret_path: str
        :return: a JSON formatted string representation of the secret
        :rtype: str
        :raise: :class:`SecretsVaultAccessError` when the caller does not have
                permission to access the secret
        :raise: :class:`SecretsVaultError` when the REST API call fails for
                any other reason
        """

        self._refresh_access_grant()

        return self.process(
            requests.get(
                f"{self.api_url}/secrets/{id}", headers=self._add_authorization_header()
            )
        ).text


class SecretServerCloud(SecretServer):
    """ A class that uses bearer token authentication to access the Secret Server
    Cloud REST API.

    It Uses :attr:`tenant`, :attr:`tld` with :attr:`SERVER_URL_TEMPLATE`,
    to create request URLs.

    It uses the :attr:`username` and :attr:`password` to get an access_token from
    Secret Server Cloud which it uses to make calls to the REST API."""

    DEFAULT_TLD = "com"
    URL_TEMPLATE = "https://{}.secretservercloud.{}"

    def __init__(self, tenant, username, password, tld=DEFAULT_TLD):
        super().__init__(
            self.URL_TEMPLATE.format(tenant, tld), username, password
        )
