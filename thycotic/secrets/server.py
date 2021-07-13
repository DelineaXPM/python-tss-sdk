"""The Thycotic Secret Server SDK API facilitates access to the Secret Server
REST API using *OAuth2 Bearer Token* authentication.

Example:

    # connect to Secret Server
    secret_server = SecretServer(base_url, authorizer, api_path_uri='/api/v1')
    # or, for Secret Server Cloud
    secret_server = SecretServerCloud(tenant, username, password, tld='com')

    # to get the secret as a ``dict``
    secret = secret_server.get_secret(123)
    # or, to use the dataclass
    secret = ServerSecret(**secret_server.get_secret(123))
"""

import json
import re
from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import datetime, timedelta

import requests


@dataclass
class ServerSecret:
    # Based on https://gist.github.com/jaytaylor/3660565
    @staticmethod
    def snake_case(camel_cased):
        """Transform to snake case

        Transforms the keys of the given map from camelCase to snake_case.
        """
        return [
            (
                re.compile("([a-z0-9])([A-Z])")
                .sub(r"\1_\2", re.compile(r"(.)([A-Z][a-z]+)").sub(r"\1_\2", k))
                .lower(),
                v,
            )
            for (k, v) in camel_cased.items()
        ]

    @dataclass
    class Field:
        item_id: int
        field_id: int
        file_attachment_id: int
        field_description: str
        field_name: str
        filename: str
        value: str
        slug: str

        def __init__(self, **kwargs):
            # The REST API returns attributes with camelCase names which we
            # replace with snake_case per Python conventions
            for k, v in ServerSecret.snake_case(kwargs):
                if k == "item_value":
                    k = "value"
                setattr(self, k, v)

    id: int
    folder_id: int
    secret_template_id: int
    site_id: int
    active: bool
    checked_out: bool
    check_out_enabled: bool
    name: str
    secret_template_name: str
    last_heart_beat_status: str
    last_heart_beat_check: datetime
    last_password_change_attempt: datetime
    fields: dict

    DEFAULT_DATETIME_FORMAT = "%Y-%m-%dT%H:%M:%S"

    def __init__(self, **kwargs):
        # The REST API returns attributes with camelCase names which we replace
        # with snake_case per Python conventions
        datetime_format = self.DEFAULT_DATETIME_FORMAT
        if "datetime_format" in kwargs:
            datetime_format = kwargs["datetime_format"]
        for k, v in self.snake_case(kwargs):
            if k in ["last_heart_beat_check", "last_password_change_attempt"]:
                # @dataclass does not marshal timestamps into datetimes automatically
                v = re.sub(r"\.[0-9]+$", "", v)
                v = datetime.strptime(v, datetime_format)
            setattr(self, k, v)
        self.fields = {
            item["slug"]: ServerSecret.Field(**item) for item in kwargs["items"]
        }


class SecretServerError(Exception):
    """An Exception that includes a message and the server response"""

    def __init__(self, message, response=None, *args, **kwargs):
        self.message = message
        super().__init__(*args, **kwargs)


class SecretServerClientError(SecretServerError):
    """An Exception that represents a client error i.e. ``400``."""


class SecretServerServiceError(SecretServerError):
    """An Exception that represents a service error i.e. ``500``."""


class Authorizer(ABC):
    """Main abstract base class for all Authorizer access methods."""

    @staticmethod
    def add_bearer_token_authorization_header(bearer_token, existing_headers={}):
        """Adds an HTTP `Authorization` header containing the `Bearer` token

        :param existing_headers: a ``dict`` containing the existing headers
        :return: a ``dict`` containing the `existing_headers` and the
                `Authorization` header
        :rtype: ``dict``
        """

        return {
            "Authorization": "Bearer " + bearer_token,
            **existing_headers,
        }

    @abstractmethod
    def get_access_token(self):
        """Returns the access_token from a Grant Request"""

    def headers(self, existing_headers={}):
        """Returns a dictionary containing headers for REST API calls"""
        return self.add_bearer_token_authorization_header(
            self.get_access_token(), existing_headers
        )


class AccessTokenAuthorizer(Authorizer):
    """Allows the use of a pre-existing access token to authorize REST API
    calls.
    """

    def get_access_token(self):
        return self.access_token

    def __init__(self, access_token):
        self.access_token = access_token


class PasswordGrantAuthorizer(Authorizer):
    """Allows the use of a username and password to be used to authorize REST
    API calls.
    """

    TOKEN_PATH_URI = "/oauth2/token"

    @staticmethod
    def get_access_grant(token_url, grant_request):
        """Gets an *OAuth2 Access Grant* by calling the Secret Server REST API
        ``token`` endpoint

        :raise :class:`SecretServerError` when the server returns anything
                other than a valid Access Grant
        """

        response = requests.post(token_url, grant_request)

        try:  # TSS returns a 200 (OK) containing HTML for some error conditions
            return json.loads(SecretServer.process(response).content)
        except json.JSONDecodeError:
            raise SecretServerError(response)

    def _refresh(self, seconds_of_drift=300):
        """Refreshes the *OAuth2 Access Grant* if it has expired or will in the next
        `seconds_of_drift` seconds.

        :raise :class:`SecretServerError` when the server returns anything other
               than a valid Access Grant
        """

        if (
            hasattr(self, "access_grant")
            and self.access_grant_refreshed
            + timedelta(seconds=self.access_grant["expires_in"] + seconds_of_drift)
            > datetime.now()
        ):
            return
        else:
            self.access_grant = self.get_access_grant(
                self.token_url, self.grant_request
            )
            self.access_grant_refreshed = datetime.now()

    def __init__(self, base_url, username, password, token_path_uri=TOKEN_PATH_URI):
        self.token_url = base_url.rstrip("/") + "/" + token_path_uri.strip("/")
        self.grant_request = {
            "username": username,
            "password": password,
            "grant_type": "password",
        }

    def get_access_token(self):
        self._refresh()
        return self.access_grant["access_token"]


class DomainPasswordGrantAuthorizer(PasswordGrantAuthorizer):
    """Allows domain access to be used to authorize REST API calls."""

    def __init__(
        self,
        base_url,
        username,
        domain,
        password,
        token_path_uri=PasswordGrantAuthorizer.TOKEN_PATH_URI,
    ):
        super().__init__(base_url, username, password, token_path_uri=token_path_uri)
        self.grant_request["domain"] = domain


class SecretServer:
    """A class that uses an *OAuth2 Bearer Token* to access the Secret Server
    REST API. It uses the and `Authorizer` to determine the Authorization
    method required to access the Secret Server at :attr:`base_url`.

    It gets an ``access_token`` that it uses to create an *HTTP Authorization
    Header* which it includes in each REST API call.
    """

    API_PATH_URI = "/api/v1"

    @staticmethod
    def process(response):
        """Process the response raising an error if the call was unsuccessful

        :return: the response if the call was successful
        :rtype: :class:`~requests.Response`
        :raises: :class:`SecretServerAccessError` when the caller does not have
                access to the secret
        :raises: :class:`SecretsAccessError` when the server responses with any
                other error
        """

        if response.status_code >= 200 and response.status_code < 300:
            return response
        if response.status_code >= 400 and response.status_code < 500:
            try:
                content = json.loads(response.content)
                if "message" in content:
                    message = content["message"]
                elif "error" in content and isinstance(content["error"], str):
                    message = content["error"]
            except json.JSONDecodeError as err:
                message = err.msg
            raise SecretServerClientError(message, response)
        else:
            raise SecretServerServiceError(response)

    def headers(self):
        """Returns a dictionary containing HTTP headers."""
        return self.authorizer.headers()

    def __init__(
        self,
        base_url,
        authorizer: Authorizer,
        api_path_uri=API_PATH_URI,
    ):
        """
        :param base_url: The base URL e.g. ``http://localhost/SecretServer``
        :type base_url: str
        :param authorizer: The authorization method to be used
        :type authorizer: Authorizer
        :param api_path_uri: Defaults to ``/api/v1``
        :type api_path_uri: str
        """

        self.base_url = base_url.rstrip("/")
        self.authorizer = authorizer
        self.api_url = f"{base_url}/{api_path_uri.strip('/')}"

    def get_secret_json(self, id):
        """Gets a Secret from Secret Server

        :param id: the id of the secret
        :type id: int
        :return: a JSON formatted string representation of the secret
        :rtype: ``str``
        :raise: :class:`SecretServerAccessError` when the caller does not have
                permission to access the secret
        :raise: :class:`SecretServerError` when the REST API call fails for
                any other reason
        """

        return self.process(
            requests.get(f"{self.api_url}/secrets/{id}", headers=self.headers())
        ).text

    def get_secret(self, id, fetch_file_attachments=True):
        """Gets a secret

        :param id: the id of the secret
        :type id: int
        :param fetch_file_attachments: whether or not to fetch file attachments
                                       and replace itemValue with the contents
                                       for each item (field), automatically
        :type fetch_file_attachments: bool
        :return: a ``dict`` representation of the secret
        :rtype: ``dict``
        :raise: :class:`SecretServerAccessError` when the caller does not have
                permission to access the secret
        :raise: :class:`SecretServerError` when the REST API call fails for
                any other reason
        """

        response = self.get_secret_json(id)

        try:
            secret = json.loads(response)
        except json.JSONDecodeError:
            raise SecretServerError(response)

        if fetch_file_attachments:
            for item in secret["items"]:
                if item["fileAttachmentId"]:
                    item["itemValue"] = self.process(
                        requests.get(
                            f"{self.api_url}/secrets/{id}/fields/{item['slug']}",
                            headers=self.headers(),
                        )
                    )
        return secret


class SecretServerV0(SecretServer):
    """A class that uses an *OAuth2 Bearer Token* to access the Secret Server
    REST API. It uses the :attr:`username` and :attr:`password` to access the
    Secret Server at :attr:`base_url`.

    It gets an ``access_token`` that it uses to create an *HTTP Authorization
    Header* which it includes in each REST API call.

    This class maintains backwards compatability with v0.0.5
    """

    def __init__(
        self,
        base_url,
        username,
        password,
        api_path_uri=SecretServer.API_PATH_URI,
        token_path_uri=PasswordGrantAuthorizer.TOKEN_PATH_URI,
    ):
        super().__init__(
            base_url,
            PasswordGrantAuthorizer(
                f"{base_url}/{token_path_uri.strip('/')}", username, password
            ),
            api_path_uri,
        )


class SecretServerCloud(SecretServer):
    """A class that uses bearer token authentication to access the Secret
    Server Cloud REST API.

    It uses :attr:`tenant`, :attr:`tld` with :attr:`SERVER_URL_TEMPLATE`,
    to create request URLs.

    It uses the :attr:`username` and :attr:`password` to get an access_token
    from Secret Server Cloud which it uses to make calls to the REST API.
    """

    DEFAULT_TLD = "com"
    URL_TEMPLATE = "https://{}.secretservercloud.{}"

    def __init__(self, tenant, authorizer: Authorizer, tld=DEFAULT_TLD):
        super().__init__(self.URL_TEMPLATE.format(tenant, tld), authorizer)
