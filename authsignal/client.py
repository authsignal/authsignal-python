import decimal
import json
import urllib.parse
from enum import Enum
from typing import Dict, Any

import humps
import requests
from requests.adapters import HTTPAdapter

from authsignal.version import VERSION

API_BASE_URL = "https://api.authsignal.com/v1"


class ActionState(Enum):
    BLOCK = "BLOCK"
    ALLOW = "ALLOW"
    CHALLENGE_REQUIRED = "CHALLENGE_REQUIRED"
    CHALLENGE_FAILED = "CHALLENGE_FAILED"
    CHALLENGE_SUCCEEDED = "CHALLENGE_SUCCEEDED"
    REVIEW_REQUIRED = "REVIEW_REQUIRED"
    REVIEW_FAILED = "REVIEW_FAILED"
    REVIEW_SUCCEEDED = "REVIEW_SUCCEEDED"


class DecimalEncoder(json.JSONEncoder):
    def default(self, o):
        if isinstance(o, decimal.Decimal):
            return (str(o),)
        return super(DecimalEncoder, self).default(o)


class CustomSession(requests.Session):
    def __init__(self, timeout, api_key):
        super().__init__()
        self.mount("http://", HTTPAdapter())
        self.mount("https://", HTTPAdapter())

        self.timeout = timeout
        self.auth = requests.auth.HTTPBasicAuth(api_key, "")
        self.headers.update(
            {
                "Content-Type": "application/json",
                "Accept": "*/*",
                "User-Agent": "authsignal-python-sdk/" + VERSION,
            }
        )

    def prepare_request(self, request):
        prepared_request = super().prepare_request(request)

        if (
            prepared_request.headers.get("Content-Type") == "application/json"
            and prepared_request.body
        ):
            data = json.loads(prepared_request.body)
            cleaned_data = self._remove_none_values(data)
            prepared_request.body = json.dumps(cleaned_data)
        return prepared_request

    @staticmethod
    def _remove_none_values(d: Dict[str, Any]) -> Dict[str, Any]:
        """Remove keys with None values from a dictionary."""
        return {k: v for k, v in d.items() if v is not None}

    def send(self, request, **kwargs) -> requests.Response:
        kwargs.setdefault("timeout", self.timeout)
        try:
            response = super().send(request, **kwargs)
            response.raise_for_status()

            if response.headers.get("Content-Type") == "application/json":
                data = response.json()
                decamelized_content = humps.decamelize(data)
                response.decamelized_content = decamelized_content
            return response
        except requests.exceptions.RequestException as e:
            error_code = None
            error_description = None
            status_code = None

            if isinstance(e, requests.exceptions.HTTPError):
                status_code = e.response.status_code
                try:
                    error_data = e.response.json()
                    error_code = error_data.get("errorCode")
                    error_description = error_data.get("errorDescription")
                except (ValueError, AttributeError):
                    pass

            raise ApiException(error_code, error_description, status_code) from e


class AuthsignalClient(object):

    def __init__(self, api_secret_key, api_url=API_BASE_URL, timeout=2.0):
        """Initialize the client.
        Args:
            api_key: Your Authsignal Secret API key of your tenant
            api_url: Base URL, including scheme and host, for sending events.
                Defaults to 'https://api.authsignal.com/v1'.
            timeout: Number of seconds to wait before failing request. Defaults
                to 2 seconds.
        """
        _assert_non_empty_string(api_url, "api_url")
        _assert_non_empty_string(api_secret_key, "api_secret_key")

        self.api_secret_key = api_secret_key
        self.api_url = api_url

        self.session = CustomSession(timeout=timeout, api_key=api_secret_key)
        self.version = VERSION

    def track(
        self, user_id: str, action: str, attributes: Dict[str, Any] = None
    ) -> Dict[str, Any]:
        """Tracks an action to authsignal, scoped to the user_id and action
        Returns the status of the action so that you can determine to whether to continue
        Args:
            user_id:  A user's id. This id should be the same as the user_id used in
                event calls.
            action: The action that you are tracking an event for, i.e. signIn.
            attributes: A dictionary containing the request body. Optional.
        """
        _assert_non_empty_string(user_id, "user_id")
        _assert_non_empty_string(action, "action")

        path = f"{self.api_url}/users/{urllib.parse.quote(user_id)}/actions/{urllib.parse.quote(action)}"

        attributes = attributes or {}
        response = self.session.post(
            url=path, data=json.dumps(attributes, cls=DecimalEncoder)
        )

        return response.decamelized_content

    def get_user(self, user_id: str) -> Dict[str, Any]:
        """Retrieves the user from authsignal
        Args:
            user_id:  A user's id.
        """
        _assert_non_empty_string(user_id, "user_id")

        path = f"{self.api_url}/users/{urllib.parse.quote(user_id)}"

        response = self.session.get(url=path)

        return response.decamelized_content

    def update_user(self, user_id: str, attributes: Dict[str, Any]) -> Dict[str, Any]:
        """Updates the user in authsignal
        Args:
            user_id:  A user's id.
            attributes: A dictionary containing the request body.
        """
        _assert_non_empty_string(user_id, "user_id")
        _assert_non_empty_dict(attributes, "attributes")

        path = f"{self.api_url}/users/{urllib.parse.quote(user_id)}"

        response = self.session.patch(
            url=path, data=json.dumps(attributes, cls=DecimalEncoder)
        )

        return response.decamelized_content

    def delete_user(self, user_id: str):
        """Deletes a user from authsignal
        Args:
            user_id:  A user's id.
        """
        _assert_non_empty_string(user_id, "user_id")

        path = f"{self.api_url}/users/{urllib.parse.quote(user_id)}"

        response = self.session.delete(url=path)

        return

    def get_authenticators(self, user_id: str) -> Dict[str, Any]:
        """Retrieves the authenticators for a user
        Args:
            user_id:  A user's id.
        """
        _assert_non_empty_string(user_id, "user_id")

        path = f"{self.api_url}/users/{urllib.parse.quote(user_id)}/authenticators"

        response = self.session.get(url=path)

        return response.decamelized_content

    def enroll_verified_authenticator(
        self, user_id: str, attributes: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Enrolls an authenticator for a given user.
        Args:
            user_id:  A user's id. This id should be the same as the user_id used in event calls.
            attributes:  A dictionary containing the request body.
        """
        _assert_non_empty_string(user_id, "user_id")
        _assert_non_empty_dict(attributes, "attributes")

        path = f"{self.api_url}/users/{urllib.parse.quote(user_id)}/authenticators"

        response = self.session.post(
            url=path, data=json.dumps(attributes, cls=DecimalEncoder)
        )

        return response.decamelized_content

    def delete_authenticator(self, user_id: str, user_authenticator_id: str):
        """Deletes an authenticator from authsignal
        Args:
            user_id: A user's id.
            user_authenticator_id: The id of the authenticator you want to delete
        """
        _assert_non_empty_string(user_id, "user_id")
        _assert_non_empty_string(user_authenticator_id, "user_authenticator_id")

        path = f"{self.api_url}/users/{urllib.parse.quote(user_id)}/authenticators/{urllib.parse.quote(user_authenticator_id)}"

        response = self.session.delete(url=path)

        return

    def validate_challenge(self, attributes: Dict[str, Any]) -> Dict[str, Any]:
        """Validates a token from authsignal
        Args:
            attributes: A dictionary containing the token to validate.
        """
        _assert_non_empty_dict(attributes, "attributes")

        path = f"{self.api_url}/validate"

        response = self.session.post(
            url=path, data=json.dumps(attributes, cls=DecimalEncoder)
        )

        return response.decamelized_content

    def get_action(
        self, user_id: str, action: str, idempotency_key: str
    ) -> Dict[str, Any]:
        """Retrieves the action from authsignal for a given user and action.
        Args:
            user_id: A user's id.
            action: The action that you are retrieving, i.e. signIn
            idempotency_key: The action's idempotency key
        """
        _assert_non_empty_string(user_id, "user_id")
        _assert_non_empty_string(action, "action")
        _assert_non_empty_string(idempotency_key, "idempotency_key")

        path = f"{self.api_url}/users/{urllib.parse.quote(user_id)}/actions/{urllib.parse.quote(action)}/{urllib.parse.quote(idempotency_key)}"

        response = self.session.get(url=path)

        return response.decamelized_content

    def update_action(
        self,
        user_id: str,
        action: str,
        idempotency_key: str,
        attributes: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Updates an action in authsignal
        Args:
            user_id: A user's id.
            action: The action that you are updating, i.e. signIn
            idempotency_key: The action's idempotency key
            attributes: A dictionary containing the request body.
        """
        _assert_non_empty_string(user_id, "user_id")
        _assert_non_empty_string(action, "action")
        _assert_non_empty_string(idempotency_key, "idempotency_key")
        _assert_non_empty_dict(attributes, "attributes")

        path = f"{self.api_url}/users/{urllib.parse.quote(user_id)}/actions/{urllib.parse.quote(action)}/{urllib.parse.quote(idempotency_key)}"

        response = self.session.patch(
            url=path, data=json.dumps(attributes, cls=DecimalEncoder)
        )

        return response.decamelized_content


class ApiException(Exception):
    def __init__(self, error_code, error_description, status_code):
        super().__init__(f"AuthsignalException: {status_code} - {error_description}")
        self.error_code = error_code
        self.error_description = error_description
        self.status_code = status_code

    def __str__(self):
        return f"AuthsignalException: {self.status_code} - {self.error_description}"


def _assert_non_empty_string(val: str, name: str) -> None:
    if not isinstance(val, str) or not val:
        raise ValueError(f"{name} must be a non-empty string")


def _assert_non_empty_dict(val: dict, name: str) -> None:
    if not isinstance(val, dict) or not val:
        raise ValueError(f"{name} must be a non-empty dict")
