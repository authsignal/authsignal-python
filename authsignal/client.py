import decimal
import json
import random
import re
import time
import urllib.parse
from email.utils import parsedate_to_datetime
from enum import Enum
from typing import Dict, Any

import humps
import requests
from requests.adapters import HTTPAdapter

from authsignal.version import VERSION
from authsignal.webhook import Webhook

API_BASE_URL = "https://api.authsignal.com/v1"
DEFAULT_RETRIES = 2
DEFAULT_CONNECT_TIMEOUT = 3.0
DEFAULT_TIMEOUT = 10.0


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
    def __init__(self, timeout, connect_timeout, retries, api_key):
        super().__init__()
        self.mount("http://", HTTPAdapter())
        self.mount("https://", HTTPAdapter())

        self.timeout = (connect_timeout, timeout)
        self.retries = retries
        self.auth = requests.auth.HTTPBasicAuth(api_key, "")
        self.headers.update(
            {
                "Content-Type": "application/json",
                "Accept": "*/*",
                "User-Agent": "authsignal-python-sdk/" + VERSION,
                "X-Authsignal-Version": VERSION,
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
        retry_count = 0

        while True:
            try:
                response = super().send(request, **kwargs)
                if self._should_retry(request, retry_count, response=response):
                    delay = self._retry_delay(retry_count, response)
                    response.close()
                    time.sleep(delay)
                    retry_count += 1
                    continue

                response.raise_for_status()

                if response.headers.get("Content-Type") == "application/json":
                    data = response.json()
                    response.decamelized_content = humps.decamelize(data)
                return response
            except (requests.exceptions.ConnectionError, requests.exceptions.Timeout) as e:
                if self._should_retry(request, retry_count, error=e):
                    time.sleep(self._retry_delay(retry_count))
                    retry_count += 1
                    continue
                self._raise_api_exception(e)
            except requests.exceptions.RequestException as e:
                self._raise_api_exception(e)

    def _is_replayable(self, request) -> bool:
        if request.method.upper() in ("GET", "HEAD", "OPTIONS"):
            return True

        body = request.body.decode() if isinstance(request.body, bytes) else request.body
        if body:
            try:
                data = json.loads(body)
                if isinstance(data, dict) and (data.get("idempotencyKey") or data.get("idempotency_key")):
                    return True
            except (TypeError, ValueError):
                pass

        return request.method.upper() == "PATCH" and re.search(
            r"/actions/[^/]+/[^/]+$", urllib.parse.urlparse(request.url).path
        ) is not None

    def _should_retry(self, request, retry_count, response=None, error=None) -> bool:
        if retry_count >= self.retries or not self._is_replayable(request):
            return False
        if error is not None:
            return True
        return response.status_code == 429 or 500 <= response.status_code <= 599

    @staticmethod
    def _retry_delay(retry_count, response=None) -> float:
        base_delay = 0.1 * (2 ** retry_count)
        delay = base_delay + random.uniform(0, base_delay * 0.2)
        if response is not None and response.status_code == 429:
            retry_after = response.headers.get("Retry-After")
            if retry_after:
                try:
                    retry_after_delay = float(retry_after)
                except ValueError:
                    try:
                        retry_after_delay = max(
                            0.0, parsedate_to_datetime(retry_after).timestamp() - time.time()
                        )
                    except (TypeError, ValueError, OverflowError):
                        retry_after_delay = 0.0
                delay = max(delay, retry_after_delay)
        return delay

    @staticmethod
    def _raise_api_exception(error):
        error_code = None
        error_description = None
        status_code = None

        if isinstance(error, requests.exceptions.HTTPError):
            status_code = error.response.status_code
            try:
                error_data = error.response.json()
                error_code = error_data.get("errorCode")
                error_description = error_data.get("errorDescription")
            except (ValueError, AttributeError):
                pass

        raise ApiException(error_code, error_description, status_code) from error


class AuthsignalClient(object):

    def __init__(
        self,
        api_secret_key,
        api_url=API_BASE_URL,
        timeout=DEFAULT_TIMEOUT,
        connect_timeout=DEFAULT_CONNECT_TIMEOUT,
        retries=DEFAULT_RETRIES,
    ):
        """Initialize the client.
        Args:
            api_secret_key: Your Authsignal Secret API key of your tenant
            api_url: Base URL, including scheme and host, for sending events.
                Defaults to 'https://api.authsignal.com/v1'.
            timeout: Number of seconds to wait while reading a response. Defaults
                to 10 seconds.
            connect_timeout: Number of seconds to wait while connecting. Defaults
                to 3 seconds.
            retries: Number of retries after the initial request. Defaults to 2.
        """
        _assert_non_empty_string(api_url, "api_url")
        _assert_non_empty_string(api_secret_key, "api_secret_key")

        self.api_secret_key = api_secret_key
        self.api_url = api_url

        self.session = CustomSession(
            timeout=timeout,
            connect_timeout=connect_timeout,
            retries=retries,
            api_key=api_secret_key,
        )
        self.version = VERSION
        self.webhook = Webhook(api_secret_key=api_secret_key)

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

    def query_users(
        self,
        username: str = None,
        email: str = None,
        phone_number: str = None,
        token: str = None,
        limit: int = None,
        last_evaluated_user_id: str = None,
    ) -> Dict[str, Any]:
        """Queries users from authsignal with optional filters
        Args:
            username: Filter by username. Optional.
            email: Filter by email. Optional.
            phone_number: Filter by phone number. Optional.
            token: Filter by token. Optional.
            limit: Maximum number of users to return. Optional.
            last_evaluated_user_id: For pagination, the last userId from previous response. Optional.
        Returns:
            A dictionary containing 'users' array and optional 'lastEvaluatedUserId' for pagination.
        """
        params = {}

        if username is not None:
            params["username"] = username
        if email is not None:
            params["email"] = email
        if phone_number is not None:
            params["phoneNumber"] = phone_number
        if token is not None:
            params["token"] = token
        if limit is not None:
            params["limit"] = str(limit)
        if last_evaluated_user_id is not None:
            params["lastEvaluatedUserId"] = last_evaluated_user_id

        query_string = urllib.parse.urlencode(params) if params else ""
        path = f"{self.api_url}/users" + (f"?{query_string}" if query_string else "")

        response = self.session.get(url=path)

        return response.decamelized_content

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
