import unittest
from unittest.mock import patch

import requests
import responses

from .client import ApiException, AuthsignalClient


class TestRetryPolicy(unittest.TestCase):
    def setUp(self):
        self.api_url = "https://api.test.authsignal.com/v1"

    @responses.activate
    @patch("authsignal.client.time.sleep", return_value=None)
    def test_retries_safe_requests_twice_on_5xx(self, _sleep):
        url = f"{self.api_url}/users/user"
        responses.add(responses.GET, url, json={"error": "unavailable"}, status=503)
        responses.add(responses.GET, url, json={"error": "unavailable"}, status=503)
        responses.add(responses.GET, url, json={"isEnrolled": False}, status=200)

        client = AuthsignalClient("secret", self.api_url)
        result = client.get_user("user")

        self.assertFalse(result["is_enrolled"])
        self.assertEqual(3, len(responses.calls))

    @responses.activate
    @patch("authsignal.client.time.sleep", return_value=None)
    def test_retries_429_responses(self, _sleep):
        url = f"{self.api_url}/users/user"
        responses.add(responses.GET, url, json={"error": "rate_limited"}, status=429, headers={"Retry-After": "0"})
        responses.add(responses.GET, url, json={"isEnrolled": False}, status=200)

        AuthsignalClient("secret", self.api_url).get_user("user")

        self.assertEqual(2, len(responses.calls))

    @responses.activate
    @patch("authsignal.client.time.sleep", return_value=None)
    def test_retries_transient_network_failures(self, _sleep):
        url = f"{self.api_url}/users/user"
        responses.add(
            responses.GET,
            url,
            body=requests.exceptions.ConnectionError("connection reset"),
        )
        responses.add(responses.GET, url, json={"isEnrolled": False}, status=200)

        AuthsignalClient("secret", self.api_url).get_user("user")

        self.assertEqual(2, len(responses.calls))

    @responses.activate
    @patch("authsignal.client.time.sleep", return_value=None)
    def test_retries_idempotent_writes(self, _sleep):
        url = f"{self.api_url}/users/user/actions/withdrawal"
        responses.add(responses.POST, url, json={"error": "unavailable"}, status=503)
        responses.add(responses.POST, url, json={"idempotencyKey": "key", "state": "ALLOW"}, status=200)

        AuthsignalClient("secret", self.api_url).track(
            "user", "withdrawal", {"idempotency_key": "key"}
        )

        self.assertEqual(2, len(responses.calls))

    @responses.activate
    @patch("authsignal.client.time.sleep", return_value=None)
    def test_does_not_retry_non_idempotent_writes_or_499(self, _sleep):
        post_url = f"{self.api_url}/users/user/actions/withdrawal"
        get_url = f"{self.api_url}/users/user"
        responses.add(responses.POST, post_url, json={"error": "unavailable"}, status=503)
        responses.add(responses.GET, get_url, json={"error": "challenge_required"}, status=499)
        client = AuthsignalClient("secret", self.api_url)

        with self.assertRaises(ApiException):
            client.track("user", "withdrawal")
        with self.assertRaises(ApiException):
            client.get_user("user")

        self.assertEqual(2, len(responses.calls))

    @responses.activate
    @patch("authsignal.client.time.sleep", return_value=None)
    def test_allows_retries_to_be_disabled(self, _sleep):
        url = f"{self.api_url}/users/user"
        responses.add(responses.GET, url, json={"error": "unavailable"}, status=503)

        with self.assertRaises(ApiException):
            AuthsignalClient("secret", self.api_url, retries=0).get_user("user")

        self.assertEqual(1, len(responses.calls))

    def test_uses_consistent_timeout_defaults(self):
        client = AuthsignalClient("secret", self.api_url)
        self.assertEqual((3.0, 10.0), client.session.timeout)
        self.assertEqual(2, client.session.retries)


if __name__ == "__main__":
    unittest.main()
