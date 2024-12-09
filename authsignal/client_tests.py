import os
import unittest
from .client import AuthsignalClient, ApiException


class TestAuthsignalClient(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.test_config = {
            "api_secret_key": os.getenv("AUTHSIGNAL_API_SECRET"),
            "api_url": os.getenv("AUTHSIGNAL_API_URL"),
        }

    def test_actions(self):
        client = AuthsignalClient(
            api_secret_key=self.test_config["api_secret_key"],
            api_url=self.test_config["api_url"],
        )

        track_attributes = {
            "redirect_url": "http://localhost:3000",
            "redirect_to_settings": True,
            "email": "not-a-real-email@authsignal.com",
            "phone_number": "1234567890",
            "ip_address": "127.0.0.1",
            "user_agent": "Authsignal-Python-SDK-Tests/1.0",
            "device_id": "device123",
            "custom": {"hello": "world"},
        }

        track_response = client.track(
            user_id="user123",
            action="python-sdk-test",
            attributes=track_attributes,
        )
        self.assertEqual(track_response["state"], "CHALLENGE_REQUIRED")
        self.assertTrue(track_response.get("idempotency_key"))
        self.assertTrue(track_response.get("is_enrolled", False))
        self.assertTrue(track_response.get("url"))
        self.assertTrue(track_response.get("token"))
        self.assertTrue(len(track_response.get("allowed_verification_methods", [])) > 0)

        get_action_response = client.get_action(
            user_id="user123",
            action="python-sdk-test",
            idempotency_key=track_response["idempotency_key"],
        )
        self.assertEqual(get_action_response["state"], "CHALLENGE_REQUIRED")
        self.assertIsNotNone(get_action_response.get("output"))

        update_action_response = client.update_action(
            user_id="user123",
            action="python-sdk-test",
            idempotency_key=track_response["idempotency_key"],
            attributes={"state": "BLOCK"},
        )
        self.assertEqual(update_action_response["state"], "BLOCK")

    def test_validate_challenge(self):
        client = AuthsignalClient(
            api_secret_key=self.test_config["api_secret_key"],
            api_url=self.test_config["api_url"],
        )

        track_response = client.track(
            user_id="user123",
            action="python-sdk-test",
            attributes={
                "redirect_url": "http://localhost:3000",
                "redirect_to_settings": True,
                "email": "not-a-real-email@authsignal.com",
                "phone_number": "1234567890",
                "ip_address": "127.0.0.1",
                "user_agent": "Authsignal-Python-SDK-Tests/1.0",
                "device_id": "device123",
            },
        )

        validate_response = client.validate_challenge(
            attributes={
                "token": track_response["token"],
            },
        )
        self.assertIsNotNone(validate_response.get("is_valid"))
        self.assertEqual(validate_response["state"], "CHALLENGE_REQUIRED")
        self.assertEqual(validate_response["user_id"], "user123")
        self.assertEqual(validate_response["action"], "python-sdk-test")
        self.assertTrue(validate_response.get("idempotency_key"))

    def test_authenticators(self):
        client = AuthsignalClient(
            api_secret_key=self.test_config["api_secret_key"],
            api_url=self.test_config["api_url"],
        )

        enroll_response = client.enroll_verified_authenticator(
            user_id="user12345",
            attributes={
                "verificationMethod": "EMAIL_OTP",
                "email": "not-a-real-email@authsignal.com",
            },
        )
        self.assertTrue(enroll_response["authenticator"]["user_authenticator_id"])
        self.assertEqual(
            enroll_response["authenticator"]["verification_method"],
            "EMAIL_OTP",
        )
        self.assertEqual(
            enroll_response["authenticator"]["email"],
            "not-a-real-email@authsignal.com",
        )
        self.assertEqual(enroll_response["authenticator"]["user_id"], "user12345")

        get_auth_response = client.get_authenticators(user_id="user12345")
        self.assertTrue(len(get_auth_response) > 0)

        authenticator = get_auth_response[0]
        self.assertTrue(authenticator["user_authenticator_id"])
        self.assertEqual(
            authenticator["verification_method"],
            "EMAIL_OTP",
        )
        self.assertEqual(authenticator["email"], "not-a-real-email@authsignal.com")

        client.delete_authenticator(
            user_id="user12345",
            user_authenticator_id=authenticator["user_authenticator_id"],
        )

        get_auth_response_after_delete = client.get_authenticators(user_id="user12345")
        for auth in get_auth_response_after_delete:
            self.assertNotEqual(
                auth["user_authenticator_id"], authenticator["user_authenticator_id"]
            )

    def test_new_client(self):
        client = AuthsignalClient("secret", "https://api.authsignal.com")
        self.assertEqual(client.api_secret_key, "secret")
        self.assertEqual(client.api_url, "https://api.authsignal.com")
        self.assertIsNotNone(client.session)

    def test_new_authsignal_api_error(self):
        error_code = "bad_request"
        error_description = "An error occurred"
        status_code = 400

        api_error = ApiException(
            error_code=error_code,
            error_description=error_description,
            status_code=status_code,
        )

        self.assertIsNotNone(api_error)
        self.assertEqual(api_error.error_code, error_code)
        self.assertEqual(api_error.error_description, error_description)
        self.assertEqual(api_error.status_code, status_code)

    def test_authsignal_api_error_message(self):
        status_code = 404
        error_description = "Not Found"

        api_error = ApiException(
            error_code="ERR404",
            error_description=error_description,
            status_code=status_code,
        )
        expected_error_message = "AuthsignalException: 404 - Not Found"
        self.assertEqual(str(api_error), expected_error_message)

    def test_users(self):
        client = AuthsignalClient(
            api_secret_key=self.test_config["api_secret_key"],
            api_url=self.test_config["api_url"],
        )

        update_user_response = client.update_user(
            user_id="a-new-user",
            attributes={
                "phoneNumber": "9876543210",
                "displayName": "A New User",
            },
        )

        self.assertEqual(
            update_user_response["phone_number"],
            "9876543210",
        )

        self.assertEqual(
            update_user_response["display_name"],
            "A New User",
        )

        get_user_response = client.get_user(user_id="a-new-user")
        self.assertEqual(
            get_user_response["phone_number"],
            "9876543210",
        )
        self.assertEqual(
            get_user_response["display_name"],
            "A New User",
        )

        client.delete_user(user_id="a-new-user")

        get_user_response = client.get_user(user_id="a-new-user")
        self.assertIsNotNone(get_user_response.get("is_enrolled"))
        self.assertFalse(get_user_response["is_enrolled"])

    def test_get_action_with_bad_secret(self):
        client = AuthsignalClient(
            api_secret_key="bad-secret",
            api_url=self.test_config["api_url"],
        )

        with self.assertRaises(ApiException) as cm:
            client.get_action(
                user_id="test-user",
                action="python-sdk-test",
                idempotency_key="test-key",
            )

        api_error = cm.exception
        self.assertEqual(api_error.status_code, 401)
        self.assertEqual(
            api_error.error_description,
            "The request is unauthorized. Check that your API key and region base URL are correctly configured.",
        )
        self.assertEqual(api_error.error_code, "unauthorized")
        self.assertEqual(
            str(api_error),
            "AuthsignalException: 401 - The request is unauthorized. Check that your API key and region base URL are correctly configured.",
        )

    def test_track_without_attributes(self):
        client = AuthsignalClient(
            api_secret_key=self.test_config["api_secret_key"],
            api_url=self.test_config["api_url"],
        )

        track_response = client.track(
            user_id="user123",
            action="python-sdk-test",
        )

        # Verify basic response structure
        self.assertEqual(track_response["state"], "CHALLENGE_REQUIRED")
        self.assertTrue(track_response.get("idempotency_key"))
        self.assertIsNotNone(track_response.get("token"))


if __name__ == "__main__":
    unittest.main()
