import unittest
import responses
import jwt
import time

import client

base_url = "https://signal.authsignal.com/v1"

class Test(unittest.TestCase):
    def setUp(self):
        self.authsignal_client = client.Client(api_key='SECRET')

    @responses.activate
    def test_get_user(self):
        responses.add(responses.GET, f"{base_url}/users/1234",
                json={"isEnrolled": False, "email": "test@gmail.com", "phoneNumber": "1234567"}, status=200)

        response = self.authsignal_client.get_user(user_id="1234")

        self.assertEqual(response["is_enrolled"], False)
        self.assertEqual(response["email"], "test@gmail.com")
        self.assertEqual(response["phone_number"], "1234567")

    @responses.activate
    def test_enroll_verified_authenticator(self):
        payload = {
            "authenticator": {
            "userAuthenticatorId": "9b2cfd40-7df2-4658-852d-a0c3456e5a2e",
            "authenticatorType": "OOB",
            "isDefault": "true",
            "phoneNumber": "+64270000000",
            "createdAt": "2022-07-25T03:31:36.219Z",
            "oobChannel": "SMS"
            },
            "recoveryCodes": ["xxxx"]
        }

        
        responses.add(responses.POST, f"{base_url}/users/1234/authenticators",
                      json=payload, status=200)
            
        response = self.authsignal_client.enroll_verified_authenticator(
                user_id="1234",
                authenticator_payload={
                    "oob_channel": "SMS",
                    "phone_number": "+64270000000"
                })

        self.assertEqual(response["authenticator"]["user_authenticator_id"],
                             "9b2cfd40-7df2-4658-852d-a0c3456e5a2e")

    @responses.activate
    def test_track(self):
        responses.add(responses.POST, f"{base_url}/users/1234/actions/signIn",
                      json={"state": "ALLOW", "idempotencyKey": "f7f6ff4c-600f-4d61-99a2-b1157fe43777", "ruleIds": []},
                      status=200)

        response = self.authsignal_client.track(
            user_id="1234",
            action="signIn",
            payload={
                "it_could_be_a_bool": True,
                "it_could_be_a_string": "test",
                "it_could_be_a_number": 400.00
            }
        )

        self.assertEqual(response["state"], "ALLOW")
        self.assertEqual(response["idempotency_key"], "f7f6ff4c-600f-4d61-99a2-b1157fe43777")

    @responses.activate
    def test_get_action(self):
        responses.add(responses.GET, f"{base_url}/users/1234/actions/signIn/15cac140-f639-48c5-92db-835ec8d3d144",
                      json={"state": "ALLOW", "ruleIds": [], "stateUpdatedAt": "2022-07-25T03:19:00.316Z", "createdAt": "2022-07-25T03:19:00.316Z"},
                      status=200)

        response = self.authsignal_client.get_action(
            user_id="1234",
            action="signIn",
            idempotency_key="15cac140-f639-48c5-92db-835ec8d3d144",
        )

        self.assertEqual(response["state"], "ALLOW")
        self.assertEqual(response["state_updated_at"], "2022-07-25T03:19:00.316Z")

class ValidateChallenge(unittest.TestCase):
    def setUp(self):
        self.api_key='SECRET'

        self.authsignal_client = client.Client(api_key=self.api_key)

        self.payload = {
            "iat": int(time.time()),
            "sub": "legitimate_user_id",
            "exp": int(time.time()) + 10 * 60,
            "iss": "test",
            "scope": "read:authenticators add:authenticators update:authenticators remove:authenticators",
            "other": {
                "tenantId": "555159e4-adc3-454b-82b1-b55a2783f712",
                "publishableKey": "2fff14a6600b7a58170793109c78b876",
                "userId": "legitimate_user_id",
                "action": "alwaysChallenge",
                "idempotencyKey": "a682af7d-c929-4c29-9c2a-71e69ab5c603"
            }
        }

        self.jwt_token = jwt.encode(self.payload, self.api_key, algorithm='HS256')

    @responses.activate
    def test_it_returns_success_if_user_id_is_correct(self):
        responses.add(responses.GET, f"{base_url}/users/legitimate_user_id/actions/alwaysChallenge/a682af7d-c929-4c29-9c2a-71e69ab5c603",
            json={"state": "CHALLENGE_SUCCEEDED", "ruleIds": [], "stateUpdatedAt": "2022-07-25T03:19:00.316Z", "createdAt": "2022-07-25T03:19:00.316Z"},
            status=200
        )

        response = self.authsignal_client.validate_challenge(user_id="legitimate_user_id", token=self.jwt_token)

        self.assertEqual(response["user_id"], "legitimate_user_id")
        self.assertEqual(response["state"], "CHALLENGE_SUCCEEDED")
        self.assertTrue(response["success"])

    @responses.activate
    def test_it_returns_success_false_if_user_id_is_incorrect(self):
        responses.add(responses.GET, f"{base_url}/users/spoofed_id/actions/alwaysChallenge/a682af7d-c929-4c29-9c2a-71e69ab5c603",
            json={"state": "CHALLENGE_SUCCEEDED", "ruleIds": [], "stateUpdatedAt": "2022-07-25T03:19:00.316Z", "createdAt": "2022-07-25T03:19:00.316Z"},
            status=200
        )

        response = self.authsignal_client.validate_challenge(user_id="spoofed_id", token=self.jwt_token)

        self.assertIsNone(response['state'])
        self.assertFalse(response['success'])

    @responses.activate
    def test_it_returns_success_true_if_no_user_id_is_provided(self):
        responses.add(responses.GET, f"{base_url}/users/legitimate_user_id/actions/alwaysChallenge/a682af7d-c929-4c29-9c2a-71e69ab5c603",
            json={"state": "CHALLENGE_SUCCEEDED", "ruleIds": [], "stateUpdatedAt": "2022-07-25T03:19:00.316Z", "createdAt": "2022-07-25T03:19:00.316Z"},
            status=200
        )

        response = self.authsignal_client.validate_challenge(token=self.jwt_token)

        self.assertEqual(response["user_id"], "legitimate_user_id")
        self.assertEqual(response["state"], "CHALLENGE_SUCCEEDED")
        self.assertTrue(response["success"])

if __name__ == "__main__":
    unittest.main()