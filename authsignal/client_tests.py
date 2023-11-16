import unittest
import responses

import client

base_url = "https://signal.authsignal.com/v1"

class Test(unittest.TestCase):
    def setUp(self):
        self.authsignal_client = client.Client(api_key='<SECRET API KEY HERE>')

    @responses.activate
    def test_get_user(self):
        responses.add(responses.GET, f"{base_url}/users/1234",
                json={"isEnrolled": False, "email": "test@gmail.com", "phoneNumber": "1234567"}, status=200)

        response = self.authsignal_client.get_user(user_id="1234")

        self.assertEqual(response["isEnrolled"], False)
        self.assertEqual(response["email"], "test@gmail.com")
        self.assertEqual(response["phoneNumber"], "1234567")

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

        self.assertEqual(response["authenticator"]["userAuthenticatorId"],
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
        self.assertEqual(response["idempotencyKey"], "f7f6ff4c-600f-4d61-99a2-b1157fe43777")

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

        print(response)

        self.assertEqual(response["state"], "ALLOW")
        self.assertEqual(response["stateUpdatedAt"], "2022-07-25T03:19:00.316Z")

if __name__ == "__main__":
    unittest.main()