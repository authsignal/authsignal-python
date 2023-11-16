import unittest
import responses

import client

base_url = "https://signal.authsignal.com"

class Test(unittest.TestCase):
    def setUp(self):
        self.authsignal_client = client.Client(api_key='<SECRET API KEY HERE>')

    @responses.activate
    def test_get_user(self):
        responses.add(responses.GET, f"{base_url}/v1/users/1234",
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

        
        responses.add(responses.POST, f"{base_url}/v1/users/1234/authenticators",
                      json=payload, status=200)
            
        response = self.authsignal_client.enroll_verified_authenticator(
                user_id="1234",
                authenticator_payload={
                    "oob_channel": "SMS",
                    "phone_number": "+64270000000"
                })

        self.assertEqual(response["authenticator"]["userAuthenticatorId"],
                             "9b2cfd40-7df2-4658-852d-a0c3456e5a2e")

if __name__ == "__main__":
    unittest.main()