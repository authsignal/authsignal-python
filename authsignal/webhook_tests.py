import unittest
import time
import base64
import hmac
import hashlib
import json

from .webhook import Webhook, InvalidSignatureError

class TestWebhook(unittest.TestCase):
    def setUp(self):
        self.secret = "YOUR_AUTHSIGNAL_SECRET_KEY" 
        self.webhook = Webhook(self.secret)
        self.payload_valid_signature = json.dumps({
            "version": 1,
            "id": "bc1598bc-e5d6-4c69-9afb-1a6fe3469d6e",
            "source": "https://authsignal.com",
            "time": "2025-02-20T01:51:56.070Z",
            "tenantId": "7752d28e-e627-4b1b-bb81-b45d68d617bc",
            "type": "email.created",
            "data": {
                "to": "not-a-real-email@authsignal.com",
                "code": "157743",
                "userId": "b9f74d36-fcfc-4efc-87f1-3664ab5a7fb0",
                "actionCode": "accountRecovery",
                "idempotencyKey": "ba8c1a7c-775d-4dff-9abe-be798b7b8bb9",
                "verificationMethod": "EMAIL_OTP",
            },
        })
        self.payload_multiple_keys = json.dumps({
            "version": 1,
            "id": "af7be03c-ea8f-4739-b18e-8b48fcbe4e38",
            "source": "https://authsignal.com",
            "time": "2025-02-20T01:47:17.248Z",
            "tenantId": "7752d28e-e627-4b1b-bb81-b45d68d617bc",
            "type": "email.created",
            "data": {
                "to": "not-a-real-email@authsignal.com",
                "code": "718190",
                "userId": "b9f74d36-fcfc-4efc-87f1-3664ab5a7fb0",
                "actionCode": "accountRecovery",
                "idempotencyKey": "68d68190-fac9-4e91-b277-c63d31d3c6b1",
                "verificationMethod": "EMAIL_OTP",
            },
        })
        self.timestamp = int(time.time())
        self.version = "v2"

    def generate_signature(self, payload, timestamp=None, secret=None, extra_signatures=None):
        if timestamp is None:
            timestamp = self.timestamp
        if secret is None:
            secret = self.secret
        hmac_content = f"{timestamp}.{payload}"
        computed_signature = base64.b64encode(
            hmac.new(secret.encode(), hmac_content.encode(), hashlib.sha256).digest()
        ).decode().replace("=", "")
        sigs = [f"{self.version}={computed_signature}"]
        if extra_signatures:
            sigs.extend([f"{self.version}={s}" for s in extra_signatures])
        return f"t={timestamp}," + ",".join(sigs)

    def test_invalid_signature_format(self):
        with self.assertRaises(InvalidSignatureError) as cm:
            self.webhook.construct_event(self.payload_valid_signature, "123")
        self.assertEqual(str(cm.exception), "Signature format is invalid.")

    def test_timestamp_tolerance_error(self):
        signature = "t=1630000000,v2=invalid_signature"
        with self.assertRaises(InvalidSignatureError) as cm:
            self.webhook.construct_event(self.payload_valid_signature, signature)
        self.assertEqual(str(cm.exception), "Timestamp is outside the tolerance zone.")

    def test_invalid_computed_signature(self):
        timestamp = int(time.time())
        signature = f"t={timestamp},v2=invalid_signature"
        with self.assertRaises(InvalidSignatureError) as cm:
            self.webhook.construct_event(self.payload_valid_signature, signature)
        self.assertEqual(str(cm.exception), "Signature mismatch.")

    def test_valid_signature(self):
        payload = self.payload_valid_signature
        timestamp = 1740016316 
        signature = self.generate_signature(payload, timestamp=timestamp, secret=self.secret)
        
        event = self.webhook.construct_event(payload, signature, tolerance=-1)
        self.assertIsNotNone(event)
        self.assertEqual(event["version"], 1)
        self.assertEqual(event["data"]["actionCode"], "accountRecovery")

    def test_valid_signature_multiple_keys(self):

        payload = self.payload_multiple_keys
        timestamp = 1740016037

        valid_signature = self.generate_signature(payload, timestamp=timestamp, secret=self.secret).split(",")[1]
        

        signature = f"t={timestamp},{valid_signature},v2=dummyInvalidSignature"

        event = self.webhook.construct_event(payload, signature, tolerance=-1)
        self.assertIsNotNone(event)
        self.assertEqual(event["version"], 1)
        self.assertEqual(event["data"]["actionCode"], "accountRecovery")

if __name__ == "__main__":
    unittest.main() 