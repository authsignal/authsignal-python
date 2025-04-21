import hmac
import hashlib
import base64
import json
import time
from typing import List, Dict, Any

DEFAULT_TOLERANCE = 5  # minutes
VERSION = "v2"

class InvalidSignatureError(Exception):
    pass

class Webhook:
    def __init__(self, api_secret_key: str):
        self.api_secret_key = api_secret_key

    def construct_event(self, payload: str, signature: str, tolerance: int = DEFAULT_TOLERANCE) -> Dict[str, Any]:
        parsed_signature = self.parse_signature(signature)
        seconds_since_epoch = int(time.time())

        if tolerance > 0 and parsed_signature["timestamp"] < seconds_since_epoch - tolerance * 60:
            raise InvalidSignatureError("Timestamp is outside the tolerance zone.")

        hmac_content = f"{parsed_signature['timestamp']}.{payload}"
        computed_signature = base64.b64encode(
            hmac.new(
                self.api_secret_key.encode(),
                hmac_content.encode(),
                hashlib.sha256
            ).digest()
        ).decode().replace("=", "")

        match = any(sig == computed_signature for sig in parsed_signature["signatures"])
        if not match:
            raise InvalidSignatureError("Signature mismatch.")

        return json.loads(payload)

    def parse_signature(self, value: str) -> Dict[str, Any]:
        timestamp = -1
        signatures: List[str] = []
        for item in value.split(","):
            kv = item.split("=")
            if kv[0] == "t":
                timestamp = int(kv[1])
            if kv[0] == VERSION:
                signatures.append(kv[1])
        if timestamp == -1 or not signatures:
            raise InvalidSignatureError("Signature format is invalid.")
        return {"timestamp": timestamp, "signatures": signatures} 