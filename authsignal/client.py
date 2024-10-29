import decimal
import authsignal
from authsignal.version import VERSION

import humps
from typing import Dict, Any, Optional
import json
import requests
import urllib.parse
from requests.adapters import HTTPAdapter

_UNICODE_STRING = str

API_BASE_URL = 'https://api.authsignal.com/v1'

BLOCK = "BLOCK"
ALLOW = "ALLOW"
CHALLENGE_REQUIRED = "CHALLENGE_REQUIRED"
CHALLENGE_FAILED = "CHALLENGE_FAILED"
CHALLENGE_SUCCEEDED = "CHALLENGE_SUCCEEDED"

class DecimalEncoder(json.JSONEncoder):
    def default(self, o):
        if isinstance(o, decimal.Decimal):
            return (str(o),)
        return super(DecimalEncoder, self).default(o)

class CustomSession(requests.Session):
    def __init__(self):
        super().__init__()
        self.mount('http://', HTTPAdapter())
        self.mount('https://', HTTPAdapter())

    def prepare_request(self, request):
        # Prepare the request to access the body
        prepared_request = super().prepare_request(request)
        
        # Remove None values from JSON payload
        if prepared_request.headers.get('Content-Type') == 'application/json' and prepared_request.body:
            try:
                data = json.loads(prepared_request.body)
                cleaned_data = self._remove_none_values(data)
                prepared_request.body = json.dumps(cleaned_data)
            except json.JSONDecodeError:
                pass
        return prepared_request

    @staticmethod
    def _remove_none_values(d: Dict[str, Any]) -> Dict[str, Any]:
        """Remove keys with None values from a dictionary."""
        return {k: v for k, v in d.items() if v is not None}

    def send(self, request, **kwargs):
        try:
            response = super().send(request, **kwargs)
            response.raise_for_status()  # Raises HTTPError for 4xx/5xx responses

            if response.headers.get('Content-Type') == 'application/json':
                try:
                    data = response.json()
                    if isinstance(data, dict) and 'actionCode' in data:
                        del data['actionCode']
                    response._content = json.dumps(humps.decamelize(data)).encode('utf-8')
                except json.JSONDecodeError:
                    pass
            return response
        except requests.exceptions.RequestException as e:
            # Handle the exception globally
            raise ApiException(str(e), request.url, http_status_code=e.response.status_code if e.response else None) from e

class Client(object):

    def __init__(
            self,
            api_key=None,
            api_url=API_BASE_URL,
            timeout=2.0,
            version=VERSION,
            session=None):
        """Initialize the client.
        Args:
            api_key: Your Authsignal Secret API key of your tenant
            api_url: Base URL, including scheme and host, for sending events.
                Defaults to 'https://signal.authsignal.com'.
            timeout: Number of seconds to wait before failing request. Defaults
                to 2 seconds.
        """
        _assert_non_empty_unicode(api_url, 'api_url')
        _assert_non_empty_unicode(api_key, 'api_key')

        if api_key is None:
            api_key = authsignal.api_key

        self.session = session or CustomSession()
        self.api_key = api_key
        self.url = api_url
        self.timeout = timeout
        self.version = version
        self.api_version = 'v1'

    def track(self, user_id, action, payload=None, path=None):
        """Tracks an action to authsignal, scoped to the user_id and action
        Returns the status of the action so that you can determine to whether to continue
        Args:
            user_id:  A user's id. This id should be the same as the user_id used in
                event calls.
            action: The action that you are retrieving, i.e. signIn
            payload(optional): The additional payload options to supply authsignal for more advance rules
        """
        _assert_non_empty_unicode(user_id, 'user_id')
        _assert_non_empty_unicode(action, 'action')

        headers = self._default_headers()

        if path is None:
            path = self._track_url(user_id, action)
        params = {}
        timeout = self.timeout

        response = self.session.post(
            path,
            data=json.dumps(payload if payload is not None else {}, cls=DecimalEncoder),
            auth=requests.auth.HTTPBasicAuth(self.api_key, ''),
            headers=headers,
            timeout=timeout,
            params=params)
        response.raise_for_status() 

        return response.json()
    
    def get_action(self, user_id, action, idempotency_key,  path=None):
        """Retrieves the action from authsignal, scoped to the user_id and action
        Returns the status of the action so that you can determine to whether to continue
        Args:
            user_id:  A user's id. This id should be the same as the user_id used in
                event calls.
            action: The action that you are retrieving, i.e. signIn
        """
        _assert_non_empty_unicode(user_id, 'user_id')
        _assert_non_empty_unicode(action, 'action')

        headers = self._default_headers()
        if path is None:
            path = self._get_action_url(user_id, action, idempotency_key)
        params = {}
        timeout = self.timeout

        response = self.session.get(
            path,
            auth=requests.auth.HTTPBasicAuth(self.api_key, ''),
            headers=headers,
            timeout=timeout,
            params=params)
        response.raise_for_status() 

        return response.json()

    def get_user(self, user_id, redirect_url=None,  path=None):
        """Retrieves the user from authsignal, and returns enrolment status, and self service url.
        Args:
            user_id:  A user's id. This id should be the same as the user_id used in
                event calls.
            redirect_url(optional): Use this to redirect the user back to the your page (redirect method)
        """
        _assert_non_empty_unicode(user_id, 'user_id')

        headers = headers = self._default_headers()
        if path is None:
            path = self._get_user_url(user_id)
        params = {}
        timeout = self.timeout

        if redirect_url is not None:
            _assert_non_empty_unicode(redirect_url, 'redirect_url')
            params.update({"redirectUrl": redirect_url})

        response = self.session.get(
            path,
            auth=requests.auth.HTTPBasicAuth(self.api_key, ''),
            headers=headers,
            timeout=timeout,
            params=params)
        response.raise_for_status()
        
        return response.json()
        
    def delete_user(self, user_id):
        _assert_non_empty_unicode(user_id, 'user_id')

        path = self._delete_user_url(user_id)
        headers = self._default_headers()

        response = self.session.delete(
            path,
            auth=requests.auth.HTTPBasicAuth(self.api_key, ''),
            headers=headers,
            timeout=self.timeout
        )
        response.raise_for_status()
        return response.json()
        
    def delete_authenticator(self, user_id: str, user_authenticator_id: str) -> Dict[str, Any]:
        _assert_non_empty_unicode(user_id, 'user_id')
        _assert_non_empty_unicode(user_authenticator_id, 'user_authenticator_id')

        user_id = urllib.parse.quote(user_id)
        user_authenticator_id = urllib.parse.quote(user_authenticator_id)
        path = f'{self.url}/v1/users/{user_id}/authenticators/{user_authenticator_id}'
        headers = self._default_headers()

        response = self.session.delete(
            path,
            auth=requests.auth.HTTPBasicAuth(self.api_key, ''),
            headers=headers,
            timeout=self.timeout
        )
        response.raise_for_status()
        return response.json()
        
    def update_user(self, user_id, data):
        user_id = urllib.parse.quote(user_id)

        path = self._get_user_url(user_id)

        headers = self._default_headers()

        response = requests.post(path, 
            json=data, 
            headers=headers, 
            auth=requests.auth.HTTPBasicAuth(self.api_key, '')
        )

        response.raise_for_status()

        return response.json()
    
    def enroll_verified_authenticator(self, user_id, authenticator_payload,  path=None):
        """Enrols an authenticator like a phone number for SMS on behalf of the user
        Args:
            user_id:  A user's id. This id should be the same as the user_id used in event calls.
            authenticator_payload:  A dictionary with the key/value of the authenticator you want to link {'oobChannel': 'SMS', 'phoneNumber': '+112345677777'}
        """
        _assert_non_empty_unicode(user_id, 'user_id')
        _assert_non_empty_dict(authenticator_payload, 'authenticator_payload')

        headers = self._default_headers()

        if path is None:
            path = self._post_enrollment_url(user_id)
        params = {}
        timeout = self.timeout

        response = self.session.post(
            path,
            auth=requests.auth.HTTPBasicAuth(self.api_key, ''),
            data=json.dumps(authenticator_payload),
            headers=headers,
            timeout=timeout,
            params=params)
        response.raise_for_status()
        return response.json()

    def validate_challenge(self, token: str, user_id: Optional[str] = None, action: Optional[str] = None) -> Dict[str, Any]:
        path = self._validate_challenge_url()
        headers = {
            'Content-Type': 'application/json',
            'Accept': 'application/json'
        }


        try:
            response = self.session.post(
                path,
                auth=requests.auth.HTTPBasicAuth(self.api_key, ''),
                data=json.dumps({'token': token, 'userId': user_id, 'action': action}),
                headers=headers,
                timeout=self.timeout
            )
            
            response_data = response.json()

            return response_data
        except requests.exceptions.RequestException as e:
            raise ApiException(str(e), path) from e

    def _default_headers(self):
        return {'Content-type': 'application/json',
                'Accept': '*/*',
                'User-Agent': self._user_agent()}

    def _user_agent(self):
        return f'Authsignal Python v{self.version}'

    def _track_url(self, user_id, action):
        path = self._ensure_versioned_path(f'/users/{user_id}/actions/{action}')
        return f'{self.url}{path}'

    def _get_action_url(self, user_id, action, idempotency_key):
        path = self._ensure_versioned_path(f'/users/{user_id}/actions/{action}/{idempotency_key}')
        return f'{self.url}{path}'

    def _get_user_url(self, user_id):
        path = self._ensure_versioned_path(f'/users/{user_id}')
        return f'{self.url}{path}'

    def _post_enrollment_url(self, user_id):
        path = self._ensure_versioned_path(f'/users/{user_id}/authenticators')
        return f'{self.url}{path}'
    
    def _validate_challenge_url(self):
        path = self._ensure_versioned_path(f'/validate')
        return f'{self.url}{path}'

    def _delete_user_url(self, user_id):
        user_id = urllib.parse.quote(user_id)
        path = self._ensure_versioned_path(f'/users/{user_id}')
        return f'{self.url}{path}'
    
    def _ensure_versioned_path(self, path):
        if not self.url.endswith(f'/{self.api_version}'):
            return f'/{self.api_version}{path}'
        return path

class ApiException(Exception):
    def __init__(self, message, url, http_status_code=None, body=None, api_status=None,
                 api_error_message=None, request=None):
        super().__init__(message)
        self.url = url
        self.http_status_code = http_status_code
        self.body = body
        self.api_status = api_status
        self.api_error_message = api_error_message
        self.request = request

    def __str__(self):
        return (f"{super().__str__()} status: {self.http_status_code}, "
                f"error: {self.api_error_message}, description: {self.body}")

def _assert_non_empty_unicode(val, name, error_cls=None):
    error = False
    if not isinstance(val, _UNICODE_STRING):
        error_cls = error_cls or TypeError
        error = True
    elif not val:
        error_cls = error_cls or ValueError
        error = True

    if error:
        raise error_cls('{0} must be a non-empty string'.format(name))

def _assert_non_empty_dict(val, name):
    if not isinstance(val, dict):
        raise TypeError('{0} must be a non-empty dict'.format(name))
    elif not val:
        raise ValueError('{0} must be a non-empty dict'.format(name))
