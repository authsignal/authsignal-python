# Authsignal Server Python SDK

[Authsignal](https://www.authsignal.com/?utm_source=github&utm_medium=python_sdk) provides passwordless step up authentication (Multi-factor Authentication - MFA) that can be placed anywhere within your application. Authsignal also provides a no-code fraud risk rules engine to manage when step up challenges are triggered.

## Installation

Python 3

```bash
pip3 install authsignal
```

or install newest source directly from GitHub:

```bash
pip3 install git+https://github.com/authsignal/authsignal-python
```

## Configuration
Initialize the Authsignal Python SDK, ensuring you do not hard code the Authsignal Secret Key, always keep this safe.

```python
import authsignal.client

authsignal_client = authsignal.Client(api_key='<SECRET API KEY HERE>')
```

## Usage

Authsignal's server side signal API has four main calls `track`, `get_action`, `get_user`, `identify`, `enroll_verified_authenticator`

These examples assume that the SDK is being called from a Starlette based framework like FastAPI, adapt depending on your app server framework.

### Track Action
The track action call is the main api call to send actions to authsignal, the default decision is to `ALLOW` actions, this allows you to call track action as a means to keep an audit trail of your user activity.

Add to the rules in the admin portal or the change default decision to influence the flows for your end users. If a user is not enrolled with authenticators, the default decision is to `ALLOW`.

```python
# OPTIONAL: The Authsignal cookie available when using the authsignal browser Javascript SDK
# you could you use own device/session/fingerprinting identifiers.
authsignal_cookie = request.cookies.get('__as_aid')

# OPTIONAL: The idempotency_key is a unique identifier per track action
# this could be for a unique object associated to your application
# like a shopping cart check out id
# If ommitted, Authsignal will generate the idempotencyKey and return in the response
import uuid
idempotency_key = uuid.uuid4()

# OPTIONAL: If you're using a redirect flow, set the redirect URL, this is the url authsignal will redirect to after a Challenge is completed.
redirect_url = "https://www.yourapp.com/back_to_your_app"

response = authsignal_client.track(
    user_id="python:1",
    action_code="testPython",
    payload={
        "redirectUrl": "https://www.example.com/",
        "email": "test@python.com",
        "deviceId": authsignal_cookie,
        "userAgent": request.headers["user-agent"],
        "ipAddress": request.headers["x-forwarded-for"],
        "custom": {
            "yourOwnCustomBoolean": True,
            "yourOwnCustomString": "Blue",
            "yourOwnCustomDecimal": 100.00,
        },
    }
)

```
*Response*
```python
response = authsignal_client.track(...)
match response["state"]
case authsignal.client.ALLOW:
    # Carry on with your operation/business logic
case authsignal.client.BLOCK:
    # Stop your operations
case authsignal.client.CHALLENGE_REQUIRED:
    # Step up authentication required, redirect or pass the challengeUrl to the front end
    response["challengeUrl"]
```

### Get Action
Call get action after a challenge is completed by the user, after a redirect or a succesful browser challenge pop-up flow, and if the state of the action is `CHALLENGE_SUCCEEDED` you can proceed with completing the business logic.

```python
response = authsignal_client.get_action(
    user_id="1234",
    action_code="signIn",
    idempotency_key="0ae73782-d8c1-49bc-be75-09612a3b9d1c",
)

if response["state"] == "CHALLENGE_SUCCEEDED":
    print("Procceed with business logic")
    # The user has successfully completed the challenge, and you should proceed with
    # the business logic
```

### Get User
Get user retrieves the current enrolment state of the user, use this call to redirect users to the enrolment or management flows so that the user can do self service management of their authenticator factors. User the `url` in the response to either redirect or initiate the pop up client side flow.

```python
response = authsignal_client.get_user(user_id="1234", redirect_url="http://www.yourapp.com/path-back")

is_enrolled = response["isEnrolled"]
url = response["url"]
```

### Identify
Get identify to link and update additional user indetifiers (like email) to the primary record.

```python
response = authsignal_client.identify(user_id="python:1", user_payload={"email": "new@email.com"})
```

### Enrol Authenticator
If your application already has a valid authenticator like a validated phone number for your customer, you can enrol the authenticator on behalf of the user using this function

```python
response = authsignal_client.enroll_verified_authenticator(user_id="1234", authenticator_payload={"oobChannel": "SMS", "phoneNumber": "+64277770770"})
```