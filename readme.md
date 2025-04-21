<img width="1070" alt="Authsignal" src="https://raw.githubusercontent.com/authsignal/authsignal-python/main/.github/images/authsignal.png">

# Authsignal Python SDK

[![PyPI version](https://img.shields.io/pypi/v/authsignal.svg)](https://pypi.org/project/authsignal/)
[![License](https://img.shields.io/github/license/authsignal/authsignal-python.svg)](https://github.com/authsignal/authsignal-python/blob/main/LICENSE)

The official Authsignal Python library for server-side applications. Use this SDK to easily integrate Authsignal's multi-factor authentication (MFA) and passwordless features into your Python backend.

## Installation

```bash
pip3 install authsignal
```

or install newest source directly from GitHub:

```bash
pip3 install git+https://github.com/authsignal/authsignal-python
```

## Getting Started

Initialize the Authsignal client with your secret key from the [Authsignal Portal](https://portal.authsignal.com/) and the API URL for your region.

```python
from authsignal import Authsignal

# Initialize the client
authsignal = Authsignal(
    api_secret_key="your_secret_key",
    api_url="https://api.authsignal.com/v1"  # Use region-specific URL
)
```

### API URLs by Region

| Region      | API URL                          |
| ----------- | -------------------------------- |
| US (Oregon) | https://api.authsignal.com/v1    |
| AU (Sydney) | https://au.api.authsignal.com/v1 |
| EU (Dublin) | https://eu.api.authsignal.com/v1 |

## License

This SDK is licensed under the [MIT License](LICENSE).

## Documentation

For more information and advanced usage examples, refer to the official [Authsignal Server-Side SDK documentation](https://docs.authsignal.com/sdks/server/overview).
