Google Auth Plugins Python Library
==================================

<!--- @begin-badges@ --->
![CI](https://github.com/LoicSikidi/google-auth-plugins-library-python/workflows/CI/badge.svg)
[![PyPI version](https://badge.fury.io/py/google-auth-plugins.svg)](https://pypi.org/project/google-auth-plugins)
<!--- @end-badges@ --->

This library (built on top of [Google's official SDK](https://github.com/googleapis/google-auth-library-python)) aims to provide features not implemented by the standard library for whatever reason.

Common reason is that the latter is not a priority in the SDK's roadmap.

⚠️ **This project doesn't want or plan to replace the official SDK but rather to be a space for experimentation providing beta features (*because security does have to wait*).**

I hope that the features available in this repo will be integrated in the official library for the common good.

## Index

* [Main difference with google-auth](#main-difference-with-google-auth)
* [Installation](#installation)
* [Usage](#usage)
  * [Domain-wide delegation credentials](#domain-wide-delegation-credentials)
* [Tests](#tests)

## Main difference with google-auth

For security reasons, this project will **always** drop support for a python version as soon as security support ends.

As an example, the version [2.16.1](https://github.com/googleapis/google-auth-library-python/blob/main/CHANGELOG.md#2161-2023-02-17) of `google-auth` launched on *2023-02-17* still supports python3.6[^1].

[^1]: https://devguide.python.org/versions/

## Installation

`google-auth-plugins` requires Python 3.7 or newer, and can be installed directly via `pip`:

```console
python3 -m venv venv && source venv/bin/activate
python -m pip install google-auth-plugins
```

## Usage

### Domain-wide delegation credentials

**A bit of context**

As stated in this [issue](https://github.com/googleapis/google-auth-library-python/issues/930) currently it's not possible to produce a delegated credentials via an impersonated identity. 

To put it another way, **today the only way to obtain those credentials is with a service account key 🤯**.

Given the importance of this kind of service accounts it seems relevant to limit as much as possible long-term credentials in order to protect against leaks.

*Domain-wide delegation credentials* allows that.

Please find below an example:

```python
import google.auth
from google_auth_plugins import dwd_credentials

target_scopes = ['https://www.googleapis.com/auth/calendar.readonly']
subject = "john.doe@pamplemousse.com"

# The impersonated service account must grant `Service Account Token Creator` to the identity represented by source_credentials
source_credentials, _ = google.auth.default()

delegated_credentials = dwd_credentials.Credentials(
  subject=subject,
  source_credentials=source_credentials,
  target_principal='dwd-impersonated-account@_project_.iam.gserviceaccount.com',
  target_scopes = target_scopes,
)
```

Alternatively, if `source_credentials` is the service account with domain-wide delegation, you can skip *target_principal* definition.

```python
source_credentials, _ = google.auth.default()

delegated_credentials = dwd_credentials.Credentials(
  subject=subject,
  source_credentials=source_credentials,
  target_scopes = target_scopes,
)
```

Finally you can switch delegated credentials as defined below:

```python
alice_delegated_creds = dwd_credentials.Credentials(
  subject="alice@example.com",
  source_credentials=source_credentials,
  target_scopes = target_scopes,
)

bob_delegated_creds = alice_delegated_creds.with_subject("bob@example.com")
```

***Note**: this module is heavily inspired by [Johannes Passing](https://jpassing.com/2022/01/15/using-domain-wide-delegation-on-google-cloud-without-service-account-keys/) blog post 🚀.* 

## Tests

```bash
make test
```