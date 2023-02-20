"""Google Cloud domain-wide delegation Impersonated credentials.

Domain-wide delegation
----------------------

Domain-wide delegation allows a service account to access user data on
behalf of any user in a Google Apps domain without consent from the user.
For example, an application that uses the Google Calendar API to add events to
the calendars of all users in a Google Apps domain would use a service account
to access the Google Calendar API on behalf of users.

This module provides authentication for applications where local credentials
impersonates a remote a domain-wide delagation service account using `IAM Credentials API`_.
   
This class can be used to impersonate a service account as long as the original
Credential object has the "Service Account Token Creator" role on the target
service account.

    .. _IAM Credentials API:
        https://cloud.google.com/iam/credentials/reference/rest/

This approach is more secure than using a service account key (long-term credential).
"""
import json
from datetime import datetime, timedelta
from http import client as http_client
from typing import Any, Dict, Mapping, Optional, Tuple

from google.auth import _helpers, credentials, exceptions
from google.auth.impersonated_credentials import Credentials as ImpersonatedCredentials
from google.auth.transport.requests import Request

_DEFAULT_TOKEN_LIFETIME_SECS = 3600  # 1 hour in seconds
_DEFAULT_TOKEN_URI = "https://oauth2.googleapis.com/token"  # nosec: B105
_TOKEN_OAUTH_GRANT = "urn:ietf:params:oauth:grant-type:jwt-bearer"  # nosec: B105
_DWD_ERROR = "Unable to acquire domain-wide delegation credentials"
_DWD_SIGN_ERROR = "Unable to sign domain-wide delegation token grant"
_IAM_SIGN_ENDPOINT = (
    "https://iamcredentials.googleapis.com/v1/projects/-"
    + "/serviceAccounts/{}:signJwt"
)


def _make_iam_sign_request(
    principal: str,
    headers: Mapping[str, str],
    body: Mapping[str, str],
    iam_sign_endpoint_override: Optional[str] = None,
) -> str:
    """Makes a request to the Google Cloud IAM service to a sign
       an OAuth 2.0 assertion.

    Args:
        principal (str): The principal to request an access token for.
        headers (Mapping[str, str]): Map of headers to transmit.
        body (Mapping[str, str]): JSON Payload body for the iamcredentials
            API call.
        iam_sign_endpoint_override (Optional[str]): The full IAM endpoint override
            with the target_principal embedded. This is useful when supporting
            impersonation with regional endpoints.

    Raises:
        google.auth.exceptions.TransportError: Raised if the impersonated
            credentials are not available.  Common reasons are
            `iamcredentials.googleapis.com` is not enabled or the
            `Service Account Token Creator` is not assigned

    Returns:
        str:  Requested OAuth 2.0 assertion
    """
    from google.auth.transport.requests import Request

    iam_endpoint = iam_sign_endpoint_override or _IAM_SIGN_ENDPOINT.format(principal)

    body = json.dumps(body).encode("utf-8")

    request = Request()
    response = request(url=iam_endpoint, method="POST", headers=headers, body=body)

    # support both string and bytes type response.data
    response_body = (
        response.data.decode("utf-8")
        if hasattr(response.data, "decode")
        else response.data
    )

    if response.status != http_client.OK:
        raise exceptions.TransportError(
            "{}: Error calling signJwt endpoint: {}".format(
                _DWD_SIGN_ERROR, response_body
            )
        )

    jwt_response: Dict[str, str] = json.loads(response_body)
    return jwt_response["signedJwt"]


def _make_token_request(
    request: Request, headers: Mapping[str, str], body: Mapping[str, str]
) -> Tuple[str, datetime]:
    """Makes a request to the OAuth 2.0 token endpoint for an access token.
    Args:
        request (Request): The Request object to use.
        headers (Mapping[str, str]): Map of headers to transmit.
        body (Mapping[str, str]): JSON Payload body for the iamcredentials
            API call.

    Raises:
        google.auth.exceptions.RefreshError: Raised if the domain-wide delegation
            credentials are not available.  Common reasons are
            `domain-wide delegation` is not setup or the
            `targeted_scopes` are not allowed

    Returns:
        Tuple[str, datetime]:  Requested access token and its expiry timestamp
    """
    token_uri = _DEFAULT_TOKEN_URI

    response = request(url=token_uri, method="POST", headers=headers, body=body)

    # support both string and bytes type response.data
    response_body = (
        response.data.decode("utf-8")
        if hasattr(response.data, "decode")
        else response.data
    )

    if response.status != http_client.OK:
        raise exceptions.RefreshError(_DWD_ERROR, response_body)

    try:
        token_response = json.loads(response_body)
        token = token_response["access_token"]

        lifetime = timedelta(seconds=token_response["expires_in"])
        expiry = _helpers.utcnow() + lifetime

        return token, expiry

    except (KeyError, ValueError, TypeError) as caught_exc:
        new_exc = exceptions.RefreshError(
            "{}: No access token or invalid expiration in response.".format(_DWD_ERROR),
            response_body,
        )
        raise new_exc from caught_exc


class Credentials(ImpersonatedCredentials):
    """This module defines Domain-wide delegation credentials produced via an
    impersonated workflow. This allow to obtain DWD credentials without requiring
    a service account key.

    The target service account must
    1) have domain-wide delegation enabled
    2) grant the originating credential principal the
    `Service Account Token Creator`_ IAM role:

    For more information about Token Creator IAM role and
    IAMCredentials API, see
    `Creating Short-Lived Service Account Credentials`_.

    .. _Service Account Token Creator:
        https://cloud.google.com/iam/docs/service-accounts#the_service_account_token_creator_role

    .. _Creating Short-Lived Service Account Credentials:
        https://cloud.google.com/iam/docs/creating-short-lived-service-account-credentials

    Usage:

    First grant source_credentials the `Service Account Token Creator`
    role on the target account to impersonate.  In this example, the
    identity (a user or a service account) represented by source_credentials has the
    token creator role on
    `dwd-impersonated-account@_project_.iam.gserviceaccount.com`
    and wants to act on behald of 'john.doe@pamplemousse.com'.

    Enable the IAMCredentials API on the source project:
    `gcloud services enable iamcredentials.googleapis.com`.

    Initialize a source credential which does not have access to
    Google Calendar::

        import google.auth

        target_scopes = ['https://www.googleapis.com/auth/calendar.readonly']
        subject = "john.doe@pamplemousse.com"

        source_credentials, _ = google.auth.default()

    Now use the source credentials to impersonate
    another service account and acquire delegated credentials::
        from google_auth_plugins import dwd_credentials

        delegated_credentials = dwd_credentials.Credentials(
        subject=subject,
        source_credentials=source_credentials,
        target_principal='dwd-impersonated-account@_project_.iam.gserviceaccount.com',
        target_scopes = target_scopes,
        )

    Resource access is granted::

        from googleapiclient.discovery import build

        try:
            service = build('calendar', 'v3', credentials=delegated_credentials)

            # Call the Calendar API
            now = utcnow().isoformat() + 'Z'  # 'Z' indicates UTC time
            print('Getting the upcoming 10 events')
            events_result = service.events().list(calendarId='primary', timeMin=now,
                                                maxResults=10, singleEvents=True,
                                                orderBy='startTime').execute()
            events = events_result.get('items', [])

            if not events:
                print('No upcoming events found.')
                return

            # Prints the start and name of the next 10 events
            for event in events:
                start = event['start'].get('dateTime', event['start'].get('date'))
                print(start, event['summary'])
        except HttpError as error:
            print('An error occurred: %s' % error)
    """

    def __init__(  # type: ignore[no-untyped-def]
        self,
        source_credentials,
        subject,
        target_scopes,
        target_principal=None,
        delegates=None,
        quota_project_id=None,
        iam_sign_endpoint_override=None,
    ):
        """
        Args:
            source_credentials (google.auth.Credentials): The source credential
                used as to acquire the impersonated credentials.
            subject (str): The email address of the
                user to for which to request delegated access.
            target_scopes (Sequence[str]): Scopes to request during the
                authorization grant.
            target_principal (Optional[str]): The service account to impersonate.
                If not defined 'source_credentials.service_account_email' will be the
                fallback value
            delegates (Sequence[str]): The chained list of delegates required
                to impersonated the final service account.  If set, the sequence of
                identities must have "Service Account Token Creator" capability
                granted to the preceding identity.  For example, if set to
                [serviceAccountB, serviceAccountC], the source_credential
                must have the Token Creator role on serviceAccountB.
                serviceAccountB must have the Token Creator on
                serviceAccountC.
                Finally, C must have Token Creator on target_principal.
                If left unset, source_credential must have that role on
                target_principal.
            quota_project_id (Optional[str]): The project ID used for quota and billing.
                This project may be different from the project used to
                create the credentials.
            iam_sign_endpoint_override (Optional[str]): The full IAM signJWT endpoint override
                with the target_principal embedded. This is useful when supporting regional endpoints.

        Raises:
            ValueError: Raised if target_principal hasn't been found.
        """
        dwd_principal = target_principal or (
            source_credentials.service_account_email
            if hasattr(source_credentials, "service_account_email")
            else None
        )
        super().__init__(
            source_credentials=source_credentials,
            target_principal=dwd_principal,
            target_scopes=target_scopes,
            delegates=delegates,
            quota_project_id=quota_project_id,
        )
        self._subject = subject
        self._iam_sign_endpoint_override = iam_sign_endpoint_override

        if self._target_principal is None:
            raise ValueError(
                "target_principal must be defined as an argument or comes from source_credentials"
            )

    @_helpers.copy_docstring(credentials.Credentials)
    def refresh(self, request):  # type: ignore[no-untyped-def]
        if not self._source_credentials.valid:
            self._source_credentials.refresh(request)

        body = {
            "delegates": self._delegates,
            "payload": json.dumps(self._get_assertion_payload()),
        }

        headers = {"Content-Type": "application/json"}

        # Apply the source credentials authentication info.
        self._source_credentials.apply(headers)

        signed_jwt = _make_iam_sign_request(
            principal=self.service_account_email,
            headers=headers,
            body=body,
            iam_sign_endpoint_override=self._iam_sign_endpoint_override,
        )

        body = {"grant_type": _TOKEN_OAUTH_GRANT, "assertion": signed_jwt}

        headers = {"Content-Type": "application/x-www-form-urlencoded"}

        self.token, self.expiry = _make_token_request(
            request=request,
            headers=headers,
            body=body,
        )

    def _get_assertion_payload(self) -> Dict[str, Any]:
        """Create an the OAuth 2.0 assertion payload.

        Once the assertion will be converted to JWT, it will used during the OAuth 2.0 grant to acquire an
        access token.

        Returns:
            dict: The authorization grant assertion payload.
        """
        lifetime = timedelta(seconds=_DEFAULT_TOKEN_LIFETIME_SECS)
        now = _helpers.utcnow()
        expiry = now + lifetime

        payload = {
            "iat": _helpers.datetime_to_secs(now),
            "exp": _helpers.datetime_to_secs(expiry),
            "iss": self._target_principal,
            "aud": _DEFAULT_TOKEN_URI,
            "sub": self._subject,
            "scope": " ".join(self._target_scopes),
        }

        return payload

    @_helpers.copy_docstring(credentials.CredentialsWithQuotaProject)
    def with_quota_project(self, quota_project_id):  # type: ignore[no-untyped-def]
        return self.__class__(
            self._source_credentials,
            subject=self._subject,
            target_principal=self._target_principal,
            target_scopes=self._target_scopes,
            delegates=self._delegates,
            quota_project_id=quota_project_id,
            iam_sign_endpoint_override=self._iam_sign_endpoint_override,
        )

    # mypy: disallow-untyped-defs
    @_helpers.copy_docstring(credentials.Scoped)
    def with_scopes(self, scopes, default_scopes=None):  # type: ignore[no-untyped-def]
        return self.__class__(
            self._source_credentials,
            subject=self._subject,
            target_principal=self._target_principal,
            target_scopes=scopes or default_scopes,
            delegates=self._delegates,
            quota_project_id=self._quota_project_id,
            iam_sign_endpoint_override=self._iam_sign_endpoint_override,
        )

    def with_subject(self, subject: str):  # type: ignore[no-untyped-def]
        """Create a copy of these credentials with the specified subject.

        Args:
            subject (str): The subject claim.

        Returns:
            google_auth_plugins.dwd_credentials.Credentials: A new credentials
                instance.
        """
        return self.__class__(
            self._source_credentials,
            subject=subject,
            target_principal=self._target_principal,
            target_scopes=self._target_scopes,
            delegates=self._delegates,
            quota_project_id=self._quota_project_id,
            iam_sign_endpoint_override=self._iam_sign_endpoint_override,
        )
