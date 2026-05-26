from threading import Lock

from dlt.common.configuration import configspec
from dlt.common.configuration.specs import CredentialsConfiguration
from dlt.sources.helpers import requests
from dlt.sources.helpers.rest_client.auth import AuthConfigBase


@configspec
class JamfCredentials(CredentialsConfiguration):
    host: str = None

    def auth(self):
        pass


@configspec
class JamfPasswordCredentials(JamfCredentials):
    username: str = None
    password: str = None

    @property
    def auth(self):
        return "password"

    @property
    def token(self):
        response = requests.post(
            f"{self.host}/api/v1/auth/token",
            auth=(self.username, self.password),
        )
        response.raise_for_status()
        return response.json()["token"]


@configspec
class JamfClientCredentials(JamfCredentials):
    client_id: str = None
    client_secret: str = None

    @property
    def auth(self):
        return "client"

    @property
    def token(self):
        response = requests.post(
            f"{self.host}/api/v1/oauth/token",
            data={
                "grant_type": "client_credentials",
                "client_id": self.client_id,
                "client_secret": self.client_secret,
            },
        )
        response.raise_for_status()
        return response.json()["access_token"]


@configspec
class JamfAuth(AuthConfigBase):
    def __init__(self, credentials: JamfPasswordCredentials | JamfClientCredentials):
        self.credentials = credentials
        self.token: str | None = None
        self._token_lock = Lock()

    def get_token(self) -> str:
        if not self.token:
            with self._token_lock:
                self.token = self.credentials.token

        return self.token

    def __call__(self, request):
        request.headers["Authorization"] = f"Bearer {self.get_token()}"
        return request
