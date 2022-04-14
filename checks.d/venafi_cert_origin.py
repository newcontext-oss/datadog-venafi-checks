# stdlib
from time import sleep

# 3rd party
import requests

# project
from datadog_checks.checks import AgentCheck


class VenafiCheck(AgentCheck):
    LIMIT = 100
    DELAY = 5

    TOKEN = ""
    BASE_URL = ""
    AUTH_METHOD = "api_key"
    USERNAME = ""
    PASSWORD = ""
    CLIENT_ID = ""
    SCOPE = ""

    VERIFY_SSL = True

    def check(self, instance):
        # configure
        self.configure(instance)

        # get access token
        if self.AUTH_METHOD == "oauth":
            self.authorize_oauth()
        else:
            self.authorize()

        # collect metrics
        self.count_cert_origins()

    def configure(self, instance):
        if "url" not in instance:
            raise Exception('Venafi instance missing "url" value.')
        if "auth_method" not in instance:
            raise Exception('Venafi instance missing "auth_method" value.')
        if "username" not in instance:
            raise Exception('Venafi instance missing "username" value.')
        if "password" not in instance:
            raise Exception('Venafi instance missing "password" value.')

        self.BASE_URL = instance["url"]
        self.AUTH_METHOD = instance["auth_method"]
        self.USERNAME = instance["username"]
        self.PASSWORD = instance["password"]

        if instance["auth_method"] == "oauth":
            if "client_id" not in instance:
                raise Exception('Venafi instance missing "client_id" value.')
            if "scope" not in instance:
                raise Exception('Venafi instance missing "scope" value.')

            self.CLIENT_ID = instance["client_id"]
            self.SCOPE = instance["scope"]

        if "req_limit" in instance:
            self.LIMIT = instance["req_limit"]

        if "req_delay" in instance:
            self.DELAY = instance["req_delay"]

        if "verify_ssl" in instance:
            self.VERIFY_SSL = instance["verify_ssl"]

    def authorize(self):
        url = self.BASE_URL + "/vedsdk/authorize/"

        payload = {
            "Username": self.USERNAME,
            "Password": self.PASSWORD,
        }

        headers = {"Content-Type": "application/json"}

        resp = requests.post(
            url,
            headers=headers,
            json=payload,
            verify=self.VERIFY_SSL,
        )

        if resp.status_code != 200:
            raise Exception(
                "Request error: url: %s, status: %d, response: %s"
                % (url, resp.status_code, resp.text)
            )

        self.TOKEN = resp.json()["APIKey"]

    def authorize_oauth(self):
        url = self.BASE_URL + "/vedauth/authorize/oauth"

        payload = {
            "username": self.USERNAME,
            "password": self.PASSWORD,
            "client_id": self.CLIENT_ID,
            "scope": self.SCOPE,
        }

        headers = {"Content-Type": "application/json"}

        resp = requests.post(
            url,
            headers=headers,
            json=payload,
            verify=self.VERIFY_SSL,
        )

        if resp.status_code != 200:
            raise Exception(
                "Request error: url: %s, status: %d, response: %s"
                % (url, resp.status_code, resp.text)
            )

        self.TOKEN = resp.json()["access_token"]

    def get_cert_origins(self):
        # set a delay between requests to avoid aborted connections
        sleep(self.DELAY)

        url = self.BASE_URL + "/vedsdk/certificates/"

        headers = {
            "Content-Type": "application/json",
            "X-Venafi-Api-Key": self.TOKEN,
        }

        params = {
            "limit": self.LIMIT,
        }

        resp = requests.get(
            url,
            params=params,
            headers=headers,
            verify=self.VERIFY_SSL,
        )

        if resp.status_code != 200:
            raise Exception(
                "Request error: url: %s, status: %d, response: %s"
                % (url, resp.status_code, resp.text)
            )

        certificates = resp.json()["Certificates"]

        if len(certificates) > 0:
            cert_origins = {}

            for certificate in certificates:
                url = self.BASE_URL + "/vedsdk/certificates/" + certificate["Guid"]

                headers = {
                    "Content-Type": "application/json",
                    "X-Venafi-Api-Key": self.TOKEN,
                }

                c_resp = requests.get(
                    url,
                    headers=headers,
                    verify=self.VERIFY_SSL,
                )

                if c_resp.status_code != 200:
                    raise Exception(
                        "Request error: url: %s, status: %d, response: %s"
                        % (url, c_resp.status_code, c_resp.text)
                    )

                cert = c_resp.json()

                if "Origin" in cert:
                    origin = cert["Origin"]

                    if origin in cert_origins:
                        cert_origins[origin] += 1
                    else:
                        cert_origins[origin] = 1

        return cert_origins

    def count_cert_origins(self):
        cert_origins = self.get_cert_origins()

        for origin_name, origin_count in cert_origins.items():
            self.count(
                "venafi.cert_origins.count",
                origin_count,
                tags=["origin:%s" % origin_name, "metric_submission_type:count",],
            )
