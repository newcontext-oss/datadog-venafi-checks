# stdlib
from datetime import datetime

# 3rd party
import requests

# project
from datadog_checks.checks import AgentCheck


class VenafiCheck(AgentCheck):
    UTCNOW = datetime.utcnow()
    LIMIT = 5000
    LOG_LIMIT = 10000

    KEY_SIZES = [256, 512, 1024, 2048]
    KEY_ALGOS = ["RSA", "ECC"]

    TOKEN = ""
    BASE_URL = ""
    AUTH_METHOD = "api_key"
    USERNAME = ""
    PASSWORD = ""
    CLIENT_ID = ""
    SCOPE = ""

    def check(self, instance):
        # configure
        self.configure(instance)

        # get access token
        if self.AUTH_METHOD == "oauth":
            self.authorize_oauth()
        else:
            self.authorize()

        # collect metrics
        self.count_valid_certs()
        self.count_expired_certs()
        self.count_pending_certs()
        self.count_invalid_certs()
        self.count_inerror_certs()
        self.count_algo_certs()
        self.count_keysize_certs()

        self.count_domains_requested()

        log_events = self.get_log_events()

        self.count_cert_issue_times(log_events)
        self.count_cert_requesters(log_events)

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

        if "log_req_limit" in instance:
            self.LOG_LIMIT = instance["log_req_limit"]

        if "key_sizes" in instance:
            self.KEY_SIZES = instance["key_sizes"]

        if "key_algorithms" in instance:
            self.KEY_ALGOS = instance["key_algorithms"]

    def authorize(self):
        url = self.BASE_URL + "/vedsdk/authorize/"

        payload = {
            "Username": self.USERNAME,
            "Password": self.PASSWORD,
        }

        headers = {"Content-Type": "application/json"}

        resp = requests.post(url, headers=headers, json=payload)

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

        resp = requests.post(url, headers=headers, json=payload)

        if resp.status_code != 200:
            raise Exception(
                "Request error: url: %s, status: %d, response: %s"
                % (url, resp.status_code, resp.text)
            )

        self.TOKEN = resp.json()["access_token"]

    def count_expired_certs(self):
        url = self.BASE_URL + "/vedsdk/certificates/"

        params = {
            "ValidToLess": self.UTCNOW,
            "limit": self.LIMIT,
        }

        headers = {
            "Content-Type": "application/json",
            "X-Venafi-Api-Key": self.TOKEN,
        }

        payload = {"CertificateType": "CodeSigning"}

        resp = requests.get(url, params=params, headers=headers, json=payload)

        if resp.status_code != 200:
            raise Exception(
                "Request error: url: %s, status: %d, response: %s"
                % (url, resp.status_code, resp.text)
            )

        num_expired_certs = len(resp.json()["Certificates"])

        self.count(
            "venafi.expired_certs.count",
            num_expired_certs,
            tags=["metric_submission_type:count"],
        )

    def count_valid_certs(self):
        url = self.BASE_URL + "/vedsdk/certificates/"

        params = {
            "ValidToGreater": self.UTCNOW,
            "ValidFromLess": self.UTCNOW,
            "limit": self.LIMIT,
        }

        headers = {
            "Content-Type": "application/json",
            "X-Venafi-Api-Key": self.TOKEN,
        }

        payload = {"CertificateType": "CodeSigning"}

        resp = requests.get(url, params=params, headers=headers, json=payload)

        if resp.status_code != 200:
            raise Exception(
                "Request error: url: %s, status: %d, response: %s"
                % (url, resp.status_code, resp.text)
            )

        num_valid_certs = len(resp.json()["Certificates"])

        self.count(
            "venafi.valid_certs.count",
            num_valid_certs,
            tags=["metric_submission_type:count"],
        )

    def count_pending_certs(self):
        url = self.BASE_URL + "/vedsdk/certificates/"

        params = {
            "PendingWorkflow": "1",
            "limit": self.LIMIT,
        }

        headers = {
            "Content-Type": "application/json",
            "X-Venafi-Api-Key": self.TOKEN,
        }

        resp = requests.get(url, params=params, headers=headers)

        if resp.status_code != 200:
            raise Exception(
                "Request error: url: %s, status: %d, response: %s"
                % (url, resp.status_code, resp.text)
            )

        num_pending_certs = len(resp.json()["Certificates"])

        self.count(
            "venafi.pending_certs.count",
            num_pending_certs,
            tags=["metric_submission_type:count"],
        )

    def count_invalid_certs(self):
        url = self.BASE_URL + "/vedsdk/certificates/"

        params = {
            "ValidationState": "Failure",
            "limit": self.LIMIT,
        }

        headers = {
            "Content-Type": "application/json",
            "X-Venafi-Api-Key": self.TOKEN,
        }

        resp = requests.get(url, params=params, headers=headers)

        if resp.status_code != 200:
            raise Exception(
                "Request error: url: %s, status: %d, response: %s"
                % (url, resp.status_code, resp.text)
            )

        num_invalid_certs = len(resp.json()["Certificates"])

        self.count(
            "venafi.invalid_certs.count",
            num_invalid_certs,
            tags=["metric_submission_type:count"],
        )

    def count_inerror_certs(self):
        url = self.BASE_URL + "/vedsdk/certificates/"

        params = {
            "InError": "1",
            "limit": self.LIMIT,
        }

        headers = {
            "Content-Type": "application/json",
            "X-Venafi-Api-Key": self.TOKEN,
        }

        resp = requests.get(url, params=params, headers=headers)

        if resp.status_code != 200:
            raise Exception(
                "Request error: url: %s, status: %d, response: %s"
                % (url, resp.status_code, resp.text)
            )

        num_inerror_certs = len(resp.json()["Certificates"])

        self.count(
            "venafi.inerror_certs.count",
            num_inerror_certs,
            tags=["metric_submission_type:count"],
        )

    def count_algo_certs(self):
        url = self.BASE_URL + "/vedsdk/certificates/"

        headers = {
            "Content-Type": "application/json",
            "X-Venafi-Api-Key": self.TOKEN,
        }

        for algo in self.KEY_ALGOS:

            params = {
                "KeyAlgorithm": algo,
                "limit": self.LIMIT,
            }

            resp = requests.get(url, params=params, headers=headers)

            if resp.status_code != 200:
                raise Exception(
                    "Request error: url: %s, status: %d, response: %s"
                    % (url, resp.status_code, resp.text)
                )

            num_certs = len(resp.json()["Certificates"])

            self.count(
                "venafi.key_algorithm.count",
                num_certs,
                tags=[
                    "key_algorithm:%s" % algo.lower(),
                    "metric_submission_type:count",
                    ],
            )

    def count_keysize_certs(self):
        url = self.BASE_URL + "/vedsdk/certificates/"

        headers = {
            "Content-Type": "application/json",
            "X-Venafi-Api-Key": self.TOKEN,
        }

        for key_size in self.KEY_SIZES:
            params = {
                "KeySize": key_size,
                "limit": self.LIMIT,
            }

            resp = requests.get(url, params=params, headers=headers)

            if resp.status_code != 200:
                raise Exception(
                    "Request error: url: %s, status: %d, response: %s"
                    % (url, resp.status_code, resp.text)
                )

            num_certs = len(resp.json()["Certificates"])

            self.count(
                "venafi.key_size.count",
                num_certs,
                tags=["key_size:%s" % key_size, "metric_submission_type:count"],
            )

    def get_domains_requested(self):
        url = self.BASE_URL + "/vedsdk/certificates/"

        headers = {
            "Content-Type": "application/json",
            "X-Venafi-Api-Key": self.TOKEN,
        }

        params = {
            "limit": self.LIMIT,
        }

        resp = requests.get(url, params=params, headers=headers)

        if resp.status_code != 200:
            raise Exception(
                "Request error: url: %s, status: %d, response: %s"
                % (url, resp.status_code, resp.text)
            )

        certificates = resp.json()["Certificates"]

        common_name_results = {}
        sans_results = {}

        for certificate in certificates:
            if "X509" not in certificate:
                continue

            cn = certificate["X509"]["CN"]

            if cn in common_name_results:
                common_name_results[cn] += 1
            else:
                common_name_results[cn] = 1

            if "SANS" in certificate["X509"]:
                sans_group = certificate["X509"]["SANS"]

                for key in sans_group:
                    for sans_name in sans_group[key]:
                        if sans_name in sans_results:
                            sans_results[sans_name] += 1
                        else:
                            sans_results[sans_name] = 1

        results = {
            "cn": common_name_results,
            "sans": sans_results,
        }

        return results

    def count_domains_requested(self):
        requested = self.get_domains_requested()

        cn_requested = requested["cn"]
        sans_requested = requested["sans"]

        for cn_name, cn_count in cn_requested.items():
            self.count(
                "venafi.common_name.count",
                cn_count,
                tags=["cn:%s" % cn_name, "metric_submission_type:count",],
            )

        for sans_name, sans_count in sans_requested.items():
            self.count(
                "venafi.requested_sans.count",
                sans_count,
                tags=["sans:%s" % sans_name, "metric_submission_type:count",],
            )

    def get_cert_issue_times(self, log_events):
        certs = {}

        for event in log_events:
            # Cert Start Time
            if "Signing Request Created" in event["Name"]:
                comp = event["Component"]

                if comp not in certs:
                    certs[comp] = {}

                cert_issue_start = self.format_date(event["ServerTimestamp"])

                certs[comp]["cert_issue_start"] = cert_issue_start

            # Cert End Time
            elif "Certificate Ready To Download" in event["Name"]:
                comp = event["Component"]

                if comp not in certs:
                    certs[comp] = {}

                cert_issue_end = self.format_date(event["ServerTimestamp"])

                certs[comp]["cert_issue_end"] = cert_issue_end

            # CA Start Time
            elif "CSR Post Successful" in event["Name"]:
                comp = event["Text1"]

                if comp not in certs:
                    certs[comp] = {}

                ca_issue_start = self.format_date(event["ServerTimestamp"])

                certs[comp]["ca_issue_start"] = ca_issue_start

            # CA End Time
            elif "Certificate Retrieval Successful" in event["Name"]:
                comp = event["Text1"]
                if comp not in certs:
                    certs[comp] = {}

                ca_issue_end = self.format_date(event["ServerTimestamp"])

                certs[comp]["ca_issue_end"] = ca_issue_end

        ca_issue_times = []
        cert_issue_times = []

        # Calculate issuance times
        for comp in certs:
            if "ca_issue_start" in certs[comp] and "ca_issue_end" in certs[comp]:
                start = certs[comp]["ca_issue_start"]
                end = certs[comp]["ca_issue_end"]
                issue_time = end - start

                ca_issue_times.append(issue_time.seconds)

            if "cert_issue_start" in certs[comp] and "cert_issue_end" in certs[comp]:
                start = certs[comp]["cert_issue_start"]
                end = certs[comp]["cert_issue_end"]
                issue_time = end - start

                cert_issue_times.append(issue_time.seconds)

        avg_ca_issue_time = self.average(ca_issue_times)
        avg_cert_issue_time = self.average(cert_issue_times)

        issue_times = {
            "ca": avg_ca_issue_time,
            "cert": avg_cert_issue_time,
        }

        return issue_times

    def count_cert_issue_times(self, log_events):
        issue_times = self.get_cert_issue_times(log_events)
        ca_issue_time = issue_times["ca"]
        cert_issue_time = issue_times["cert"]

        self.count(
            "venafi.ca_issue_time.avg",
            ca_issue_time,
            tags=["metric_submission_type:count"],
        )

        self.count(
            "venafi.cert_issue_time.avg",
            cert_issue_time,
            tags=["metric_submission_type:count"],
        )

    def get_cert_requesters(self, log_events):
        results = {}

        for event in log_events:
            if "Object Created" in event["Name"]:
                requester = event["Text1"]

                if requester in results:
                    results[requester] += 1
                else:
                    results[requester] = 1

        return results

    def count_cert_requesters(self, log_events):
        requestors = self.get_cert_requesters(log_events)

        for requester, count in requestors.items():
            self.count(
                "venafi.cert_requester.count",
                count,
                tags=["requester:%s" % requester, "metric_submission_type:count"],
            )

    def get_log_events(self):
        url = self.BASE_URL + "/vedsdk/Log/"

        params = {
            "limit": self.LOG_LIMIT,
        }

        headers = {
            "Content-Type": "application/json",
            "X-Venafi-Api-Key": self.TOKEN,
        }

        resp = requests.get(url, params=params, headers=headers)

        if resp.status_code != 200:
            raise Exception(
                "Request error: url: %s, status: %d, response: %s"
                % (url, resp.status_code, resp.text)
            )

        logs = resp.json()["LogEvents"]

        return logs

    def average(self, nums):
        if not nums:
            return None

        raw_avg = sum(nums) / len(nums)

        # round to last 3 decimal places for easier visual inspection
        avg = round(raw_avg, 3)

        return avg

    def format_date(self, timestamp):
        # remove zeros past microseconds
        _time = timestamp.split(".")
        _timestamp = ".".join([_time[0], _time[1][:6]])

        formatted_date = datetime.strptime(_timestamp, "%Y-%m-%dT%H:%M:%S.%f")

        return formatted_date
