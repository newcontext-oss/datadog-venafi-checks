# Datadog Venafi checks

[![New Context](https://img.shields.io/badge/awesome-for%20hire-orange?style=flat-square)](http://www.newcontext.com)

This is a collection of [metrics](http://docs.datadoghq.com/developers/metrics/agent_metrics_submission) and [checks](http://docs.datadoghq.com/guides/agent_checks/) for a [Datadog agent](https://github.com/DataDog/datadog-agent) deployed on the Venafi Trust Protection Platform server. These metrics provide insight into the health of the Venafi platform, and a live, at-a-glance view into the machine identities active throughout your organization. This repo also includes pre-built dashboards for these metrics that can be imported to an active Datadog account.

## Using The Checks

The Datadog agent is assumed to be installed on a host running Microsoft Windows.

Place the `.py` file you want to use in to the checks directory — `C:\ProgramData\Datadog\checks.d` by default — and the YAML config file in the config directory — `C:\ProgramData\Datadog\conf.d` by default. Restart the agent to verify that the plugin is working.

To install the project's dependencies, clone this repo to the host machine and run `pip install -r requirements.txt`.

### Checks Configuration Files

#### `venafi_cert.yaml`

| Key                     | Description                                                                                          | Required |
| ----------------------- | ---------------------------------------------------------------------------------------------------- | -------- |
| url                     | The url of the Venafi instance                                                                       | Yes      |
| auth_method             | `oauth` or `api_key` (Default)                                                                       | No       |
| username                | Venafi tpp username                                                                                  | Yes      |
| password                | Venafi tpp password                                                                                  | Yes      |
| client_id               | `OAuth` client id. Required if `auth_method` is `oauth`.                                             | No       |
| scope                   | `OAuth` scope. Required if `auth_method` is `oauth`.                                                 | No       |
| req_limit               | Default is `10000`. Limits number of records returned from the API.                                  | No       |
| key_sizes               | Default is a list of `[512, 1024, 2048]`                                                             | No       |
| key_algorithms          | Default is a list of `["RSA", "ECC"]`                                                                | No       |
| min_collection_interval | Default is `60`. Sets the minimum interval of metrics collections when the DataDog agent is running. | No       |
| verify_ssl              | Default is `True`. Verify SSL certificates. Set to `False` if using self-signed SSL certificates     | No       |

#### `venafi_cert_origin.yaml`

| Key                     | Description                                                                                          | Required |
| ----------------------- | ---------------------------------------------------------------------------------------------------- | -------- |
| url                     | The url of the Venafi instance                                                                       | Yes      |
| auth_method             | `oauth` or `api_key` (Default)                                                                       | No       |
| username                | Venafi tpp username                                                                                  | Yes      |
| password                | Venafi tpp password                                                                                  | Yes      |
| client_id               | `OAuth` client id. Required if `auth_method` is `oauth`.                                             | No       |
| scope                   | `OAuth` scope. Required if `auth_method` is `oauth`.                                                 | No       |
| req_limit               | Default is `10`. Limits number of records returned from the API.                                     | No       |
| req_delay               | Default is `3`. Sets a delay between the fetching of record sets.                                    | No       |
| key_algorithms          | Default is a list of `["RSA", "ECC"]`                                                                | No       |
| min_collection_interval | Default is `60`. Sets the minimum interval of metrics collections when the DataDog agent is running. | No       |
| verify_ssl              | Default is `True`. Verify SSL certificates. Set to `False` if using self-signed SSL certificates     | No       |

#### `venafi_db.yaml`

| Key                     | Description                                                                                          | Required |
| ----------------------- | ---------------------------------------------------------------------------------------------------- | -------- |
| backup_path             | The path to the `VenafiTPP.bak` file                                                                 | Yes      |
| min_collection_interval | Default is `60`. Sets the minimum interval of metrics collections when the DataDog agent is running. | No       |

## Using the Dashboards

Import the dashboards with the following directions:

https://docs.datadoghq.com/dashboards/#copy-import-export

## Checks

Here's our list of checks!

### Windows Service

Provides a status check of windows services running, needed for the Venafi platform.

This uses the built-in [check](https://docs.datadoghq.com/integrations/windows_service/) and configured to monitor the following services:

- Venafi services
- Microsoft SQL

Note: Installation only requires copying the `conf.d/windows_service.yaml` file. There is no `check.d/windows_service.py` to copy over.

Note: Venafi services and the database may be running on different hosts. In this case, comment out the lines that are not relevant to the host.

## Venafi Cert

Provides the following metrics:

- valid certificates
- expired certificates
- pending certificates
- certificates failed validation
- certificates in error state
- key sizes
- key algorithms
- common names requested
- subject alternative names requested
- certificate requesters
- certificate issuance time
- CA issuance time

### Valid Certificates

`venafi.valid_certs.count`

Returns the number of certificates that are valid and have not expired. These certificates are between their "ValidFrom" and "ValidTo" dates with respect to the current UTC time.

### Expired Certificates

`venafi.expired_certs.count`

Returns the number of certificates that are not valid and have expired. These certificates are outside of their "ValidFrom" and "ValidTo" dates with respect to the current UTC time.

### Pending Certificates

`venafi.pending_certs.count`

Returns the number of certificates in a pending workflow.

### Certificates Failed Validation

`venafi.invalid_certs.count`

Returns the number of certificates that failed validation.

### Certificates in Error

`venafi.inerror_certs.count`

Returns the number of certificates in an error state.

### Key Sizes

`venafi.key_size.count`

Returns the number of certificates with their respective key size.

For example, there could be 100 certificates with a key length of 1024 bits and 10 certificates with key length of 512 bits.

### Key Algorithms

`venafi.key_algorithm.count`

Returns the number of certificates with their respective key algorithms.

For example, there could be 100 certificates using the RSA algorithm and 10 certificates using the ECC algorithm.

### Common Names Requested

`venafi.common_name.count`

Returns the number of occurrences that a domain is requested in the certificate's common name (CN) field.

For example, there could be 100 certificates with common name "dev.local".

### Subject Alternative Names Requested

`venafi.requested_sans.count`

Returns the number of occurrences that a domain/ip/email is requested in the certificate's subject alternative names (SANS) field.

For example, there could be 100 certificates that include "dev.local" in the subject alternative names field.

### Certificate Requesters

`venafi.cert_requester.count`

Returns the number of occurences that a user requested a certificate.

### Certificate Issuance Time

`venafi.cert_issue_time.avg`

Returns the average number of seconds for the Venafi platform to generate a certificate.

### CA Issuance Time

`venafi.ca_issue_time.avg`

Returns the average number of seconds for the Certificate Authority (CA) to respond to a certificate signing request (CSR).

### Venafi Cert Origin

`venafi.cert_origins.count`

Provides the "Origin" field used in certificates (e.g. web-admin).

### Venafi DB

`venafi.db_backup.mtime`

Provides the last modification time for a database backup (e.g. 2020-05-05 0900).

## Dashboards

### Venafi Service

Displays a snap-shot view of Venafi services to quickly see if a service is failing.

### Venafi Requesters

Displays the following metrics when a new certificate is requested:

- domains in the cn and sans fields
- origins requested
- users requesting certificates

### Venafi Certificates

Displays timeseries of certificate metrics to see historical trends

## Running the project locally

You will need Docker, Python 3.7+ and PIP installed and in your `$PATH` as well as a valid DataDog API Key.

1. Install the project's dependencies by first cloning this repo to your local machine. Then run `pip install -r requirements.txt`.
2. Run `export DD_API_KEY=YOURKEYHERE`.
3. Run `docker-compose -up` in the project directory.

## Contributing

This project thrives on community contributions.

Information about contributing to the project can be found in the
[Contributing document](CONTRIBUTING.md).

## Powered by New Context

[![New Context Logo](https://newcontext.com/wp-content/uploads/2018/02/New-Context-logo2.png)](http://www.newcontext.com)

This project is maintained and funded by New Context, which provides
"security first" automation to mission critical infrastructure.
Founded in 2013, we were doing DevSecOps before it became a buzzword. You can
[hire us](https://newcontext.com/contact-us/) to
improve your time-to-market, reduce risk, and boost your security/compliance posture.

We're always [looking to hire](https://newcontext.com/careers/) seasoned engineers,
with a mixed background across development, IT infrastructure, automation, and/or security.

## License

This project is distributed under the [Apache License](LICENSE).
