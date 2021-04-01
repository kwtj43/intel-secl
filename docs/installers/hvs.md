# HVS Installer

## Environment variables

Following env variable(s) are for configuring the behavior of hve installer. Such variables has to
be set in the shell running installer binary.

 Key | Required | Type | Description 
-----|----------|------|-------------
 HVS_NOSETUP | - | `string` | If set to `true`, installer will not perform setup tasks

## Usage
```shell
./hvs-v3.0.0.bin
```

## env file

`env file` is a file defining key-value pairs that can be automatically loaded during the setup process of hvs.
Reference [answer-file.md](../shared/setup/answer-file.md) for more information.

### Fields for HVS setup only

These fields are used for running hvs setup tasks only. None of which is later stored in hvs configuration file,
`/etc/hvs/config.yml`

Field | Required | Type | Description | Alternative
------|----------|------|-------------|-------------
BEARER_TOKEN | `Required` | `string` | The bearer token for accessing `CMS` |
DB_SSL_CERT_SOURCE | - |`string` | The source file from which to copy database SSL certificate | HVS_DB_SSL_CERT_SOURCE

### Fields for HVS configuration

Each of the following field corresponds a field in hvs configuration file. 

Category | Field | Required | Type | Default | Alternative
---------|-------|----------|------|---------|-------------
General | AAS_BASE_URL | `Required` | `string` | | AAS_API_URL
\- | CMS_BASE_URL | `Required` |`string` | |
\- | CMS_CERT_DIGEST | `Required` |`string` | |
HVS | HVS_SERVICE_USERNAME | `Required` |`string` | |
\- | HVS_SERVICE_PASSWORD | `Required` |`string` | |
\- | HVS_DATA_ENCRYPTION_KEY | - |`string` | |
TLS | TLS_CERT_FILE | - |`string` | |
\- | TLS_KEY_FILE | - |`string` | |
\- | TLS_COMMON_NAME | - |`string` | |
\- | TLS_SAN_LIST | - |`string` | | SAN_LIST
SAML | SAML_CERT_FILE | - |`string` | |
\- | SAML_KEY_FILE | - |`string` | |
\- | SAML_COMMON_NAME | - |`string` | |
\- | SAML_ISSUER_NAME | - |`string` | |
\- | SAML_VALIDITY_SECONDS | - |`int` | 86400 |
Flavor Signing | FLAVOR_SIGNING_CERT_FILE | - |`string` || 
\- | FLAVOR_SIGNING_KEY_FILE | - |`string` | |
\- | FLAVOR_SIGNING_COMMON_NAME | - |`string` | |
Privacy CA | PRIVACY_CA_CERT_FILE | - |`string` | |
\- | PRIVACY_CA_KEY_FILE | - |`string` | |
\- | PRIVACY_CA_COMMON_NAME | - |`string` | |
\- | PRIVACY_CA_ISSUER | - |`string` | |
\- | PRIVACY_CA_VALIDITY_YEARS | - |`int` | |
Tag CA | TAG_CA_CERT_FILE | - |`string` | |
\- | TAG_CA_KEY_FILE | - |`string` | |
\- | TAG_CA_COMMON_NAME | - |`string` | |
\- | TAG_CA_ISSUER | - |`string` | |
\- | TAG_CA_VALIDITY_YEARS | - |`int` | |
Log | LOG_MAX_LENGTH | - |`int` | |
\- | LOG_ENABLE_STDOUT | - |`bool` | |
\- | LOG_LEVEL | - |`string` | |
Endorsement CA | ENDORSEMENT_CA_CERT_FILE | - |`string` | |
\- | ENDORSEMENT_CA_KEY_FILE | - |`string` | |
\- | ENDORSEMENT_CA_COMMON_NAME | - |`string` | |
\- | ENDORSEMENT_CA_ISSUER | - |`string` | |
\- | ENDORSEMENT_CA_VALIDITY_YEARS | - |`int` | |
Server | SERVER_PORT | - |`int` | |
\- | SERVER_READ_TIMEOUT | - |`Duration` | | HVS_SERVER_READ_TIMEOUT
\- | SERVER_READ_HEADER_TIMEOUT | - |`Duration` | | HVS_SERVER_READ_HEADER_TIMEOUT
\- | SERVER_WRITE_TIMEOUT | - |`Duration` | | HVS_SERVER_WRITE_TIMEOUT
\- | SERVER_IDLE_TIMEOUT | - |`Duration` | | HVS_SERVER_IDLE_TIMEOUT
\- | SERVER_MAX_HEADER_BYTES | - |`int` | | HVS_SERVER_MAX_HEADER_BYTES
Database | DB_VENDOR |  |`string` | | HVS_DB_VENDOR
\- | DB_HOST | `Required` |`string` | | HVS_DB_HOSTNAME
\- | DB_PORT | `Required` |`int` | | HVS_DB_PORT
\- | DB_NAME | `Required` |`string` | | HVS_DB_NAME
\- | DB_USERNAME | `Required` |`string` | | HVS_DB_USERNAME
\- | DB_PASSWORD | `Required` |`string` | | HVS_DB_PASSWORD
\- | DB_SSL_MODE | - |`string` | verify-full | HVS_DB_SSL_MODE
\- | DB_SSL_CERT | - |`string` | | HVS_DB_SSLCERT
\- | DB_CONN_RETRY_ATTEMPTS | - |`int` | 4 |
\- | DB_CONN_RETRY_TIME | - |`int` | 1 |
HRRS | HRRS_REFRESH_PERIOD | - |`Duration` | 2 minutes ("2m")|
\- | HRRS_REFRESH_LOOK_AHEAD | - |`Duration` | 5 minutes ("5m")|
Audit Log | AUDIT_LOG_MAX_ROW_COUNT | - | `int` | 10000
\- | AUDIT_LOG_NUMBER_ROTATED | - | `int` | 10
\- | AUDIT_LOG_BUFFER_SIZE | - | `int` | 5000
