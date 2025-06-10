# ngx_http_auth_internal_module

# Name

This Nginx module provides internal request authentication by validating a custom HTTP header (default is X-Fingerprint) against a set of predefined secrets. The module is highly configurable and allows flexible integration into existing systems for enhanced security.

* Validates an X-Fingerprint HTTP header against a preconfigured list of secrets.
* Supports multiple secrets for flexible configuration.
* Configurable behavior for missing, invalid or expired time.

# Table of Content

- [ngx\_http\_auth\_internal\_module](#ngx_http_auth_internal_module)
- [Name](#name)
- [Table of Content](#table-of-content)
- [Status](#status)
- [Synopsis](#synopsis)
- [Installation](#installation)
- [Directives](#directives)
  - [auth\_internal](#auth_internal)
  - [auth\_internal\_request\_secrets](#auth_internal_request_secrets)
  - [auth\_internal\_proxy\_secret](#auth_internal_proxy_secret)
  - [auth\_internal\_empty\_deny](#auth_internal_empty_deny)
  - [auth\_internal\_failure\_deny](#auth_internal_failure_deny)
  - [internal\_request\_auth\_timeout](#internal_request_auth_timeout)
  - [internal\_request\_auth\_header](#internal_request_auth_header)
- [Variables](#variables)
  - [$auth\_internal\_result](#auth_internal_result)
  - [$auth\_internal\_proxy\_fingerprint](#auth_internal_proxy_fingerprint)
- [Author](#author)
- [License](#license)

# Status

This Nginx module is currently considered experimental. Issues and PRs are welcome if you encounter any problems.

# Synopsis

```nginx
http {
    auth_internal on;
    auth_internal_request_secret secret1 secret2;
    auth_internal_timeout 600;
    auth_internal_header X-Fingerprint;
    auth_internal_empty_deny off;
    auth_internal_failure_deny on;
    auth_internal_proxy_secret secret1;

    server {
        listen 80;

        location / {
            proxy_set_header X-Fingerprint $auth_internal_proxy_fingerprint;
            proxy_pass http://upstream_server;
        }
    }
}
```

# Installation

To use theses modules, configure your nginx branch with `--add-module=/path/to/ngx_http_access_control_module`.

# Directives

## auth_internal

**Syntax:** *auth_internal on | off;*

**Default:** *auth_internal off;*

**Context:** *http, server*

Enable or disable the internal authentication.

## auth_internal_request_secrets

**Syntax:** *auth_internal_request_secrets secret1 \[secret2 ...\];*

**Default:** *-;*

**Context:** *http, server*

Specifies one or more secrets used to validate the header. A maximum of three secrets are allowed.

## auth_internal_proxy_secret

**Syntax:** *auth_internal_proxy_secrets secret;*

**Default:** *-;*

**Context:** *http, server*

Specifies the secret used to gerenate a new value of fingerprint validation header. The fingerprint value will be appended to the variable `$auth_internal_proxy_fingerprint`, which can be used to append to upstream request headers to enable auth by upstream server.

For example, with the following configuration
```
server {
    listen 80;
    auth_internal_proxy_secrets test_secret;
    ...

    location / {
        ...
        proxy_set_header X-Fingerprint $auth_internal_proxy_fingerprint;
        proxy_pass http://upstream_server;
    }
}
```

## auth_internal_empty_deny

**Syntax:** *auth_internal_empty_deny on | off;*

**Default:** *auth_internal_empty_deny off;*

**Context:** *http, server*

Determines whether to deny requests missing the header. If set to `on`, missing headers result in a deny status.

## auth_internal_failure_deny

**Syntax:** *auth_internal_failure_deny on | off;*

**Default:** *auth_internal_failure_deny on;*

**Context:** *http, server*

Determines whether to deny requests when fingerprint validation fails. If set to `on, invalid fingerprints result in a deny status.

## internal_request_auth_timeout

**Syntax:** *auth_internal_failure_deny on | off;*

**Default:** *auth_internal_failure_deny on;*

**Context:** *http, server*

Specifies the maximum allowed age of a timestamp (in seconds) in the header. Requests with timestamps exceeding this value are denied. Only valid when `auth_internal_failure_deny` is set to `on`.

## internal_request_auth_header

**Syntax:** *internal_request_auth_header header_name;*

**Default:** *internal_request_auth_header X-Fingerprint;*

**Context:** *http, server*

Specifies the name of the HTTP header used for fingerprint validation.

# Variables

## \$auth_internal_result

Indicates the result of the internal authentication process.

Possible Values:
* off: Authentication is disabled (internal_request_auth is off).
* empty: The fingerprint header is missing.
* failure: Authentication failed due to an invalid timestamp, hash mismatch, or other errors.
* success: Authentication succeeded.

## \$auth_internal_proxy_fingerprint

Generates a new fingerprint based on the current server time and the configured secrets.

Format: <8-character imestamp><32-character MD5 hash>
The first 8 characters are a hexadecimal UNIX timestamp.
The last 32 characters are the MD5 hash of the secret concatenated with the timestamp.

# Author

Hanada im@hanada.info

# License

This Nginx module is licensed under [BSD 2-Clause License](LICENSE).
