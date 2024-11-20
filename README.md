# ngx_http_internal_auth_module

# Name

This Nginx module provides internal request authentication by validating a custom HTTP header (default is X-Fingerprint) against a set of predefined secrets. The module is highly configurable and allows flexible integration into existing systems for enhanced security.

* Validates an X-Fingerprint HTTP header against a preconfigured list of secrets.
* Supports multiple secrets for flexible configuration.
* Configurable behavior for missing, invalid or expired time.

# Table of Content

* [Name](#name)
* [Status](#status)
* [Synopsis](#synopsis)
* [Installation](#installation)
* [Directives](#directives)
  * [internal_auth](#internal_auth)
  * [internal_auth_request_secrets](#internal_auth_request_secrets)
  * [internal_auth_proxy_secret](#internal_auth_proxy_secret)
  * [internal_auth_empty_deny](#internal_auth_empty_deny)
  * [internal_auth_failure_deny](#internal_auth_failure_deny)
  * [internal_request_auth_header](#internal_request_auth_header)
* [Variables](#variables)
  * [$internal_auth_proxy_fingerprint](#\$internal_auth_proxy_fingerprint)
  * [$internal_auth_proxy_fingerprint](#\$internal_auth_proxy_fingerprint)
* [Author](#author)
* [License](#license)

# Status

This Nginx module is currently considered experimental. Issues and PRs are welcome if you encounter any problems.

# Synopsis

```nginx
http {
    internal_auth on;
    internal_auth_request_secret secret1 secret2;
    internal_auth_timeout 600;
    internal_auth_header X-Fingerprint;
    internal_auth_empty_deny off;
    internal_auth_failure_deny on;
    internal_auth_proxy_secret secret1;

    server {
        listen 80;

        location / {
            proxy_set_header X-Fingerprint $internal_auth_proxy_fingerprint;
            proxy_pass http://upstream_server;
        }
    }
}
```

# Installation

To use theses modules, configure your nginx branch with `--add-module=/path/to/ngx_http_access_control_module`.

# Directives

## internal_auth

**Syntax:** *internal_auth on | off;*

**Default:** *internal_auth off;*

**Context:** *http, server*

Enable or disable the internal authentication module.

## internal_auth_request_secrets

**Syntax:** *internal_auth_request_secrets secret1 \[secret2 ...\];*

**Default:** *-;*

**Context:** *http, server*

Specifies one or more secrets used to validate the header. A maximum of three secrets are allowed.

## internal_auth_proxy_secret

**Syntax:** *internal_auth_proxy_secrets secret;*

**Default:** *-;*

**Context:** *http, server*

Specifies the secret used to gerenate a new value of fingerprint validation header. The fingerprint value will be appended to the variable `$internal_auth_proxy_fingerprint`, which can be used to append to upstream request headers to enable auth by upstream server.

For example, with the following configuration
```
server {
    listen 80;
    internal_auth_proxy_secrets test_secret;
    ...

    location / {
        ...
        proxy_set_header X-Fingerprint $internal_auth_proxy_fingerprint;
        proxy_pass http://upstream_server;
    }
}
```

## internal_auth_empty_deny

**Syntax:** *internal_auth_empty_deny on | off;*

**Default:** *internal_auth_empty_deny off;*

**Context:** *http, server*

Determines whether to deny requests missing the header. If set to `on`, missing headers result in a deny status.

## internal_auth_failure_deny

**Syntax:** *internal_auth_failure_deny on | off;*

**Default:** *internal_auth_failure_deny on;*

**Context:** *http, server*

Determines whether to deny requests when fingerprint validation fails. If set to `on, invalid fingerprints result in a deny status.

## internal_request_auth_timeout

**Syntax:** *internal_auth_failure_deny on | off;*

**Default:** *internal_auth_failure_deny on;*

**Context:** *http, server*

Specifies the maximum allowed age of a timestamp (in seconds) in the header. Requests with timestamps exceeding this value are denied. Only valid when `internal_auth_failure_deny` is set to `on`.

## internal_request_auth_header

**Syntax:** *internal_request_auth_header header_name;*

**Default:** *internal_request_auth_header X-Fingerprint;*

**Context:** *http, server*

Specifies the name of the HTTP header used for fingerprint validation.

# Variables

## \$internal_auth_result

Indicates the result of the internal authentication process.

Possible Values:
* off: Authentication is disabled (internal_request_auth is off).
* empty: The fingerprint header is missing.
* failure: Authentication failed due to an invalid timestamp, hash mismatch, or other errors.
* success: Authentication succeeded.

## \$internal_auth_proxy_fingerprint

Generates a new fingerprint based on the current server time and the configured secrets.

Format: <8-character imestamp><32-character MD5 hash>
The first 8 characters are a hexadecimal UNIX timestamp.
The last 32 characters are the MD5 hash of the secret concatenated with the timestamp.

# Author

Hanada im@hanada.info

# License

This Nginx module is licensed under [BSD 2-Clause License](LICENSE).
