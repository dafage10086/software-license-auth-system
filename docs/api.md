# Gateway API

## Common contract

- Base URL: a public HTTPS reverse proxy in front of the loopback Gateway.
- Content type: `application/json`.
- Maximum request body: 32 KiB.
- JSON objects reject unknown fields, trailing data, and malformed input.
- All timestamps are UTC RFC 3339 strings.
- `/api/v2/activate`, `/api/v2/lease`, and `/api/v2/logout` require `Authorization: Bearer <session>`.
- The client cannot provide an upstream path, HTTP method, timeout, or lease TTL.

The examples below list field names rather than usable credentials.

## `POST /api/v2/login`

Request fields:

| Field | Required | Meaning |
|---|---|---|
| `product` | yes | Must equal the configured product code, such as `DEMO-PRODUCT` |
| `username` | yes | 4-32 ASCII letters, digits, dot, underscore, or hyphen; normalized to lowercase |
| `password` | yes | Account password |
| `client_version` | yes | Client integration version |

Success fields: `ok`, `message`, `session_token`, `user_id`, `username`, and `server_time`.

The session token is sensitive and must never be logged or displayed.

## `POST /api/v2/activate`

Request fields:

| Field | Required | Meaning |
|---|---|---|
| `product` | yes | Configured product code |
| `card_key` | no | Paid YEAR or FOREVER key; omitted to resolve/create the trial |
| `device_fingerprint` | yes | Uppercase SHA-256 device fingerprint |
| `components` | yes | Allowed hardware component digest map |
| `client_version` | yes | Client integration version |

Success fields: `ok`, `message`, `user_id`, `license_id`, `machine_id`, `machine_fingerprint`, `plan`, `price`, optional `expires_at`, and `server_time`.

The server verifies owner, product, status, plan, price, expiry, and machine relationships after any mutation. A lost response is not treated as proof of success.

## `POST /api/v2/lease`

Request fields:

| Field | Required | Meaning |
|---|---|---|
| `product` | yes | Configured product code |
| `machine_id` | yes | Exact machine resource returned by activation |
| `device_fingerprint` | yes | Current candidate fingerprint |
| `components` | yes | Current candidate component digests |
| `manifest_sha256` | yes | 64 uppercase hexadecimal characters |
| `challenge` | yes | 32-128 character URL-safe random challenge |
| `client_version` | yes | Client integration version |

Success fields: `ok`, `message`, `machine_file`, `machine_file_expires_at`, `refresh_after_seconds`, `challenge`, `manifest_sha256`, `binding_sha256`, `plan`, optional `business_expires_at`, and `server_time`.

The current contract requires a 3600-second signed machine file and returns a 600-second refresh interval. Replayed challenges are rejected.

## `POST /api/v2/logout`

Request field: `product`.

The Gateway revokes the current Keygen token. The client clears its local DPAPI session in a `finally` path even when the network request fails.

## Errors and rate limits

Errors use a fixed response shape:

| Field | Meaning |
|---|---|
| `ok` | `false` |
| `message` | Sanitized client-facing message |
| `server_time` | Current UTC server time |

The Gateway uses method checks, per-operation rate limits, login failure backoff, challenge replay protection, bounded deadlines, response-size limits, and redirect refusal. It does not return Keygen response bodies or internal errors to the client.

Typical status classes:

- `400`: malformed or invalid request contract.
- `401`: invalid or missing session/account credentials.
- `403`: inactive, expired, wrong-owner, wrong-product, or machine mismatch.
- `404`: required authorization resource not found.
- `405`: method not allowed.
- `409`: conflicting authorization state.
- `429`: rate or login backoff limit.
- `503`: sanitized upstream or timeout failure.
