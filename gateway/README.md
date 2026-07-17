# Authorization Gateway

This Go service exposes four fixed operations in front of an official Keygen CE deployment:

- `POST /api/v2/login`
- `POST /api/v2/activate`
- `POST /api/v2/lease`
- `POST /api/v2/logout`

It binds to loopback only, applies bounded HTTP timeouts and rate limits, rejects unknown JSON fields, and never accepts an arbitrary upstream path or method from a client.

## Required environment

```text
LICENSE_AUTH_ADDR=127.0.0.1:8787
LICENSE_AUTH_PRODUCT_CODE=DEMO-PRODUCT
LICENSE_AUTH_KEYGEN_BASE_URL=http://127.0.0.1:18788
LICENSE_AUTH_KEYGEN_ACCOUNT_ID=CHANGE_ME
LICENSE_AUTH_KEYGEN_PRODUCT_ID=CHANGE_ME
LICENSE_AUTH_KEYGEN_PUBLIC_KEY=CHANGE_ME
```

Use a reverse proxy for public HTTPS. Do not expose the Keygen CE port or this loopback listener directly.

## Test

```powershell
go test ./...
```
