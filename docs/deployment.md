# Deployment

## Prerequisites

- A supported Docker and Docker Compose installation for Keygen CE.
- Go 1.26 for the Gateway.
- .NET 8 SDK on Windows for the administrator tool, client SDK, and demo.
- A public DNS name and TLS reverse proxy for the Gateway.
- A dedicated restricted SSH account if the Windows administrator tool reaches Keygen through forwarding.

## 1. Keygen CE

Use the template under `deploy/keygen`:

```powershell
Set-Location .\deploy\keygen
Copy-Item .env.example .env
powershell -NoProfile -ExecutionPolicy Bypass -File .\test-compose.ps1
docker compose --profile setup run --rm setup
docker compose up -d
```

Replace every placeholder with an independent value before starting. The template publishes only `127.0.0.1:18788`; PostgreSQL, Redis, and ClickHouse have no host port.

Create the product and three policies in Keygen with these application contracts:

| Plan | Duration | Price metadata | Machines | Users |
|---|---:|---:|---:|---:|
| TRIAL | 2,592,000 seconds | 0 | 1 | 1 |
| YEAR | 31,536,000 seconds | 128 | 1 | 1 |
| FOREVER | no business expiry | 288 | 1 | 1 |

All plans use first activation as the expiry basis, restrict access after expiry, and require the server-side machine relationship. Keep the Keygen IDs for the next steps; do not commit them when they identify a live deployment.

## 2. Gateway

Required environment:

```text
LICENSE_AUTH_ADDR=127.0.0.1:8787
LICENSE_AUTH_PRODUCT_CODE=DEMO-PRODUCT
LICENSE_AUTH_KEYGEN_BASE_URL=http://127.0.0.1:18788
LICENSE_AUTH_KEYGEN_ACCOUNT_ID=YOUR_KEYGEN_ACCOUNT_ID
LICENSE_AUTH_KEYGEN_PRODUCT_ID=YOUR_KEYGEN_PRODUCT_ID
LICENSE_AUTH_KEYGEN_PUBLIC_KEY=YOUR_KEYGEN_PUBLIC_KEY
```

Build and test:

```powershell
Push-Location .\gateway
go test ./...
go vet ./...
go build .
Pop-Location
```

The Gateway refuses a non-loopback listener and a non-loopback Keygen base URL. Publish only the TLS reverse proxy. Forward exactly the four `/api/v2` routes and the health route; do not publish Keygen directly.

## 3. Administrator tool

Build:

```powershell
dotnet build .\admin\src\SoftwareLicenseAuth.Admin.csproj -c Release --nologo
```

Copy `admin-config.json.example` to `admin-config.json` beside the executable and replace the Keygen IDs. The public source contains the non-routable placeholders `license.example.com`, `license-auth-tunnel`, and `keygen.license.invalid`. Before a private deployment, replace and test the fixed tunnel host, restricted username, and pinned Keygen authority for that deployment.

The expected local tunnel directory is under `%LOCALAPPDATA%\SoftwareLicenseAuth\Admin`. Protect the tunnel configuration, private key, and known-hosts file for the current user and LocalSystem only. The administrator token is stored separately with CurrentUser DPAPI and is never printed.

## 4. Client integration

Reference `client-sdk/src/SoftwareLicenseAuth.Client.csproj` or package the library using your own release process. Place `auth-config.json` beside the application with:

- public HTTPS Gateway base URL;
- Keygen machine-file public key;
- Keygen account ID;
- Keygen product ID.

Construct `LicenseAuthClient` with the uppercase SHA-256 of the application manifest used by your release process. Call `LoginAsync`, `ActivateAsync`, `RefreshAsync`, and `LogoutAsync`; do not persist returned authorization objects yourself.

## Rollout

1. Back up Keygen database and named volumes.
2. Deploy Keygen and verify internal health.
3. Deploy the Gateway on loopback and verify through public TLS.
4. Create one test account, trial, paid license, and machine; verify login, activation, lease refresh, logout, and machine revocation.
5. Deploy the administrator tool to operator machines.
6. Release the client only after the clean-room test and public-release gate pass.

## Rollback

- Keep the prior Keygen image, Compose file, Gateway binary, administrator build, client build, and matching database/volume backup as one rollback set.
- Roll back schema and image versions together; never attach an older application to an incompatible upgraded database.
- Restore DNS or reverse-proxy routing only after the previous Gateway and Keygen health checks pass.
- Do not delete volumes as a rollback shortcut.

## Incident response

If a token, password, private key, or live configuration is exposed:

1. Remove public access and preserve logs without copying secrets into issues.
2. Revoke the affected Keygen token or account session.
3. Rotate the credential at its source and update dependent services.
4. Review machine, license, and administrator audit activity.
5. Rebuild affected release artifacts if a signing or machine-file key was exposed.
6. Run the full test suite and `scripts/verify-public-release.ps1` before restoring service.
