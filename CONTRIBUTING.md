# Contributing

## Scope

Contributions should improve the generic authorization Gateway, Windows administrator, client SDK, demo, deployment template, tests, or documentation. Do not add product-specific runners, private release tooling, customer assets, or hosted-service features that conflict with Keygen CE licensing.

## Development requirements

- Go 1.26
- .NET 8 SDK on Windows
- PowerShell 5.1+
- Docker Compose for Compose-model validation

## Required checks

```powershell
Push-Location .\gateway
go test ./... -count=1
go vet ./...
Pop-Location

dotnet test .\admin\tests\SoftwareLicenseAuth.Admin.Tests.csproj -c Release --nologo
dotnet test .\client-sdk\tests\SoftwareLicenseAuth.Client.Tests.csproj -c Release --nologo
dotnet build .\examples\windows-demo\SoftwareLicenseAuth.Demo.csproj -c Release --nologo

powershell -NoProfile -ExecutionPolicy Bypass -File .\deploy\keygen\test-compose.ps1
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\test-docs.ps1
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\test-public-release.ps1
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\verify-public-release.ps1
```

## Pull requests

- Keep changes narrowly scoped.
- Add a failing test before behavior changes and show the test passing afterward.
- Keep `README.md` and `README_EN.md` synchronized.
- Document configuration, API, deployment, or security changes under `docs/`.
- Do not commit generated `bin`, `obj`, publish, archive, database, or binary output.
- Do not place real credentials, endpoints, customer data, or production identifiers in code, tests, issues, or commit messages.

By submitting a contribution, you agree that it may be distributed under the repository's `AGPL-3.0-only` license. Third-party code must retain its original license and notice.
