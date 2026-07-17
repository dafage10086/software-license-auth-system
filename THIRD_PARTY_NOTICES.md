# Third-party notices

This repository contains original integration code and references independent third-party components. Each component remains subject to its own license.

## Keygen CE

- Component: Keygen CE API
- Referenced version: `keygen/api:v1.7.0`
- License: FCL-1.0-ALv2 for the referenced release
- Source: <https://github.com/keygen-sh/keygen-api>
- Included text: [`deploy/keygen/LICENSE_KEYGEN_FCL.md`](deploy/keygen/LICENSE_KEYGEN_FCL.md)

The repository references the official container image and does not redistribute Keygen CE source. The FCL terms, including the competing-use restriction and future-license clause, apply independently from this repository's AGPL license.

## .NET client dependencies

- `NSec.Cryptography` 22.4.0, MIT License: <https://github.com/ektrah/nsec>
- `System.Management` 8.0.0, .NET runtime license: <https://github.com/dotnet/runtime>
- `System.Security.Cryptography.ProtectedData` 8.0.0, .NET runtime license: <https://github.com/dotnet/runtime>
- libsodium, ISC License: <https://github.com/jedisct1/libsodium>

The complete notices distributed with the client library are in [`client-sdk/src/THIRD_PARTY_NOTICES.txt`](client-sdk/src/THIRD_PARTY_NOTICES.txt).

## Test dependencies

- xUnit.net 2.9.2, Apache-2.0: <https://github.com/xunit/xunit>
- Microsoft.NET.Test.Sdk 17.11.1, MIT: <https://github.com/microsoft/vstest>

## Deployment images

The Compose template references PostgreSQL, Redis, and ClickHouse container images. Review the license and distribution terms published by each upstream project before production use:

- PostgreSQL: <https://www.postgresql.org/about/licence/>
- Redis: <https://redis.io/legal/licenses/>
- ClickHouse: <https://github.com/ClickHouse/ClickHouse>

No third-party trademark rights are granted by this repository.
