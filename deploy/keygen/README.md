# Keygen CE deployment template

This template references the official `keygen/api:v1.7.0` image. It does not redistribute Keygen source code or production data.

## Network boundary

- Only the Keygen web service is published, at `127.0.0.1:18788`.
- PostgreSQL, Redis, and ClickHouse stay on the internal Compose network.
- Put a TLS reverse proxy or the repository gateway in front of Keygen. Do not expose port `18788` directly to the Internet.

## Configure

```powershell
Copy-Item .env.example .env
```

Replace every `CHANGE_ME` and `EXAMPLE_` value. Generate independent values for each cryptographic field; do not reuse database or administrator passwords. Keep `.env` outside source control.

## Initialize and start

```powershell
docker compose --profile setup run --rm setup
docker compose up -d
docker compose ps
```

Run migrations for an existing deployment with:

```powershell
docker compose --profile migrate run --rm migrate
```

Before upgrades, back up the named volumes and pin the replacement image version. To roll back, restore the previous Compose file, image version, and matching volume backup together.

## Verify the public template

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\test-compose.ps1
```

## License boundary

Keygen CE is a separate dependency under FCL-1.0-ALv2. Review [LICENSE_KEYGEN_FCL.md](LICENSE_KEYGEN_FCL.md) before deployment. In particular, do not use the covered version to offer a competing hosted licensing service while the FCL restriction applies.
