# Security model

## Assets

- Account passwords and short user sessions.
- License keys, policy state, expiry, and price metadata.
- Machine relationships, hardware components, and device public keys.
- Keygen administrator tokens and SSH tunnel material.
- Machine-file signing keys and client verification public keys.
- Production configuration, databases, backups, and customer packages.

## Trust boundaries

The Windows client is attacker-controlled. It must never be the authority for plan, price, expiry, machine ownership, or lease duration. Keygen and the Gateway form the server authority. The administrator tool is more privileged than a client and must run only for approved operators.

## Server controls

- Gateway and Keygen listeners are loopback-only in the public templates.
- Public traffic terminates at a TLS reverse proxy.
- The Gateway exposes four fixed operations and rejects arbitrary upstream routing.
- Strict JSON, size limits, fixed HTTP methods, bounded deadlines, no redirects, and sanitized upstream errors reduce injection and data leakage.
- Per-operation limits, login backoff, and one-time challenges reduce brute force and replay.
- License state is re-read after mutations before success is returned.
- User, license, product, and machine ownership are checked together.

## Client controls

- Username normalization is identical in the administrator, Gateway, and SDK.
- Hardware binding combines multiple physical sources with a CNG device key.
- Session data is protected with CurrentUser DPAPI and atomically replaced.
- Machine files are strict UTF-8, canonical base64, and Ed25519 verified.
- Signed claims, server time, persisted last server time, expiry, manifest hash, and challenge binding are checked before session persistence.
- Errors and `ToString()` methods redact passwords, tokens, card keys, and machine files.

## Administrator controls

- Configuration accepts only the fixed local Keygen authority.
- The SSH command uses a fixed forwarding shape, pinned known hosts, hidden process launch, and no interactive shell.
- Tunnel files and DPAPI token storage reject unsafe paths, reparse points, and untrusted ownership.
- Administrator operations use bounded deadlines and post-mutation recovery checks.

## Secret handling

Never commit or attach:

- `.env`, `admin-config.json`, or `auth-config.json` from a live deployment;
- private keys, certificates, DPAPI blobs, cookies, sessions, or administrator tokens;
- databases, volume archives, server backups, binaries, customer packages, or logs with credentials.

Use obvious placeholders in public examples. Run `scripts/verify-public-release.ps1` before every push and after a fresh clone.

## Limitations

Hardware fingerprinting and local anti-tamper controls raise effort but do not make a Windows client unbreakable. A determined attacker can patch client code, emulate hardware responses, or inspect process memory. The design therefore keeps business authority on the server and uses short signed leases to limit offline reuse.

This public edition intentionally excludes the production integrity-signing chain and product-specific runner. Integrators remain responsible for secure release signing, update delivery, monitoring, backups, TLS configuration, host hardening, and legal compliance.

## Reporting

Follow [SECURITY.md](../SECURITY.md). Do not publish active credentials, customer data, or a working exploit in a public issue.
