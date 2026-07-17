# Security policy

## Supported version

Security fixes are applied to the current `main` branch. Older snapshots and private forks are not maintained by this repository.

## Reporting a vulnerability

Use GitHub's private security advisory workflow when available. For coordination about a private report, contact QQ group `924211252` and state that the message concerns a security issue.

Include:

- affected commit;
- affected component;
- minimal reproduction using fake data;
- impact and required preconditions;
- suggested mitigation, if known.

Do not include real passwords, tokens, private keys, customer data, production hostnames, or live sessions. Do not open a public issue for an unpatched vulnerability.

## Response

The project will validate the report, identify affected versions, prepare a regression test and minimal fix, and publish remediation details after a safe update is available. No response-time guarantee is offered.

## Boundaries

Reports about Keygen CE itself, .NET, Go, PostgreSQL, Redis, ClickHouse, or other independent dependencies should also be sent to the relevant upstream security channel. This repository cannot grant rights or fixes on behalf of those projects.
