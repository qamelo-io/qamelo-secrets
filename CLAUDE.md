# Qamelo Secrets

Secret broker service for the Qamelo integration platform. Sole Vault client — no other service talks to Vault directly.

Platform docs: https://github.com/qamelo-io/qamelo-docs
Design decisions: https://github.com/qamelo-io/qamelo-docs/blob/main/SECRETS-DESIGN.md

## Tech Stack

- Java 25, Quarkus 3.33.1 LTS
- Vert.x WebClient (raw HTTP to Vault)
- SmallRye Health
- Testcontainers (Vault dev server)

## Modules

| Module | Purpose |
|---|---|
| qamelo-secrets-domain | DTOs, error model, SPI interfaces. Zero Vault imports. |
| qamelo-secrets-infra | Vault client implementation (Vert.x WebClient), response mapping |
| qamelo-secrets-app | REST resources, SharedSecretAuthFilter, health check, audit, Quarkus wiring |

## Architecture

- Hexagonal: domain defines interfaces, infra implements with Vault
- Stateless broker: no database, no cache, no lease tracking
- Engine-per-resource REST API at `/api/v1/internal/secrets/*`
- SharedSecretAuthFilter on all `/api/v1/internal/*` endpoints

## SPI Interfaces (domain module)

- SecretStore — KV v2 (credentials with versioning)
- CertificateStore — PKI (certificate lifecycle)
- TransitEngine — Transit (encrypt/decrypt without key export)
- SshEngine — SSH (signed certificates, OTP)
- DatabaseCredentialStore — Database (dynamic JDBC credentials)

## Error Model

7 codes: SECRET_NOT_FOUND (404), ACCESS_DENIED (403), VAULT_UNAVAILABLE (503), LEASE_EXPIRED (410), INVALID_REQUEST (400), RATE_LIMITED (429), UPSTREAM_ERROR (502)

## Build

```bash
mvn clean install
```

## Related Repos

- **qamelo-docs** — cross-repo architecture, SECRETS-DESIGN.md, PRD
- **qamelo-server** — consumes vault path refs at deploy time
- **qamelo-iam** — SharedSecretAuthFilter pattern origin
- **qamelo-infra** — Vault deployment, engine setup, K8s auth

## Version

0.1.0-SNAPSHOT
