# safe-docker

A small policy-enforced HTTP proxy for Docker Compose operations.

Safe by default. Human-readable policy. Built for agents, operators, and internal automation.

## What it is

`safe-docker` exposes a **small, explicit subset** of Docker operations over HTTP:

- health, status, logs (read-only)
- restart, start, stop (container lifecycle)
- up, down (compose service management)
- recreate, build (dangerous — require explicit opt-in + HITL approval)

It does **not** expose the full Docker API.
It is a policy firewall in front of Docker, not a Docker replacement.

**No CLI shelling.** All compose operations go through the [Docker Compose SDK](https://docs.docker.com/compose/compose-sdk/) — no `docker` binary required in the container.

## Why

Mounting `/var/run/docker.sock` into random apps or agents is ambient authority.
One bug or prompt injection becomes host-level container control.

`safe-docker` reduces blast radius by forcing every operation through:

- signed caller-token auth
- project-scoped service aliases
- per-service, per-action policy
- deny-by-default behavior
- audit logging

## API

### Public
- `GET /health`

### Protected
- `GET /v1/projects`
- `GET /v1/projects/{project}/services`
- `GET /v1/projects/{project}/services/{service}/status`
- `GET /v1/projects/{project}/services/{service}/logs?tail=100`
- `POST /v1/projects/{project}/services/{service}/restart`
- `POST /v1/projects/{project}/services/{service}/start`
- `POST /v1/projects/{project}/services/{service}/stop`
- `POST /v1/projects/{project}/services/{service}/up`
- `POST /v1/projects/{project}/services/{service}/down`
- `POST /v1/projects/{project}/services/{service}/recreate` ⚠️
- `POST /v1/projects/{project}/services/{service}/build` ⚠️

⚠️ = Dangerous actions. Require `dangerous: true` in service policy.

Auth header:

```text
X-API-Key: <signed-caller-token>
```

## Example policy

See `policy.example.yaml`.

Core shape:

```yaml
auth:
  authorized_callers:
    - openclaw-agent
  token_secret_env: SAFE_DOCKER_AUTH_SECRET

projects:
  myproject:  # Docker Compose project name
    services:
      api:
        actions: [status, logs, restart, up, down]

      postgres:
        actions: [status, logs]  # No restart — data safety

      worker:
        actions: [status, logs, restart, recreate]
        dangerous: true  # Required for recreate
```

Container resolution:
1. If `container` is set on a service → use exact container name
2. Otherwise → lookup by compose labels (`com.docker.compose.project` + `com.docker.compose.service`)

## Threat model

This tool is safer than exposing the Docker socket directly, but it is still a privileged bridge to Docker.

Security goal:
- if an API key leaks, the attacker gets only the actions and services explicitly allowed in policy
- not arbitrary Docker access

Non-goals:
- arbitrary exec into containers
- image pull/push (build is allowed with `dangerous: true`)
- network or volume management
- general Docker administration
- multi-tenant isolation boundary replacement

## Security properties

- deny by default
- strict YAML parsing
- startup fails on malformed policy
- startup verifies Docker connectivity
- per-project, per-service, per-action authorization
- structured audit logging for protected requests
- bounded log tail requests

## Quick start

1. Copy the example policy:

```bash
cp policy.example.yaml policy.yaml
```

2. Set `SAFE_DOCKER_AUTH_SECRET`, then edit authorized callers, projects, and services.

3. Run it:

```bash
go run . -config policy.yaml
```

4. Query health:

```bash
curl http://127.0.0.1:8080/health
```

5. Mint a caller token locally:

```bash
safe-docker auth mint --caller openclaw-agent
safe-docker auth mint --caller openclaw-agent --ttl 1h --json
```

6. Restart an allowed service:

```bash
curl -X POST \
  -H 'X-API-Key: <signed-caller-token>' \
  http://127.0.0.1:8080/v1/projects/myproject/services/api/restart
```

Token format:
- payload: compact JSON claims including `caller`, `exp`, and `v`
- signature: `HMAC-SHA256(secret, canonical_payload)`
- header value: `<base64url(payload)>.<hex(signature)>`

Example payload:
```json
{"caller":"komodo","aud":"safe-docker","iat":1775768400,"exp":1775772000,"v":1}
```

## Docker Compose

See `docker-compose.example.yaml`.

**Required for build/recreate:** Mount the project root read-only at `/project`:

```yaml
safe-docker:
  image: ghcr.io/reptilianhq/safe-docker:latest
  volumes:
    - /var/run/docker.sock:/var/run/docker.sock
    - ./:/project:ro  # Project root for builds
    - ./control/policy.yaml:/app/policy.yaml:ro
```

The SDK reads the compose file and build contexts from `/project`. Without this mount, build and recreate operations will fail.

Recommended deployment posture:
- bind only to localhost or a trusted internal network
- put behind an authenticated reverse proxy if exposed beyond local host
- keep policy file read-only
- mount project root read-only (`:ro`) — safe-docker only needs to read, not write
- do not share API keys between unrelated callers

## OpenAPI

A full OpenAPI 3.0 spec is available at [`openapi.yaml`](./openapi.yaml).

## Contributing

See [`CONTRIBUTING.md`](./CONTRIBUTING.md).
