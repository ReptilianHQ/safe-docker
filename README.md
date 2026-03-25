# safe-docker

A small policy-enforced HTTP proxy for Docker Compose operations.

Safe by default. Human-readable policy. Built for agents, operators, and internal automation.

## What it is

`safe-docker` exposes a **small, explicit subset** of Docker operations over HTTP:

- health, status, logs (read-only)
- restart, start, stop (container lifecycle)
- up, down (compose service management)
- recreate, build (dangerous — require explicit opt-in)

It does **not** expose the full Docker API.
It is a policy firewall in front of Docker, not a Docker replacement.

## Why

Mounting `/var/run/docker.sock` into random apps or agents is ambient authority.
One bug or prompt injection becomes host-level container control.

`safe-docker` reduces blast radius by forcing every operation through:

- API-key auth
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
X-API-Key: <your-key>
```

## Example policy

See `policy.example.yaml`.

Core shape:

```yaml
auth:
  keys:
    sk_live_agent_abc123:
      label: openclaw-agent

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

2. Edit API keys, projects, and services.

3. Run it:

```bash
go run . -config policy.yaml
```

4. Query health:

```bash
curl http://127.0.0.1:8080/health
```

5. Restart an allowed service:

```bash
curl -X POST \
  -H 'X-API-Key: sk_live_agent_abc123' \
  http://127.0.0.1:8080/v1/projects/myproject/services/api/restart
```

## Docker Compose

See `docker-compose.example.yaml`.

Recommended deployment posture:
- bind only to localhost or a trusted internal network
- put behind an authenticated reverse proxy if exposed beyond local host
- keep policy file read-only
- do not share API keys between unrelated callers

## OpenAPI

A full OpenAPI 3.0 spec is available at [`openapi.yaml`](./openapi.yaml).

## Contributing

See [`CONTRIBUTING.md`](./CONTRIBUTING.md).
