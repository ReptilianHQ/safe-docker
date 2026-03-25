# Contributing to safe-docker

Thanks for your interest. This is a small, focused tool — contributions should keep it that way.

## Principles

- **Narrow surface** — safe-docker is a policy firewall, not a Docker management platform. New endpoints need a strong justification.
- **Fail closed** — any ambiguity in auth or policy should result in denial, not access.
- **No new dependencies** without good reason. The current dependency set is intentionally minimal.

## Development

**Prerequisites:** Go 1.21+

```bash
# Build
go build ./...

# Test
go test -v -race ./...

# Run locally (needs Docker + a policy file)
cp policy.example.yaml policy.yaml
# Edit policy.yaml — set your API key and services
go run . -config policy.yaml
```

## Testing

All tests run without Docker. The test suite uses `httptest` and a stub server so Docker is never required in CI.

Tests live in `main_test.go`. Please add tests for any new behavior.

## Pull requests

- Keep changes small and focused
- Include tests
- Update `openapi.yaml` if you add or change endpoints
- Update `README.md` if behavior changes

## What we won't accept

- General Docker management features (image build/pull, network/volume ops)
- Multi-tenant isolation (this tool is for trusted internal networks)
- External dependencies beyond what's in `go.mod`
- Arbitrary exec into containers
