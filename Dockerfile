FROM golang:1.25-alpine AS build
WORKDIR /src

RUN apk add --no-cache ca-certificates git

# Copy dependency files first for better caching
COPY go.mod go.sum ./
RUN go mod download

# Copy source and build
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o /out/safe-docker .

FROM alpine:3.23
LABEL org.opencontainers.image.title="safe-docker" \
      org.opencontainers.image.description="Policy-enforced HTTP proxy for Docker Compose operations" \
      org.opencontainers.image.licenses="MIT"

ARG DOCKER_COMPOSE_VERSION=2.39.4
ARG TARGETARCH
RUN apk add --no-cache ca-certificates wget docker-cli docker-cli-buildx \
 && case "${TARGETARCH}" in \
      amd64) compose_arch=x86_64 ;; \
      arm64) compose_arch=aarch64 ;; \
      *) echo "unsupported TARGETARCH: ${TARGETARCH}" >&2; exit 1 ;; \
    esac \
 && mkdir -p /usr/local/lib/docker/cli-plugins \
 && wget -O /usr/local/lib/docker/cli-plugins/docker-compose "https://github.com/docker/compose/releases/download/v${DOCKER_COMPOSE_VERSION}/docker-compose-linux-${compose_arch}" \
 && chmod +x /usr/local/lib/docker/cli-plugins/docker-compose \
 && addgroup -S app \
 && adduser -S -G app app \
 && mkdir -p /app \
 && chown -R app:app /app

WORKDIR /app
COPY --from=build /out/safe-docker /app/safe-docker

EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
  CMD wget -qO- http://127.0.0.1:8080/health >/dev/null || exit 1

USER app
ENTRYPOINT ["/app/safe-docker"]
CMD ["-config", "/app/policy.yaml"]
