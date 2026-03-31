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

RUN apk add --no-cache ca-certificates wget docker-cli-buildx \
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
