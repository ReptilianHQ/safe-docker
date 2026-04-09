package main

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/docker/docker/client"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
)

type Server struct {
	cfg         Config
	docker      *client.Client
	compose     *ComposeClient
	log         *slog.Logger
	approvalsMu sync.Mutex
	approvals   map[string]*pendingApproval
}

type auditEntry struct {
	Timestamp string `json:"timestamp"`
	Caller    string `json:"caller"`
	Action    string `json:"action"`
	Service   string `json:"service,omitempty"`
	Container string `json:"container,omitempty"`
	Result    string `json:"result"`
	Reason    string `json:"reason,omitempty"`
	RequestID string `json:"request_id,omitempty"`
	Remote    string `json:"remote_addr,omitempty"`
}

func buildLogger(cfg LoggingConfig) *slog.Logger {
	var level slog.Level
	switch strings.ToLower(cfg.Level) {
	case "debug":
		level = slog.LevelDebug
	case "warn":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	default:
		level = slog.LevelInfo
	}
	opts := &slog.HandlerOptions{Level: level}
	if strings.ToLower(cfg.Format) == "text" {
		return slog.New(slog.NewTextHandler(os.Stdout, opts))
	}
	return slog.New(slog.NewJSONHandler(os.Stdout, opts))
}

func newServer(cfg Config, log *slog.Logger) (*Server, error) {
	dockerClient, err := client.NewClientWithOpts(
		client.WithHost("unix://"+cfg.Docker.SocketPath),
		client.WithAPIVersionNegotiation(),
	)
	if err != nil {
		return nil, fmt.Errorf("create docker client: %w", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	info, err := dockerClient.Info(ctx)
	if err != nil {
		return nil, fmt.Errorf("docker socket not reachable at %q: %w", cfg.Docker.SocketPath, err)
	}
	log.Info("docker connected", "server_version", info.ServerVersion, "containers", info.Containers)

	// Initialize Compose SDK client for build/up/down/recreate operations
	composeClient, err := NewComposeClient(cfg.Docker.SocketPath)
	if err != nil {
		return nil, fmt.Errorf("create compose client: %w", err)
	}
	log.Info("compose SDK initialized")

	srv := &Server{
		cfg:       cfg,
		docker:    dockerClient,
		compose:   composeClient,
		log:       log,
		approvals: make(map[string]*pendingApproval),
	}

	// Background sweeper: remove expired tokens every 60 seconds.
	go srv.sweepExpiredApprovals()

	return srv, nil
}

func (s *Server) router() http.Handler {
	r := chi.NewRouter()
	r.Use(middleware.RequestID)
	r.Use(middleware.RealIP)
	r.Use(s.structuredLogger())
	r.Use(middleware.Recoverer)

	r.Get("/health", s.healthHandler)
	r.Group(func(r chi.Router) {
		r.Use(s.requireAPIKey)
		r.Get("/v1/projects", s.listProjectsHandler)
		r.Get("/v1/projects/{project}/services", s.listServicesHandler)
		r.Get("/v1/projects/{project}/services/{service}/status", s.statusHandler)
		r.Get("/v1/projects/{project}/services/{service}/logs", s.logsHandler)
		r.Post("/v1/projects/{project}/services/{service}/restart", s.restartHandler)
		r.Post("/v1/projects/{project}/services/{service}/start", s.startHandler)
		r.Post("/v1/projects/{project}/services/{service}/stop", s.stopHandler)
		r.Post("/v1/projects/{project}/services/{service}/up", s.upHandler)
		r.Post("/v1/projects/{project}/services/{service}/down", s.downHandler)
		r.Post("/v1/projects/{project}/services/{service}/recreate", s.recreateHandler)
		r.Post("/v1/projects/{project}/services/{service}/build", s.buildHandler)
		r.Post("/v1/approve", s.approveHandler)
	})
	return r
}

// ---------------------------------------------------------------------------
// Middleware
// ---------------------------------------------------------------------------

func (s *Server) structuredLogger() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ww := middleware.NewWrapResponseWriter(w, r.ProtoMajor)
			start := time.Now()
			defer func() {
				s.log.Info("http request",
					"method", r.Method,
					"path", r.URL.Path,
					"status", ww.Status(),
					"bytes", ww.BytesWritten(),
					"duration_ms", time.Since(start).Milliseconds(),
					"request_id", middleware.GetReqID(r.Context()),
					"remote_addr", r.RemoteAddr,
				)
			}()
			next.ServeHTTP(ww, r)
		})
	}
}

func (s *Server) requireAPIKey(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		key := r.Header.Get("X-API-Key")
		meta, ok := s.cfg.Auth.Keys[key]
		if strings.TrimSpace(key) == "" {
			writeError(w, http.StatusUnauthorized, "X-API-Key header required")
			return
		}
		if !ok {
			writeError(w, http.StatusForbidden, "invalid API key")
			return
		}
		ctx := context.WithValue(r.Context(), callerContextKey{}, meta.Label)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

type callerContextKey struct{}

func callerFromContext(ctx context.Context) string {
	caller, _ := ctx.Value(callerContextKey{}).(string)
	if caller == "" {
		return "unknown"
	}
	return caller
}
