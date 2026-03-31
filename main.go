package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"regexp"
	"slices"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/client"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"gopkg.in/yaml.v3"
)

var validServiceName = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]*$`)

var validActions = map[string]struct{}{
	"status":   {},
	"logs":     {},
	"restart":  {},
	"start":    {},
	"stop":     {},
	"up":       {},
	"down":     {},
	"recreate": {},
	"build":    {},
}

// dangerousActions require explicit opt-in via `dangerous: true` in policy
var dangerousActions = map[string]struct{}{
	"recreate": {},
	"build":    {},
}

type Config struct {
	Server   ServerConfig             `yaml:"server"`
	Docker   DockerConfig             `yaml:"docker"`
	Auth     AuthConfig               `yaml:"auth"`
	Projects map[string]ProjectConfig `yaml:"projects"`
	Logging  LoggingConfig            `yaml:"logging"`
	Approval ApprovalConfig           `yaml:"approval"`
}

type ProjectConfig struct {
	Services map[string]ServicePolicy `yaml:"services"`
}

type ServerConfig struct {
	ListenAddr string `yaml:"listen_addr"`
}

type DockerConfig struct {
	SocketPath     string `yaml:"socket_path"`
	TimeoutSeconds int    `yaml:"timeout_seconds"`
	LogTailDefault int    `yaml:"log_tail_default"`
	LogTailMax     int    `yaml:"log_tail_max"`
}

type AuthConfig struct {
	Keys map[string]APIKeyConfig `yaml:"keys"`
}

type APIKeyConfig struct {
	Label string `yaml:"label"`
}

type ServicePolicy struct {
	Container string   `yaml:"container,omitempty"` // Optional: container name for Docker SDK actions (status/logs/restart/start/stop). If omitted, service key is used.
	Actions   []string `yaml:"actions"`
	Dangerous bool     `yaml:"dangerous"` // Required for recreate/build actions
}

type LoggingConfig struct {
	Level  string `yaml:"level"`
	Format string `yaml:"format"`
}

// ApprovalConfig controls the human-in-the-loop webhook for dangerous actions.
type ApprovalConfig struct {
	WebhookURL      string `yaml:"webhook_url"`
	TokenTTLSecs    int    `yaml:"token_ttl_seconds"`
	TokenTTLMaxSecs int    `yaml:"token_ttl_max_seconds"`
}

// pendingApproval holds state for a dangerous action awaiting human sign-off.
type pendingApproval struct {
	Action      string
	Project     string
	Service     string
	ComposeArgs []string
	ExpiresAt   time.Time
	Used        bool
}

type Server struct {
	cfg         Config
	docker      *client.Client
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

func main() {
	configPath := flag.String("config", "policy.yaml", "path to YAML policy/config")
	flag.Parse()

	cfg, err := loadConfig(*configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "FATAL: load config: %v\n", err)
		os.Exit(1)
	}

	log := buildLogger(cfg.Logging)
	srv, err := newServer(cfg, log)
	if err != nil {
		log.Error("server init failed", "error", err)
		os.Exit(1)
	}
	defer func() { _ = srv.docker.Close() }()

	httpServer := &http.Server{
		Addr:         cfg.Server.ListenAddr,
		Handler:      srv.router(),
		ReadTimeout:  15 * time.Second,
		WriteTimeout: time.Duration(cfg.Docker.TimeoutSeconds+5) * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		log.Info("safe-docker listening", "addr", cfg.Server.ListenAddr)
		if err := httpServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Error("server error", "error", err)
			os.Exit(1)
		}
	}()

	<-quit
	log.Info("shutting down")
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := httpServer.Shutdown(ctx); err != nil {
		log.Error("graceful shutdown failed", "error", err)
		os.Exit(1)
	}
	log.Info("shutdown complete")
}

func defaults() Config {
	return Config{
		Server: ServerConfig{ListenAddr: ":8080"},
		Docker: DockerConfig{
			SocketPath:     "/var/run/docker.sock",
			TimeoutSeconds: 15,
			LogTailDefault: 100,
			LogTailMax:     500,
		},
		Auth:     AuthConfig{Keys: map[string]APIKeyConfig{}},
		Projects: map[string]ProjectConfig{},
		Logging:  LoggingConfig{Level: "info", Format: "json"},
		Approval: ApprovalConfig{
			TokenTTLSecs:    120,
			TokenTTLMaxSecs: 600,
		},
	}
}

func loadConfig(path string) (Config, error) {
	cfg := defaults()
	f, err := os.Open(path)
	if err != nil {
		return cfg, fmt.Errorf("open config %q: %w", path, err)
	}
	defer func() { _ = f.Close() }()

	raw, err := io.ReadAll(f)
	if err != nil {
		return cfg, fmt.Errorf("read config %q: %w", path, err)
	}
	expanded := os.ExpandEnv(string(raw))

	dec := yaml.NewDecoder(strings.NewReader(expanded))
	dec.KnownFields(true)
	if err := dec.Decode(&cfg); err != nil {
		return cfg, fmt.Errorf("parse config %q: %w", path, err)
	}
	if err := cfg.validate(); err != nil {
		return cfg, err
	}
	return cfg, nil
}

func (c *Config) validate() error {
	if len(c.Auth.Keys) == 0 {
		return fmt.Errorf("auth.keys must contain at least one API key")
	}
	for key, meta := range c.Auth.Keys {
		if strings.TrimSpace(key) == "" {
			return fmt.Errorf("auth.keys cannot contain empty key values")
		}
		if strings.TrimSpace(meta.Label) == "" {
			return fmt.Errorf("auth.keys[%q].label is required", key)
		}
	}
	if len(c.Projects) == 0 {
		return fmt.Errorf("projects must declare at least one project")
	}
	for project, projectCfg := range c.Projects {
		if !validServiceName.MatchString(project) {
			return fmt.Errorf("invalid project name %q", project)
		}
		if len(projectCfg.Services) == 0 {
			return fmt.Errorf("projects.%s.services must declare at least one service", project)
		}
		seenContainers := map[string]string{}
		for service, policy := range projectCfg.Services {
			if !validServiceName.MatchString(service) {
				return fmt.Errorf("invalid service name %q in project %q", service, project)
			}
			policy.Container = strings.TrimSpace(policy.Container)
			// Container is optional — resolved via compose labels at runtime
			if policy.Container != "" {
				if owner, exists := seenContainers[policy.Container]; exists {
					return fmt.Errorf("container %q mapped by both %q and %q in project %q", policy.Container, owner, service, project)
				}
				seenContainers[policy.Container] = service
			}
			if len(policy.Actions) == 0 {
				return fmt.Errorf("projects.%s.services.%s.actions must contain at least one action", project, service)
			}
			for _, action := range policy.Actions {
				if _, ok := validActions[action]; !ok {
					return fmt.Errorf("projects.%s.services.%s.actions contains unknown action %q", project, service, action)
				}
				// Dangerous actions require explicit opt-in
				if _, isDangerous := dangerousActions[action]; isDangerous && !policy.Dangerous {
					return fmt.Errorf("projects.%s.services.%s.actions contains dangerous action %q but dangerous: true not set", project, service, action)
				}
			}
		}
	}
	if c.Docker.TimeoutSeconds <= 0 {
		return fmt.Errorf("docker.timeout_seconds must be > 0")
	}
	if c.Docker.LogTailDefault <= 0 {
		return fmt.Errorf("docker.log_tail_default must be > 0")
	}
	if c.Docker.LogTailMax < c.Docker.LogTailDefault {
		return fmt.Errorf("docker.log_tail_max must be >= docker.log_tail_default")
	}
	return nil
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

	srv := &Server{
		cfg:       cfg,
		docker:    dockerClient,
		log:       log,
		approvals: make(map[string]*pendingApproval),
	}

	// Background sweeper: remove expired tokens every 60 seconds.
	go srv.sweepExpiredApprovals()

	return srv, nil
}

// sweepOnce performs one pass of cleanup, removing expired tokens from the approvals map.
// Used by the background ticker and testable for unit tests.
func (s *Server) sweepOnce() {
	now := time.Now()
	s.approvalsMu.Lock()
	for token, ap := range s.approvals {
		if now.After(ap.ExpiresAt) {
			tokenPrefix := token
			if len(token) > 8 {
				tokenPrefix = token[:8] + "…"
			}
			s.log.Info("approval expired",
				"token", tokenPrefix,
				"action", ap.Action,
				"service", ap.Service,
				"project", ap.Project,
			)
			delete(s.approvals, token)
		}
	}
	s.approvalsMu.Unlock()
}

// sweepExpiredApprovals periodically removes expired tokens from the approvals map.
func (s *Server) sweepExpiredApprovals() {
	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		s.sweepOnce()
	}
}

// generateToken creates a cryptographically random 32-byte hex token.
func generateToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generate token: %w", err)
	}
	return hex.EncodeToString(b), nil
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

func (s *Server) healthHandler(w http.ResponseWriter, r *http.Request) {
	status := "ok"
	httpStatus := http.StatusOK

	if s.docker == nil {
		status = "degraded"
		httpStatus = http.StatusServiceUnavailable
	} else {
		ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
		defer cancel()
		_, err := s.docker.Ping(ctx)
		if err != nil {
			status = "degraded"
			httpStatus = http.StatusServiceUnavailable
		}
	}
	writeJSON(w, httpStatus, map[string]string{"status": status})
}

func (s *Server) listProjectsHandler(w http.ResponseWriter, r *http.Request) {
	projects := make([]map[string]any, 0, len(s.cfg.Projects))
	for name, proj := range s.cfg.Projects {
		projects = append(projects, map[string]any{
			"project":       name,
			"service_count": len(proj.Services),
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"projects": projects})
}

func (s *Server) listServicesHandler(w http.ResponseWriter, r *http.Request) {
	project := chi.URLParam(r, "project")
	projectCfg, ok := s.cfg.Projects[project]
	if !ok {
		writeError(w, http.StatusNotFound, "unknown project")
		return
	}
	services := make([]map[string]any, 0, len(projectCfg.Services))
	for name, svc := range projectCfg.Services {
		services = append(services, map[string]any{
			"service": name,
			"actions": svc.Actions,
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"project": project, "services": services})
}

// resolveContainer finds a container by explicit name or by compose labels.
//
// Resolution strategy:
//  1. If policy.Container is set → match by exact container name
//  2. Otherwise → match by compose labels (project key + service key)
//
// Returns container ID, resolved name, and error.
func (s *Server) resolveContainer(ctx context.Context, project, serviceKey string, policy ServicePolicy) (string, string, error) {
	containers, err := s.docker.ContainerList(ctx, container.ListOptions{All: true})
	if err != nil {
		return "", "", fmt.Errorf("failed to list containers: %w", err)
	}

	// Strategy 1: If explicit container name is set, match by name
	if policy.Container != "" {
		for _, c := range containers {
			for _, name := range c.Names {
				if strings.TrimPrefix(name, "/") == policy.Container {
					return c.ID, policy.Container, nil
				}
			}
		}
		return "", policy.Container, fmt.Errorf("container %q not found", policy.Container)
	}

	// Strategy 2: Match by compose labels (project key = compose project name)
	var matches []struct {
		id   string
		name string
	}
	for _, c := range containers {
		proj, hasProj := c.Labels["com.docker.compose.project"]
		svc, hasSvc := c.Labels["com.docker.compose.service"]
		if hasProj && hasSvc && proj == project && svc == serviceKey {
			resolvedName := serviceKey
			if len(c.Names) > 0 {
				resolvedName = strings.TrimPrefix(c.Names[0], "/")
			}
			matches = append(matches, struct {
				id   string
				name string
			}{c.ID, resolvedName})
		}
	}
	if len(matches) == 0 {
		return "", serviceKey, fmt.Errorf("no container found for service %q in project %q", serviceKey, project)
	}
	if len(matches) > 1 {
		return "", serviceKey, fmt.Errorf("multiple containers found for service %q (replicas not supported, use explicit container name)", serviceKey)
	}
	return matches[0].id, matches[0].name, nil
}

func (s *Server) statusHandler(w http.ResponseWriter, r *http.Request) {
	project, service, policy, ok := s.authorizeAction(w, r, "status")
	if !ok {
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), time.Duration(s.cfg.Docker.TimeoutSeconds)*time.Second)
	defer cancel()

	containerID, resolvedName, err := s.resolveContainer(ctx, project, service, policy)
	if err != nil {
		s.audit(r, "status", service, resolvedName, "not_found", err.Error())
		writeError(w, http.StatusNotFound, "container not found")
		return
	}

	// Get container details for state/status
	containers, err := s.docker.ContainerList(ctx, container.ListOptions{All: true})
	if err != nil {
		s.audit(r, "status", service, resolvedName, "error", err.Error())
		writeError(w, http.StatusBadGateway, "failed to list containers")
		return
	}
	for _, c := range containers {
		if c.ID == containerID {
			s.audit(r, "status", service, resolvedName, "success", "")
			writeJSON(w, http.StatusOK, map[string]any{
				"project":   project,
				"service":   service,
				"container": resolvedName,
				"id":        trimContainerID(c.ID),
				"state":     c.State,
				"status":    c.Status,
			})
			return
		}
	}
	s.audit(r, "status", service, resolvedName, "error", "container disappeared")
	writeError(w, http.StatusNotFound, "container not found")
}

func (s *Server) logsHandler(w http.ResponseWriter, r *http.Request) {
	project, service, policy, ok := s.authorizeAction(w, r, "logs")
	if !ok {
		return
	}
	tail := s.cfg.Docker.LogTailDefault
	if raw := strings.TrimSpace(r.URL.Query().Get("tail")); raw != "" {
		var parsed int
		if _, err := fmt.Sscanf(raw, "%d", &parsed); err != nil || parsed <= 0 || parsed > s.cfg.Docker.LogTailMax {
			s.audit(r, "logs", service, policy.Container, "denied", "invalid tail parameter")
			writeError(w, http.StatusBadRequest, fmt.Sprintf("tail must be between 1 and %d", s.cfg.Docker.LogTailMax))
			return
		}
		tail = parsed
	}
	ctx, cancel := context.WithTimeout(r.Context(), time.Duration(s.cfg.Docker.TimeoutSeconds)*time.Second)
	defer cancel()

	containerID, resolvedName, err := s.resolveContainer(ctx, project, service, policy)
	if err != nil {
		s.audit(r, "logs", service, resolvedName, "not_found", err.Error())
		writeError(w, http.StatusNotFound, "container not found")
		return
	}

	reader, err := s.docker.ContainerLogs(ctx, containerID, container.LogsOptions{
		ShowStdout: true,
		ShowStderr: true,
		Tail:       fmt.Sprintf("%d", tail),
	})
	if err != nil {
		s.audit(r, "logs", service, resolvedName, "error", err.Error())
		writeError(w, http.StatusBadGateway, fmt.Sprintf("logs failed: %v", err))
		return
	}
	defer func() { _ = reader.Close() }()
	payload, err := stripDockerMuxHeader(reader)
	if err != nil {
		s.audit(r, "logs", service, resolvedName, "error", err.Error())
		writeError(w, http.StatusBadGateway, fmt.Sprintf("log decode failed: %v", err))
		return
	}
	s.audit(r, "logs", service, resolvedName, "success", "")
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(payload)
}

func (s *Server) restartHandler(w http.ResponseWriter, r *http.Request) {
	s.lifecycleHandler(w, r, "restart", func(ctx context.Context, containerName string) error {
		stopTimeout := 10
		return s.docker.ContainerRestart(ctx, containerName, container.StopOptions{Timeout: &stopTimeout})
	})
}

func (s *Server) startHandler(w http.ResponseWriter, r *http.Request) {
	s.lifecycleHandler(w, r, "start", func(ctx context.Context, containerName string) error {
		return s.docker.ContainerStart(ctx, containerName, container.StartOptions{})
	})
}

func (s *Server) stopHandler(w http.ResponseWriter, r *http.Request) {
	s.lifecycleHandler(w, r, "stop", func(ctx context.Context, containerName string) error {
		stopTimeout := 10
		return s.docker.ContainerStop(ctx, containerName, container.StopOptions{Timeout: &stopTimeout})
	})
}

func (s *Server) upHandler(w http.ResponseWriter, r *http.Request) {
	s.composeHandler(w, r, "up", "up", "-d")
}

func (s *Server) downHandler(w http.ResponseWriter, r *http.Request) {
	s.composeHandler(w, r, "down", "down")
}

func (s *Server) recreateHandler(w http.ResponseWriter, r *http.Request) {
	s.composeHandler(w, r, "recreate", "up", "-d", "--force-recreate")
}

func (s *Server) buildHandler(w http.ResponseWriter, r *http.Request) {
	s.composeHandler(w, r, "build", "build")
}

func (s *Server) composeHandler(w http.ResponseWriter, r *http.Request, action string, composeArgs ...string) {
	project, service, _, ok := s.authorizeAction(w, r, action)
	if !ok {
		return
	}

	// Intercept dangerous actions for HITL approval.
	if _, isDangerous := dangerousActions[action]; isDangerous {
		s.handleDangerousAction(w, r, action, project, service, composeArgs...)
		return
	}

	s.executeCompose(w, r, action, project, service, composeArgs...)
}

// executeCompose runs the actual docker compose command and writes the response.
// Used by both composeHandler (non-dangerous) and approveHandler (post-approval).
func (s *Server) executeCompose(w http.ResponseWriter, r *http.Request, action, project, service string, composeArgs ...string) {
	ctx, cancel := context.WithTimeout(r.Context(), time.Duration(s.cfg.Docker.TimeoutSeconds)*time.Second)
	defer cancel()

	// Compose commands use the project key as -p flag and service key as the compose service name
	args := []string{"compose", "-p", project}
	args = append(args, composeArgs...)
	args = append(args, service)
	cmd := exec.CommandContext(ctx, "docker", args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		s.audit(r, action, service, "", "error", err.Error())
		writeError(w, http.StatusBadGateway, fmt.Sprintf("%s failed: %v\n%s", action, err, string(output)))
		return
	}
	s.audit(r, action, service, "", "success", "")
	writeJSON(w, http.StatusOK, map[string]any{
		"project": project,
		"service": service,
		"status":  action + " completed",
		"output":  string(output),
	})
}

// handleDangerousAction intercepts a dangerous compose action and requests
// human approval via webhook before allowing execution.
func (s *Server) handleDangerousAction(w http.ResponseWriter, r *http.Request, action, project, service string, composeArgs ...string) {
	if s.cfg.Approval.WebhookURL == "" {
		writeError(w, http.StatusForbidden, "dangerous action requires approval webhook to be configured")
		return
	}

	// Validate webhook URL scheme — must be http:// or https://
	if !strings.HasPrefix(s.cfg.Approval.WebhookURL, "http://") && !strings.HasPrefix(s.cfg.Approval.WebhookURL, "https://") {
		s.log.Error("invalid webhook URL scheme", "url", s.cfg.Approval.WebhookURL)
		writeError(w, http.StatusInternalServerError, "invalid webhook URL scheme")
		return
	}

	ttl := time.Duration(s.cfg.Approval.TokenTTLSecs) * time.Second
	maxTTL := time.Duration(s.cfg.Approval.TokenTTLMaxSecs) * time.Second
	if ttl > maxTTL {
		ttl = maxTTL
	}
	expiresAt := time.Now().Add(ttl)

	token, err := generateToken()
	if err != nil {
		s.log.Error("failed to generate approval token", "error", err)
		writeError(w, http.StatusInternalServerError, "failed to generate approval token")
		return
	}

	ap := &pendingApproval{
		Action:      action,
		Project:     project,
		Service:     service,
		ComposeArgs: composeArgs,
		ExpiresAt:   expiresAt,
		Used:        false,
	}
	s.approvalsMu.Lock()
	s.approvals[token] = ap
	s.approvalsMu.Unlock()

	// POST to webhook.
	webhookPayload := map[string]string{
		"approval_key": token,
		"action":       action,
		"service":      service,
		"project":      project,
		"expires_at":   expiresAt.UTC().Format(time.RFC3339),
		"message":      fmt.Sprintf("Agent requested: docker compose %s %s", action, service),
	}
	payloadBytes, _ := json.Marshal(webhookPayload)

	webhookCtx, webhookCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer webhookCancel()

	req, err := http.NewRequestWithContext(webhookCtx, http.MethodPost, s.cfg.Approval.WebhookURL, bytes.NewReader(payloadBytes))
	if err != nil {
		s.approvalsMu.Lock()
		delete(s.approvals, token)
		s.approvalsMu.Unlock()
		s.log.Error("failed to build webhook request", "error", err)
		writeError(w, http.StatusServiceUnavailable, "failed to reach approval webhook")
		return
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil || resp.StatusCode >= 500 {
		s.approvalsMu.Lock()
		delete(s.approvals, token)
		s.approvalsMu.Unlock()
		reason := "webhook POST failed"
		if err != nil {
			reason = err.Error()
		} else {
			reason = fmt.Sprintf("webhook returned %d", resp.StatusCode)
			_ = resp.Body.Close()
		}
		s.log.Error("approval webhook error", "reason", reason)
		writeError(w, http.StatusServiceUnavailable, "approval webhook unavailable")
		return
	}
	_ = resp.Body.Close()

	s.log.Info("approval pending",
		"action", action,
		"project", project,
		"service", service,
		"expires_at", expiresAt.UTC().Format(time.RFC3339),
		"caller", callerFromContext(r.Context()),
	)

	writeJSON(w, http.StatusAccepted, map[string]string{
		"status":  "pending_approval",
		"message": "approval requested \u2014 waiting for human confirmation",
	})
}

// approveHandler handles POST /v1/approve — executes a previously approved action.
func (s *Server) approveHandler(w http.ResponseWriter, r *http.Request) {
	var body struct {
		ApprovalKey string `json:"approval_key"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || strings.TrimSpace(body.ApprovalKey) == "" {
		writeError(w, http.StatusBadRequest, "approval_key is required")
		return
	}
	token := body.ApprovalKey

	s.approvalsMu.Lock()
	ap, exists := s.approvals[token]
	if !exists {
		s.approvalsMu.Unlock()
		writeError(w, http.StatusNotFound, "approval token not found")
		return
	}
	if time.Now().After(ap.ExpiresAt) {
		delete(s.approvals, token)
		s.approvalsMu.Unlock()
		writeError(w, http.StatusGone, "approval token has expired")
		return
	}
	if ap.Used {
		s.approvalsMu.Unlock()
		writeError(w, http.StatusConflict, "approval token already used")
		return
	}

	// Mark used and copy fields before releasing the lock.
	ap.Used = true
	action := ap.Action
	project := ap.Project
	service := ap.Service
	composeArgs := make([]string, len(ap.ComposeArgs))
	copy(composeArgs, ap.ComposeArgs)
	s.approvalsMu.Unlock()

	// Execute the compose command directly (skip dangerous check).
	ctx, cancel := context.WithTimeout(r.Context(), time.Duration(s.cfg.Docker.TimeoutSeconds)*time.Second)
	defer cancel()

	args := []string{"compose", "-p", project}
	args = append(args, composeArgs...)
	args = append(args, service)
	cmd := exec.CommandContext(ctx, "docker", args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		s.audit(r, "approve:"+action, service, "", "error", err.Error())
		writeError(w, http.StatusBadGateway, fmt.Sprintf("%s failed: %v\n%s", action, err, string(output)))
		return
	}

	s.audit(r, "approve:"+action, service, "", "success", "")
	writeJSON(w, http.StatusOK, map[string]any{
		"status":  "executed",
		"project": project,
		"service": service,
		"output":  string(output),
	})
}

func (s *Server) lifecycleHandler(w http.ResponseWriter, r *http.Request, action string, fn func(context.Context, string) error) {
	project, service, policy, ok := s.authorizeAction(w, r, action)
	if !ok {
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), time.Duration(s.cfg.Docker.TimeoutSeconds)*time.Second)
	defer cancel()

	containerID, resolvedName, err := s.resolveContainer(ctx, project, service, policy)
	if err != nil {
		s.audit(r, action, service, resolvedName, "not_found", err.Error())
		writeError(w, http.StatusNotFound, "container not found")
		return
	}

	if err := fn(ctx, containerID); err != nil {
		s.audit(r, action, service, resolvedName, "error", err.Error())
		writeError(w, http.StatusBadGateway, fmt.Sprintf("%s failed: %v", action, err))
		return
	}
	s.audit(r, action, service, resolvedName, "success", "")
	writeJSON(w, http.StatusOK, map[string]string{"project": project, "service": service, "container": resolvedName, "status": action + "ed"})
}

func (s *Server) authorizeAction(w http.ResponseWriter, r *http.Request, action string) (string, string, ServicePolicy, bool) {
	if r.Method != methodForAction(action) {
		w.Header().Set("Allow", methodForAction(action))
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return "", "", ServicePolicy{}, false
	}
	project := chi.URLParam(r, "project")
	if !validServiceName.MatchString(project) {
		s.audit(r, action, "", "", "denied", "invalid project name")
		writeError(w, http.StatusBadRequest, "invalid project name")
		return "", "", ServicePolicy{}, false
	}
	projectCfg, ok := s.cfg.Projects[project]
	if !ok {
		s.audit(r, action, "", "", "denied", "unknown project")
		writeError(w, http.StatusNotFound, "unknown project")
		return "", "", ServicePolicy{}, false
	}
	service := chi.URLParam(r, "service")
	if !validServiceName.MatchString(service) {
		s.audit(r, action, service, "", "denied", "invalid service name")
		writeError(w, http.StatusBadRequest, "invalid service name")
		return "", "", ServicePolicy{}, false
	}
	policy, ok := projectCfg.Services[service]
	if !ok {
		s.audit(r, action, service, "", "denied", "unknown service")
		writeError(w, http.StatusNotFound, "unknown service")
		return "", "", ServicePolicy{}, false
	}
	if !slices.Contains(policy.Actions, action) {
		s.audit(r, action, service, policy.Container, "denied", "action not allowed")
		writeError(w, http.StatusForbidden, "action not allowed")
		return "", "", policy, false
	}
	return project, service, policy, true
}

func methodForAction(action string) string {
	if action == "status" || action == "logs" {
		return http.MethodGet
	}
	return http.MethodPost
}

func (s *Server) audit(r *http.Request, action, service, containerName, result, reason string) {
	entry := auditEntry{
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		Caller:    callerFromContext(r.Context()),
		Action:    action,
		Service:   service,
		Container: containerName,
		Result:    result,
		Reason:    reason,
		RequestID: middleware.GetReqID(r.Context()),
		Remote:    r.RemoteAddr,
	}
	s.log.Info("audit",
		"timestamp", entry.Timestamp,
		"caller", entry.Caller,
		"action", entry.Action,
		"service", entry.Service,
		"container", entry.Container,
		"result", entry.Result,
		"reason", entry.Reason,
		"request_id", entry.RequestID,
		"remote_addr", entry.Remote,
	)
}

func trimContainerID(id string) string {
	if len(id) > 12 {
		return id[:12]
	}
	return id
}

func stripDockerMuxHeader(r io.Reader) ([]byte, error) {
	header := make([]byte, 8)
	var result []byte
	for {
		_, err := io.ReadFull(r, header)
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("read docker mux header: %w", err)
		}
		size := uint32(header[4])<<24 | uint32(header[5])<<16 | uint32(header[6])<<8 | uint32(header[7])
		if size == 0 {
			continue
		}
		payload := make([]byte, size)
		if _, err := io.ReadFull(r, payload); err != nil {
			return nil, fmt.Errorf("read docker mux payload: %w", err)
		}
		result = append(result, payload...)
	}
	return result, nil
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}
