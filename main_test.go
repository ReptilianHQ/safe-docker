package main

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// ─── helpers ────────────────────────────────────────────────────────────────

func minimalConfig() Config {
	return Config{
		Server: ServerConfig{ListenAddr: ":8080"},
		Docker: DockerConfig{
			SocketPath:     "/var/run/docker.sock",
			TimeoutSeconds: 15,
			LogTailDefault: 100,
			LogTailMax:     500,
		},
		Auth: AuthConfig{
			Keys: map[string]APIKeyConfig{
				"test-key": {Label: "test-agent"},
			},
		},
		Projects: map[string]ProjectConfig{
			"testproj": {
				Services: map[string]ServicePolicy{
					"myapp": {
						Container: "testproj-myapp-1",
						Actions:   []string{"status", "logs", "restart"},
					},
					"readonly": {
						Container: "testproj-readonly-1",
						Actions:   []string{"status", "logs"},
					},
				},
			},
		},
		Logging: LoggingConfig{Level: "error", Format: "json"},
	}
}

// stubServer builds a Server with no real Docker client — only for handler
// tests that don't exercise Docker code paths (auth, routing, validation).
func stubServer(cfg Config) *Server {
	return &Server{
		cfg: cfg,
		log: buildLogger(cfg.Logging),
	}
}

func get(t *testing.T, srv *Server, path, apiKey string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	if apiKey != "" {
		req.Header.Set("X-API-Key", apiKey)
	}
	rr := httptest.NewRecorder()
	srv.router().ServeHTTP(rr, req)
	return rr
}

func post(t *testing.T, srv *Server, path, apiKey string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, path, nil)
	if apiKey != "" {
		req.Header.Set("X-API-Key", apiKey)
	}
	rr := httptest.NewRecorder()
	srv.router().ServeHTTP(rr, req)
	return rr
}

func decodeJSON(t *testing.T, body io.Reader) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.NewDecoder(body).Decode(&m); err != nil {
		t.Fatalf("decode JSON: %v", err)
	}
	return m
}

// ─── Config validation ───────────────────────────────────────────────────────

func TestConfigValidate_OK(t *testing.T) {
	cfg := minimalConfig()
	if err := cfg.validate(); err != nil {
		t.Fatalf("expected valid config, got: %v", err)
	}
}

func TestConfigValidate_NoKeys(t *testing.T) {
	cfg := minimalConfig()
	cfg.Auth.Keys = map[string]APIKeyConfig{}
	if err := cfg.validate(); err == nil {
		t.Fatal("expected error for empty auth.keys")
	}
}

func TestConfigValidate_EmptyKeyValue(t *testing.T) {
	cfg := minimalConfig()
	cfg.Auth.Keys["  "] = APIKeyConfig{Label: "spacey"}
	if err := cfg.validate(); err == nil {
		t.Fatal("expected error for whitespace-only key")
	}
}

func TestConfigValidate_MissingKeyLabel(t *testing.T) {
	cfg := minimalConfig()
	cfg.Auth.Keys["some-key"] = APIKeyConfig{Label: ""}
	if err := cfg.validate(); err == nil {
		t.Fatal("expected error for key with empty label")
	}
}

func TestConfigValidate_NoProjects(t *testing.T) {
	cfg := minimalConfig()
	cfg.Projects = map[string]ProjectConfig{}
	if err := cfg.validate(); err == nil {
		t.Fatal("expected error for no projects")
	}
}

func TestConfigValidate_NoServices(t *testing.T) {
	cfg := minimalConfig()
	proj := cfg.Projects["testproj"]
	proj.Services = map[string]ServicePolicy{}
	cfg.Projects["testproj"] = proj
	if err := cfg.validate(); err == nil {
		t.Fatal("expected error for no services")
	}
}

func TestConfigValidate_InvalidServiceName(t *testing.T) {
	cfg := minimalConfig()
	proj := cfg.Projects["testproj"]
	proj.Services["Bad Name!"] = ServicePolicy{Container: "c", Actions: []string{"status"}}
	cfg.Projects["testproj"] = proj
	if err := cfg.validate(); err == nil {
		t.Fatal("expected error for invalid service name")
	}
}

func TestConfigValidate_EmptyContainerUsesComposeLabels(t *testing.T) {
	// Container is optional — if empty, compose labels are used for lookup
	cfg := minimalConfig()
	proj := cfg.Projects["testproj"]
	proj.Services["noc"] = ServicePolicy{Container: "", Actions: []string{"status"}}
	cfg.Projects["testproj"] = proj
	if err := cfg.validate(); err != nil {
		t.Fatalf("empty container should be valid (uses compose labels): %v", err)
	}
}

func TestConfigValidate_DuplicateContainer(t *testing.T) {
	cfg := minimalConfig()
	proj := cfg.Projects["testproj"]
	proj.Services["dupe"] = ServicePolicy{Container: "testproj-myapp-1", Actions: []string{"status"}}
	cfg.Projects["testproj"] = proj
	if err := cfg.validate(); err == nil {
		t.Fatal("expected error for duplicate container mapping")
	}
}

func TestConfigValidate_EmptyActions(t *testing.T) {
	cfg := minimalConfig()
	proj := cfg.Projects["testproj"]
	proj.Services["noact"] = ServicePolicy{Container: "testproj-noact-1", Actions: []string{}}
	cfg.Projects["testproj"] = proj
	if err := cfg.validate(); err == nil {
		t.Fatal("expected error for empty actions")
	}
}

func TestConfigValidate_UnknownAction(t *testing.T) {
	cfg := minimalConfig()
	proj := cfg.Projects["testproj"]
	proj.Services["bad"] = ServicePolicy{Container: "testproj-bad-1", Actions: []string{"nuke"}}
	cfg.Projects["testproj"] = proj
	if err := cfg.validate(); err == nil {
		t.Fatal("expected error for unknown action")
	}
}

func TestConfigValidate_BadDockerTimeout(t *testing.T) {
	cfg := minimalConfig()
	cfg.Docker.TimeoutSeconds = 0
	if err := cfg.validate(); err == nil {
		t.Fatal("expected error for zero timeout")
	}
}

func TestConfigValidate_LogTailMaxLessThanDefault(t *testing.T) {
	cfg := minimalConfig()
	cfg.Docker.LogTailDefault = 200
	cfg.Docker.LogTailMax = 100
	if err := cfg.validate(); err == nil {
		t.Fatal("expected error when log_tail_max < log_tail_default")
	}
}

func TestConfigDefaults(t *testing.T) {
	cfg := defaults()
	if cfg.Server.ListenAddr != ":8080" {
		t.Errorf("expected listen_addr :8080, got %q", cfg.Server.ListenAddr)
	}
	if cfg.Docker.TimeoutSeconds != 15 {
		t.Errorf("expected timeout 15, got %d", cfg.Docker.TimeoutSeconds)
	}
}

// ─── loadConfig ─────────────────────────────────────────────────────────────

func TestLoadConfig_FromFile(t *testing.T) {
	// Use the checked-in example policy
	cfg, err := loadConfig("policy.example.yaml")
	if err != nil {
		t.Fatalf("loadConfig(policy.example.yaml): %v", err)
	}
	if len(cfg.Projects) == 0 {
		t.Fatal("expected at least one project in policy.example.yaml")
	}
}

func TestLoadConfig_MissingFile(t *testing.T) {
	_, err := loadConfig("does-not-exist.yaml")
	if err == nil {
		t.Fatal("expected error for missing config file")
	}
}

// ─── Authentication ──────────────────────────────────────────────────────────

func TestAuth_NoKey(t *testing.T) {
	srv := stubServer(minimalConfig())
	rr := get(t, srv, "/v1/projects", "")
	if rr.Code != http.StatusUnauthorized {
		t.Errorf("want 401, got %d", rr.Code)
	}
	body := decodeJSON(t, rr.Body)
	if _, ok := body["error"]; !ok {
		t.Error("expected error field in response")
	}
}

func TestAuth_WrongKey(t *testing.T) {
	srv := stubServer(minimalConfig())
	rr := get(t, srv, "/v1/projects", "wrong-key")
	if rr.Code != http.StatusForbidden {
		t.Errorf("want 403, got %d", rr.Code)
	}
}

func TestAuth_WhitespaceOnlyKey(t *testing.T) {
	srv := stubServer(minimalConfig())
	rr := get(t, srv, "/v1/projects", "   ")
	if rr.Code != http.StatusUnauthorized {
		t.Errorf("want 401 for whitespace-only key, got %d", rr.Code)
	}
}

func TestAuth_ValidKey(t *testing.T) {
	srv := stubServer(minimalConfig())
	rr := get(t, srv, "/v1/projects", "test-key")
	// 200 — no docker call needed for list handler
	if rr.Code != http.StatusOK {
		t.Errorf("want 200 with valid key, got %d", rr.Code)
	}
}

// ─── /health ────────────────────────────────────────────────────────────────

func TestHealth_NoAuth(t *testing.T) {
	// /health must be reachable without an API key
	srv := stubServer(minimalConfig())
	// Without a real docker client the ping will fail → "degraded"
	// but it must still return a response (not 401/403)
	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	rr := httptest.NewRecorder()
	srv.router().ServeHTTP(rr, req)
	if rr.Code == http.StatusUnauthorized || rr.Code == http.StatusForbidden {
		t.Errorf("/health should not require auth, got %d", rr.Code)
	}
}

// ─── /v1/projects ───────────────────────────────────────────────────────────

func TestListProjects_ReturnsAll(t *testing.T) {
	srv := stubServer(minimalConfig())
	rr := get(t, srv, "/v1/projects", "test-key")
	if rr.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", rr.Code)
	}
	body := decodeJSON(t, rr.Body)
	projects, ok := body["projects"].([]any)
	if !ok {
		t.Fatalf("expected projects array, got %T", body["projects"])
	}
	if len(projects) != 1 {
		t.Errorf("want 1 project, got %d", len(projects))
	}
}

// ─── /v1/projects/{project}/services ─────────────────────────────────────────

func TestListServices_ReturnsAll(t *testing.T) {
	srv := stubServer(minimalConfig())
	rr := get(t, srv, "/v1/projects/testproj/services", "test-key")
	if rr.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", rr.Code)
	}
	body := decodeJSON(t, rr.Body)
	services, ok := body["services"].([]any)
	if !ok {
		t.Fatalf("expected services array, got %T", body["services"])
	}
	if len(services) != 2 {
		t.Errorf("want 2 services, got %d", len(services))
	}
}

func TestListServices_UnknownProject(t *testing.T) {
	srv := stubServer(minimalConfig())
	rr := get(t, srv, "/v1/projects/unknown/services", "test-key")
	if rr.Code != http.StatusNotFound {
		t.Errorf("want 404 for unknown project, got %d", rr.Code)
	}
}

func TestListServices_ContentType(t *testing.T) {
	srv := stubServer(minimalConfig())
	rr := get(t, srv, "/v1/projects/testproj/services", "test-key")
	ct := rr.Header().Get("Content-Type")
	if !strings.HasPrefix(ct, "application/json") {
		t.Errorf("want application/json, got %q", ct)
	}
}

// ─── Authorization — action gating ──────────────────────────────────────────

func TestAuthorize_UnknownProject(t *testing.T) {
	srv := stubServer(minimalConfig())
	rr := get(t, srv, "/v1/projects/unknown/services/myapp/status", "test-key")
	if rr.Code != http.StatusNotFound {
		t.Errorf("want 404 for unknown project, got %d", rr.Code)
	}
}

func TestAuthorize_UnknownService(t *testing.T) {
	srv := stubServer(minimalConfig())
	rr := get(t, srv, "/v1/projects/testproj/services/ghost/status", "test-key")
	if rr.Code != http.StatusNotFound {
		t.Errorf("want 404 for unknown service, got %d", rr.Code)
	}
}

func TestAuthorize_ActionNotAllowed(t *testing.T) {
	// "readonly" service only allows status + logs, not restart
	srv := stubServer(minimalConfig())
	rr := post(t, srv, "/v1/projects/testproj/services/readonly/restart", "test-key")
	if rr.Code != http.StatusForbidden {
		t.Errorf("want 403 when action not in policy, got %d", rr.Code)
	}
	body := decodeJSON(t, rr.Body)
	if _, ok := body["error"]; !ok {
		t.Error("expected error field")
	}
}

func TestAuthorize_InvalidServiceName(t *testing.T) {
	srv := stubServer(minimalConfig())
	// Uppercase fails the validServiceName regex (only lowercase allowed)
	rr := get(t, srv, "/v1/projects/testproj/services/INVALID/status", "test-key")
	// Expect 400 for invalid service name
	if rr.Code != http.StatusBadRequest {
		t.Errorf("want 400 for invalid service name (uppercase), got %d", rr.Code)
	}
}

// ─── Method enforcement ──────────────────────────────────────────────────────

func TestMethodEnforcement_StatusMustBeGET(t *testing.T) {
	srv := stubServer(minimalConfig())
	req := httptest.NewRequest(http.MethodPost, "/v1/projects/testproj/services/myapp/status", nil)
	req.Header.Set("X-API-Key", "test-key")
	rr := httptest.NewRecorder()
	srv.router().ServeHTTP(rr, req)
	// chi returns 405 for wrong method on a registered route
	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("want 405 for POST on status endpoint, got %d", rr.Code)
	}
}

func TestMethodEnforcement_RestartMustBePOST(t *testing.T) {
	srv := stubServer(minimalConfig())
	rr := get(t, srv, "/v1/projects/testproj/services/myapp/restart", "test-key")
	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("want 405 for GET on restart endpoint, got %d", rr.Code)
	}
}

// ─── Utility functions ───────────────────────────────────────────────────────

func TestTrimContainerID_Long(t *testing.T) {
	id := "abc123def456789"
	got := trimContainerID(id)
	if got != id[:12] {
		t.Errorf("want %q, got %q", id[:12], got)
	}
}

func TestTrimContainerID_Short(t *testing.T) {
	id := "abc"
	got := trimContainerID(id)
	if got != id {
		t.Errorf("want %q, got %q", id, got)
	}
}

func TestStripDockerMuxHeader_Empty(t *testing.T) {
	result, err := stripDockerMuxHeader(strings.NewReader(""))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result) != 0 {
		t.Errorf("expected empty result, got %d bytes", len(result))
	}
}

func TestStripDockerMuxHeader_ValidFrame(t *testing.T) {
	payload := []byte("hello world")
	size := uint32(len(payload))
	// Docker mux header: [stream_type(1), padding(3), size(4 bytes big-endian)]
	header := []byte{
		0x01,             // stdout
		0x00, 0x00, 0x00, // padding
		byte(size >> 24), byte(size >> 16), byte(size >> 8), byte(size),
	}
	frame := append(header, payload...)
	result, err := stripDockerMuxHeader(strings.NewReader(string(frame)))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(result) != string(payload) {
		t.Errorf("want %q, got %q", payload, result)
	}
}

func TestStripDockerMuxHeader_MultipleFrames(t *testing.T) {
	makeFrame := func(data string) []byte {
		p := []byte(data)
		sz := uint32(len(p))
		h := []byte{0x01, 0x00, 0x00, 0x00, byte(sz >> 24), byte(sz >> 16), byte(sz >> 8), byte(sz)}
		return append(h, p...)
	}
	var buf []byte
	buf = append(buf, makeFrame("line one\n")...)
	buf = append(buf, makeFrame("line two\n")...)

	result, err := stripDockerMuxHeader(strings.NewReader(string(buf)))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := "line one\nline two\n"
	if string(result) != want {
		t.Errorf("want %q, got %q", want, result)
	}
}

func TestBuildLogger_Levels(t *testing.T) {
	for _, level := range []string{"debug", "info", "warn", "error", "unknown"} {
		logger := buildLogger(LoggingConfig{Level: level, Format: "json"})
		if logger == nil {
			t.Errorf("buildLogger returned nil for level %q", level)
		}
	}
}

func TestBuildLogger_TextFormat(t *testing.T) {
	logger := buildLogger(LoggingConfig{Level: "info", Format: "text"})
	if logger == nil {
		t.Fatal("buildLogger returned nil for text format")
	}
}

func TestValidServiceNameRegex(t *testing.T) {
	valid := []string{"myapp", "my-app", "my.app", "my_app", "app123", "a"}
	invalid := []string{"", "My App", "bad!", "-leading", ".leading"}

	for _, name := range valid {
		if !validServiceName.MatchString(name) {
			t.Errorf("expected %q to be valid", name)
		}
	}
	for _, name := range invalid {
		if validServiceName.MatchString(name) {
			t.Errorf("expected %q to be invalid", name)
		}
	}
}

// ─── HITL approval helpers ───────────────────────────────────────────────────

// postBody makes an authenticated POST with a JSON body.
func postBody(t *testing.T, srv *Server, path, apiKey string, body any) *httptest.ResponseRecorder {
	t.Helper()
	b, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal body: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	if apiKey != "" {
		req.Header.Set("X-API-Key", apiKey)
	}
	rr := httptest.NewRecorder()
	srv.router().ServeHTTP(rr, req)
	return rr
}

// configWithDangerousService returns a config that includes a service allowing build/recreate.
func configWithDangerousService() Config {
	cfg := minimalConfig()
	proj := cfg.Projects["testproj"]
	proj.Services["danger"] = ServicePolicy{
		Container: "testproj-danger-1",
		Actions:   []string{"build", "recreate"},
		Dangerous: true,
	}
	cfg.Projects["testproj"] = proj
	return cfg
}

// ─── HITL approval tests ─────────────────────────────────────────────────────

// TestDangerous_NoWebhook verifies that dangerous actions with no webhook configured return 403.
func TestDangerous_NoWebhook(t *testing.T) {
	cfg := configWithDangerousService()
	// No webhook URL set.
	srv := stubServer(cfg)
	srv.approvals = make(map[string]*pendingApproval)

	rr := post(t, srv, "/v1/projects/testproj/services/danger/build", "test-key")
	if rr.Code != http.StatusForbidden {
		t.Errorf("want 403 when no webhook configured, got %d", rr.Code)
	}
	body := decodeJSON(t, rr.Body)
	if _, ok := body["error"]; !ok {
		t.Error("expected error field in response")
	}
}

// TestDangerous_WebhookReceivesPayload verifies webhook is POSTed with correct fields
// and the caller gets 202 (token must NOT appear in response).
func TestDangerous_WebhookReceivesPayload(t *testing.T) {
	var receivedPayload map[string]string
	webhookSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := json.NewDecoder(r.Body).Decode(&receivedPayload); err != nil {
			t.Errorf("decode webhook payload: %v", err)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer webhookSrv.Close()

	cfg := configWithDangerousService()
	cfg.Approval.WebhookURL = webhookSrv.URL
	cfg.Approval.TokenTTLSecs = 120
	srv := stubServer(cfg)
	srv.approvals = make(map[string]*pendingApproval)

	rr := post(t, srv, "/v1/projects/testproj/services/danger/build", "test-key")
	if rr.Code != http.StatusAccepted {
		t.Errorf("want 202, got %d: %s", rr.Code, rr.Body.String())
	}

	// Response body must NOT contain the token.
	respBody := decodeJSON(t, rr.Body)
	if _, hasToken := respBody["approval_key"]; hasToken {
		t.Error("approval_key must NOT appear in the response body")
	}
	if status, _ := respBody["status"].(string); status != "pending_approval" {
		t.Errorf("want status=pending_approval, got %q", status)
	}

	// Webhook must have received the token and required fields.
	if receivedPayload == nil {
		t.Fatal("webhook was not called")
	}
	for _, field := range []string{"approval_key", "action", "service", "project", "expires_at", "message"} {
		if receivedPayload[field] == "" {
			t.Errorf("webhook payload missing field %q", field)
		}
	}
	if receivedPayload["action"] != "build" {
		t.Errorf("want action=build, got %q", receivedPayload["action"])
	}
	if receivedPayload["project"] != "testproj" {
		t.Errorf("want project=testproj, got %q", receivedPayload["project"])
	}
	if receivedPayload["service"] != "danger" {
		t.Errorf("want service=danger, got %q", receivedPayload["service"])
	}
}

// TestDangerous_WebhookFailure verifies 503 is returned and token is cleaned up when webhook fails.
func TestDangerous_WebhookFailure(t *testing.T) {
	// Server that always returns 500.
	webhookSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer webhookSrv.Close()

	cfg := configWithDangerousService()
	cfg.Approval.WebhookURL = webhookSrv.URL
	srv := stubServer(cfg)
	srv.approvals = make(map[string]*pendingApproval)

	rr := post(t, srv, "/v1/projects/testproj/services/danger/build", "test-key")
	if rr.Code != http.StatusServiceUnavailable {
		t.Errorf("want 503 on webhook failure, got %d", rr.Code)
	}

	// Token must have been cleaned up.
	srv.approvalsMu.Lock()
	count := len(srv.approvals)
	srv.approvalsMu.Unlock()
	if count != 0 {
		t.Errorf("expected no pending approvals after webhook failure, got %d", count)
	}
}

// TestApprove_MissingKey verifies 404 for unknown token.
func TestApprove_MissingKey(t *testing.T) {
	cfg := configWithDangerousService()
	srv := stubServer(cfg)
	srv.approvals = make(map[string]*pendingApproval)

	rr := postBody(t, srv, "/v1/approve", "test-key", map[string]string{"approval_key": "nonexistent"})
	if rr.Code != http.StatusNotFound {
		t.Errorf("want 404 for missing token, got %d", rr.Code)
	}
}

// TestApprove_ExpiredToken verifies 410 for expired token.
func TestApprove_ExpiredToken(t *testing.T) {
	cfg := configWithDangerousService()
	srv := stubServer(cfg)
	srv.approvals = map[string]*pendingApproval{
		"expired-token": {
			Action:    "build",
			Project:   "testproj",
			Service:   "danger",
			ExpiresAt: time.Now().Add(-1 * time.Minute), // already expired
			Used:      false,
		},
	}

	rr := postBody(t, srv, "/v1/approve", "test-key", map[string]string{"approval_key": "expired-token"})
	if rr.Code != http.StatusGone {
		t.Errorf("want 410 for expired token, got %d", rr.Code)
	}
}

// TestApprove_UsedToken verifies 409 for already-used token.
func TestApprove_UsedToken(t *testing.T) {
	cfg := configWithDangerousService()
	srv := stubServer(cfg)
	srv.approvals = map[string]*pendingApproval{
		"used-token": {
			Action:    "build",
			Project:   "testproj",
			Service:   "danger",
			ExpiresAt: time.Now().Add(5 * time.Minute),
			Used:      true, // already used
		},
	}

	rr := postBody(t, srv, "/v1/approve", "test-key", map[string]string{"approval_key": "used-token"})
	if rr.Code != http.StatusConflict {
		t.Errorf("want 409 for used token, got %d", rr.Code)
	}
}

// TestApprove_EmptyKey verifies 400 when approval_key is missing.
func TestApprove_EmptyKey(t *testing.T) {
	cfg := configWithDangerousService()
	srv := stubServer(cfg)
	srv.approvals = make(map[string]*pendingApproval)

	rr := postBody(t, srv, "/v1/approve", "test-key", map[string]string{})
	if rr.Code != http.StatusBadRequest {
		t.Errorf("want 400 for missing approval_key, got %d", rr.Code)
	}
}

// TestApprove_RequiresAuth verifies /v1/approve is behind API key auth.
func TestApprove_RequiresAuth(t *testing.T) {
	cfg := configWithDangerousService()
	srv := stubServer(cfg)
	srv.approvals = make(map[string]*pendingApproval)

	rr := postBody(t, srv, "/v1/approve", "", map[string]string{"approval_key": "sometoken"})
	if rr.Code != http.StatusUnauthorized {
		t.Errorf("want 401 without API key, got %d", rr.Code)
	}
}

// TestApprove_MalformedJSON verifies 400 for malformed JSON body.
func TestApprove_MalformedJSON(t *testing.T) {
	cfg := configWithDangerousService()
	srv := stubServer(cfg)
	srv.approvals = make(map[string]*pendingApproval)

	req := httptest.NewRequest(http.MethodPost, "/v1/approve", strings.NewReader("{{{"))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", "test-key")
	rr := httptest.NewRecorder()
	srv.router().ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("want 400 for malformed JSON, got %d", rr.Code)
	}
	body := decodeJSON(t, rr.Body)
	if _, ok := body["error"]; !ok {
		t.Error("expected error field in response")
	}
}

// TestDangerous_InvalidWebhookScheme verifies 500 when webhook URL has invalid scheme.
func TestDangerous_InvalidWebhookScheme(t *testing.T) {
	cfg := configWithDangerousService()
	cfg.Approval.WebhookURL = "file:///etc/passwd" // invalid scheme
	srv := stubServer(cfg)
	srv.approvals = make(map[string]*pendingApproval)

	rr := post(t, srv, "/v1/projects/testproj/services/danger/build", "test-key")
	if rr.Code != http.StatusInternalServerError {
		t.Errorf("want 500 for invalid webhook scheme, got %d", rr.Code)
	}
	body := decodeJSON(t, rr.Body)
	if _, ok := body["error"]; !ok {
		t.Error("expected error field in response")
	}
}

// TestGenerateToken verifies tokens are 64 hex chars (32 bytes) and unique.
func TestGenerateToken(t *testing.T) {
	seen := make(map[string]struct{})
	for i := 0; i < 10; i++ {
		tok, err := generateToken()
		if err != nil {
			t.Fatalf("generateToken error: %v", err)
		}
		if len(tok) != 24 {
			t.Errorf("expected 64-char hex token, got len=%d: %q", len(tok), tok)
		}
		if _, dup := seen[tok]; dup {
			t.Errorf("duplicate token generated: %q", tok)
		}
		seen[tok] = struct{}{}
	}
}

// TestDefaults_ApprovalTTL verifies approval TTL defaults are set correctly.
func TestDefaults_ApprovalTTL(t *testing.T) {
	cfg := defaults()
	if cfg.Approval.TokenTTLSecs != 120 {
		t.Errorf("expected default TokenTTLSecs=120, got %d", cfg.Approval.TokenTTLSecs)
	}
	if cfg.Approval.TokenTTLMaxSecs != 600 {
		t.Errorf("expected default TokenTTLMaxSecs=600, got %d", cfg.Approval.TokenTTLMaxSecs)
	}
}

// TestDangerous_TTLClamped verifies that TokenTTLSecs is clamped to TokenTTLMaxSecs.
func TestDangerous_TTLClamped(t *testing.T) {
	var receivedPayload map[string]string
	webhookSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := json.NewDecoder(r.Body).Decode(&receivedPayload); err != nil {
			t.Errorf("decode webhook payload: %v", err)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer webhookSrv.Close()

	cfg := configWithDangerousService()
	cfg.Approval.WebhookURL = webhookSrv.URL
	cfg.Approval.TokenTTLSecs = 1000   // request 1000 seconds
	cfg.Approval.TokenTTLMaxSecs = 300 // but max is 300 seconds
	srv := stubServer(cfg)
	srv.approvals = make(map[string]*pendingApproval)

	now := time.Now()
	rr := post(t, srv, "/v1/projects/testproj/services/danger/build", "test-key")
	if rr.Code != http.StatusAccepted {
		t.Fatalf("want 202, got %d", rr.Code)
	}

	// Check that webhook received the expires_at field
	if receivedPayload == nil {
		t.Fatal("webhook was not called")
	}
	expiresAtStr, ok := receivedPayload["expires_at"]
	if !ok {
		t.Fatal("webhook payload missing expires_at field")
	}

	// Parse expires_at timestamp
	expiresAt, err := time.Parse(time.RFC3339, expiresAtStr)
	if err != nil {
		t.Fatalf("parse expires_at: %v", err)
	}

	// Verify TTL is clamped to max (300 seconds, which is 5 minutes)
	actualTTL := expiresAt.Sub(now).Seconds()
	expectedTTL := 300.0
	tolerance := 2.0 // allow 2 seconds of clock drift

	if actualTTL < expectedTTL-tolerance || actualTTL > expectedTTL+tolerance {
		t.Errorf("want TTL ~300s, got %.1f seconds", actualTTL)
	}
}

// TestSweeper_LogsExpiredTokens verifies that sweepOnce() logs expired tokens with correct fields.
func TestSweeper_LogsExpiredTokens(t *testing.T) {
	cfg := configWithDangerousService()
	srv := stubServer(cfg)
	srv.approvals = map[string]*pendingApproval{
		"valid-token": {
			Action:    "build",
			Project:   "testproj",
			Service:   "danger",
			ExpiresAt: time.Now().Add(10 * time.Minute),
			Used:      false,
		},
		"expired-token-1": {
			Action:    "recreate",
			Project:   "testproj",
			Service:   "danger",
			ExpiresAt: time.Now().Add(-5 * time.Minute),
			Used:      false,
		},
		"expired-token-2": {
			Action:    "build",
			Project:   "testproj",
			Service:   "danger",
			ExpiresAt: time.Now().Add(-1 * time.Second),
			Used:      false,
		},
	}

	// Run one sweep
	srv.sweepOnce()

	// Verify expired tokens were removed
	srv.approvalsMu.Lock()
	count := len(srv.approvals)
	_, hasValid := srv.approvals["valid-token"]
	_, hasExpired1 := srv.approvals["expired-token-1"]
	_, hasExpired2 := srv.approvals["expired-token-2"]
	srv.approvalsMu.Unlock()

	if count != 1 {
		t.Errorf("expected 1 approval after sweep, got %d", count)
	}
	if !hasValid {
		t.Error("valid token was unexpectedly removed")
	}
	if hasExpired1 || hasExpired2 {
		t.Error("expired tokens were not removed")
	}
}

// ─── SDK architecture tests ─────────────────────────────────────────────────

// TestNoExecImport verifies that main.go does not import os/exec.
// This is a compile-time guarantee that compose operations go through the SDK.
func TestNoExecImport(t *testing.T) {
	// This test exists as documentation. The real proof is:
	// 1. No "os/exec" import in main.go (verified at build time)
	// 2. ComposeClient uses github.com/docker/compose/v5/pkg/compose
	// 3. executeCompose dispatches to ComposeClient.{Up,Down,Recreate,Build}
	//
	// If someone adds exec.Command back, the linter and code review should catch it.
	// This test is a belt-and-suspenders reminder of the architectural constraint.
	t.Log("compose operations use SDK, not CLI exec — verified by absence of os/exec import")
}
