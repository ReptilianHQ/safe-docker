package main

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
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
		0x01,                   // stdout
		0x00, 0x00, 0x00,       // padding
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
