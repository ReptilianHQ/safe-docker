package main

import (
	"fmt"
	"io"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

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

// composeActions are actions that require a compose file (handled via the Compose SDK).
var composeActions = map[string]struct{}{
	"up":       {},
	"down":     {},
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
	ComposeFile string                   `yaml:"compose_file"` // Required when any service uses compose actions. Use the host path (e.g. ${PWD}/docker-compose.yml).
	Services    map[string]ServicePolicy `yaml:"services"`
}

type ServerConfig struct {
	ListenAddr string `yaml:"listen_addr"`
}

type DockerConfig struct {
	SocketPath     string `yaml:"socket_path"`
	TimeoutSeconds int    `yaml:"timeout_seconds"`
	LogTailDefault   int `yaml:"log_tail_default"`
	LogTailMax       int `yaml:"log_tail_max"`
	RateLimitSeconds int `yaml:"rate_limit_seconds"`
}

type AuthConfig struct {
	AuthorizedCallers []string `yaml:"authorized_callers"`
	TokenSecretEnv    string   `yaml:"token_secret_env"`
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
	WebhookSecret   string `yaml:"webhook_secret"`
	TokenTTLSecs    int    `yaml:"token_ttl_seconds"`
	TokenTTLMaxSecs int    `yaml:"token_ttl_max_seconds"`
}

// pendingApproval holds state for a dangerous action awaiting human sign-off.
type pendingApproval struct {
	Action         string
	Project        string
	Service        string
	WebhookContext map[string]any
	ExpiresAt      time.Time
	Used           bool
}

func defaults() Config {
	return Config{
		Server: ServerConfig{ListenAddr: "127.0.0.1:8080"},
		Docker: DockerConfig{
			SocketPath:       "/var/run/docker.sock",
			TimeoutSeconds:   15,
			LogTailDefault:   100,
			LogTailMax:       500,
			RateLimitSeconds: 10,
		},
		Auth:     AuthConfig{TokenSecretEnv: "SAFE_DOCKER_AUTH_SECRET"},
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
	// Env var override: SAFE_DOCKER_RATE_LIMIT_SECONDS
	if v := os.Getenv("SAFE_DOCKER_RATE_LIMIT_SECONDS"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil {
			return cfg, fmt.Errorf("SAFE_DOCKER_RATE_LIMIT_SECONDS: %w", err)
		}
		cfg.Docker.RateLimitSeconds = n
	}

	if err := cfg.validate(); err != nil {
		return cfg, err
	}
	return cfg, nil
}

func (c *Config) validate() error {
	if len(c.Auth.AuthorizedCallers) == 0 {
		return fmt.Errorf("auth.authorized_callers must contain at least one caller")
	}
	seenCallers := map[string]struct{}{}
	for _, caller := range c.Auth.AuthorizedCallers {
		caller = strings.TrimSpace(caller)
		if caller == "" {
			return fmt.Errorf("auth.authorized_callers cannot contain empty values")
		}
		if _, exists := seenCallers[caller]; exists {
			return fmt.Errorf("auth.authorized_callers contains duplicate caller %q", caller)
		}
		seenCallers[caller] = struct{}{}
	}
	if strings.TrimSpace(c.Auth.TokenSecretEnv) == "" {
		return fmt.Errorf("auth.token_secret_env is required")
	}
	if strings.TrimSpace(os.Getenv(c.Auth.TokenSecretEnv)) == "" {
		return fmt.Errorf("auth.token_secret_env %q is not set", c.Auth.TokenSecretEnv)
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
		needsCompose := false
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
				if _, isCompose := composeActions[action]; isCompose {
					needsCompose = true
				}
			}
		}
		if needsCompose && strings.TrimSpace(projectCfg.ComposeFile) == "" {
			return fmt.Errorf("projects.%s.compose_file is required when any service uses compose actions (up/down/recreate/build)", project)
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
