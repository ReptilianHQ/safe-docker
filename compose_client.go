package main

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/compose-spec/compose-go/v2/cli"
	"github.com/compose-spec/compose-go/v2/types"
	"github.com/docker/cli/cli/command"
	"github.com/docker/cli/cli/flags"
	"github.com/docker/compose/v5/pkg/api"
	"github.com/docker/compose/v5/pkg/compose"
)

// DefaultComposeFile is the default path where the compose file is mounted.
// Assumes project root is mounted at /project.
const DefaultComposeFile = "/project/docker-compose.yml"

// ComposeClient wraps the Docker Compose SDK for service operations.
// All operations go through the SDK — no CLI shelling.
type ComposeClient struct {
	dockerCLI *command.DockerCli
}

// NewComposeClient creates a new Compose client using the Docker socket.
func NewComposeClient(socketPath string) (*ComposeClient, error) {
	dockerCLI, err := command.NewDockerCli()
	if err != nil {
		return nil, fmt.Errorf("failed to create docker CLI: %w", err)
	}

	// Configure Docker host via client options, not environment
	opts := &flags.ClientOptions{}
	if socketPath != "" && socketPath != "/var/run/docker.sock" {
		opts.Hosts = []string{"unix://" + socketPath}
	}

	if err := dockerCLI.Initialize(opts); err != nil {
		return nil, fmt.Errorf("failed to initialize docker CLI: %w", err)
	}

	return &ComposeClient{dockerCLI: dockerCLI}, nil
}

// newService creates a fresh compose service with request-local output capture.
// Returns the service and the output buffer to read results from.
func (c *ComposeClient) newService() (api.Compose, *bytes.Buffer, error) {
	output := &bytes.Buffer{}
	service, err := compose.NewComposeService(c.dockerCLI,
		compose.WithOutputStream(output),
		compose.WithErrorStream(output),
		compose.WithPrompt(compose.AlwaysOkPrompt()),
	)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create compose service: %w", err)
	}
	return service, output, nil
}

// loadProject loads a Compose project from a compose file.
// It mirrors normal `docker compose` env resolution as closely as possible by:
//   - setting the working directory to the compose file's directory
//   - loading host OS env
//   - loading .env from the project directory when present
func (c *ComposeClient) loadProject(ctx context.Context, projectName, composeFile string) (*types.Project, error) {
	if composeFile == "" {
		composeFile = DefaultComposeFile
	}

	if _, err := os.Stat(composeFile); err != nil {
		return nil, fmt.Errorf("compose file not found at %s: %w", composeFile, err)
	}

	projectDir := filepath.Dir(composeFile)
	dotEnvPath := filepath.Join(projectDir, ".env")

	optionFns := []cli.ProjectOptionsFn{
		cli.WithName(projectName),
		cli.WithWorkingDirectory(projectDir),
		cli.WithOsEnv,
	}
	if _, err := os.Stat(dotEnvPath); err == nil {
		optionFns = append(optionFns, cli.WithEnvFiles(dotEnvPath))
	}
	optionFns = append(optionFns, cli.WithDotEnv)

	options, err := cli.NewProjectOptions([]string{composeFile}, optionFns...)
	if err != nil {
		return nil, fmt.Errorf("failed to create project options: %w", err)
	}

	project, err := cli.ProjectFromOptions(ctx, options)
	if err != nil {
		return nil, fmt.Errorf("failed to load project: %w", err)
	}

	return project, nil
}

// ComposeResult holds the result of a compose operation.
type ComposeResult struct {
	Output string
	Error  error
}

// Up starts a service (docker compose up -d <service>).
func (c *ComposeClient) Up(ctx context.Context, projectName, serviceName, composeFile string) ComposeResult {
	project, err := c.loadProject(ctx, projectName, composeFile)
	if err != nil {
		return ComposeResult{Error: err}
	}

	service, output, err := c.newService()
	if err != nil {
		return ComposeResult{Error: err}
	}

	err = service.Up(ctx, project, api.UpOptions{
		Create: api.CreateOptions{
			Services: []string{serviceName},
		},
		Start: api.StartOptions{
			Services: []string{serviceName},
		},
	})

	return ComposeResult{Output: output.String(), Error: err}
}

// Down stops a service (docker compose down <service>).
func (c *ComposeClient) Down(ctx context.Context, projectName, serviceName, composeFile string) ComposeResult {
	_, err := c.loadProject(ctx, projectName, composeFile)
	if err != nil {
		return ComposeResult{Error: err}
	}

	service, output, err := c.newService()
	if err != nil {
		return ComposeResult{Error: err}
	}

	err = service.Down(ctx, projectName, api.DownOptions{
		Services: []string{serviceName},
	})

	return ComposeResult{Output: output.String(), Error: err}
}

// Recreate recreates a service (docker compose up -d --force-recreate <service>).
func (c *ComposeClient) Recreate(ctx context.Context, projectName, serviceName, composeFile string) ComposeResult {
	project, err := c.loadProject(ctx, projectName, composeFile)
	if err != nil {
		return ComposeResult{Error: err}
	}

	service, output, err := c.newService()
	if err != nil {
		return ComposeResult{Error: err}
	}

	err = service.Up(ctx, project, api.UpOptions{
		Create: api.CreateOptions{
			Services: []string{serviceName},
			Recreate: api.RecreateForce,
		},
		Start: api.StartOptions{
			Services: []string{serviceName},
		},
	})

	return ComposeResult{Output: output.String(), Error: err}
}

// Build builds a service image (docker compose build <service>).
func (c *ComposeClient) Build(ctx context.Context, projectName, serviceName, composeFile string) ComposeResult {
	project, err := c.loadProject(ctx, projectName, composeFile)
	if err != nil {
		return ComposeResult{Error: err}
	}

	service, output, err := c.newService()
	if err != nil {
		return ComposeResult{Error: err}
	}

	err = service.Build(ctx, project, api.BuildOptions{
		Services: []string{serviceName},
	})

	return ComposeResult{Output: output.String(), Error: err}
}
