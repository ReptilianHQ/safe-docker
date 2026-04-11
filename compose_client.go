package main

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/compose-spec/compose-go/v2/cli"
	"github.com/compose-spec/compose-go/v2/types"
	"github.com/docker/cli/cli/command"
	"github.com/docker/cli/cli/flags"
	imageapi "github.com/docker/docker/api/types/image"
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
	log       *slog.Logger
}

// ComposeServiceSummary is a compact description of a compose service for debug logging and preflight responses.
type ComposeServiceSummary struct {
	Name         string   `json:"name"`
	Image        string   `json:"image,omitempty"`
	HasBuild     bool     `json:"has_build"`
	BuildContext string   `json:"build_context,omitempty"`
	DependsOn    []string `json:"depends_on,omitempty"`
}

// ComposePreflight summarizes the compose project and obvious local-image issues before executing an action.
type ComposePreflight struct {
	Project            string                  `json:"project"`
	ComposeFile        string                  `json:"compose_file"`
	LoadedProjectName  string                  `json:"loaded_project_name"`
	TargetService      string                  `json:"target_service"`
	RequestedServices  []string                `json:"requested_services"`
	ProjectServices    []ComposeServiceSummary `json:"project_services"`
	SelectedServices   []ComposeServiceSummary `json:"selected_services"`
	MissingLocalImages []string                `json:"missing_local_images,omitempty"`
}

// ComposeResult holds the result of a compose operation.
type ComposeResult struct {
	Output    string            `json:"output,omitempty"`
	Error     error             `json:"-"`
	Preflight *ComposePreflight `json:"preflight,omitempty"`
}

// NewComposeClient creates a new Compose client using the Docker socket.
func NewComposeClient(socketPath string, log *slog.Logger) (*ComposeClient, error) {
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

	return &ComposeClient{dockerCLI: dockerCLI, log: log}, nil
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

func (c *ComposeClient) Preflight(ctx context.Context, projectName, serviceName, composeFile string) (*ComposePreflight, error) {
	project, err := c.loadProject(ctx, projectName, composeFile)
	if err != nil {
		return nil, err
	}
	return c.preflightProject(ctx, project, projectName, serviceName, composeFile)
}

func (c *ComposeClient) preflightProject(ctx context.Context, project *types.Project, projectName, serviceName, composeFile string) (*ComposePreflight, error) {
	selected, err := selectServices(project, serviceName)
	if err != nil {
		return nil, err
	}

	result := &ComposePreflight{
		Project:           projectName,
		ComposeFile:       effectiveComposeFile(composeFile),
		LoadedProjectName: project.Name,
		TargetService:     serviceName,
		RequestedServices: []string{serviceName},
		ProjectServices:   summarizeServices(project.Services),
		SelectedServices:  summarizeServices(selected),
	}

	missing, err := c.findMissingLocalImages(ctx, project.Services)
	if err != nil {
		if c.log != nil {
			c.log.Debug("compose preflight image check failed",
				"project", projectName,
				"target_service", serviceName,
				"error", err,
			)
		}
	} else {
		result.MissingLocalImages = missing
	}

	return result, nil
}

func effectiveComposeFile(composeFile string) string {
	if composeFile == "" {
		return DefaultComposeFile
	}
	return composeFile
}

func selectServices(project *types.Project, serviceName string) (types.Services, error) {
	for _, svc := range project.Services {
		if svc.Name == serviceName {
			return types.Services{svc}, nil
		}
	}
	return nil, fmt.Errorf("service %q not found in compose project %q", serviceName, project.Name)
}

func summarizeServices(services types.Services) []ComposeServiceSummary {
	summaries := make([]ComposeServiceSummary, 0, len(services))
	for _, svc := range services {
		dependsOn := make([]string, 0, len(svc.DependsOn))
		for dep := range svc.DependsOn {
			dependsOn = append(dependsOn, dep)
		}
		sort.Strings(dependsOn)

		summary := ComposeServiceSummary{
			Name:      svc.Name,
			Image:     strings.TrimSpace(svc.Image),
			HasBuild:  svc.Build != nil,
			DependsOn: dependsOn,
		}
		if svc.Build != nil {
			summary.BuildContext = svc.Build.Context
		}
		summaries = append(summaries, summary)
	}
	sort.Slice(summaries, func(i, j int) bool { return summaries[i].Name < summaries[j].Name })
	return summaries
}

func (c *ComposeClient) findMissingLocalImages(ctx context.Context, services types.Services) ([]string, error) {
	dockerClient := c.dockerCLI.Client()
	missingSet := make(map[string]struct{})
	for _, svc := range services {
		if svc.Build != nil {
			continue
		}
		imageRef := strings.TrimSpace(svc.Image)
		if imageRef == "" {
			continue
		}
		_, err := dockerClient.ImageInspect(ctx, imageRef, imageapi.InspectOptions{})
		if err != nil {
			if strings.Contains(strings.ToLower(err.Error()), "no such image") {
				missingSet[imageRef] = struct{}{}
				continue
			}
			return nil, fmt.Errorf("inspect image %q: %w", imageRef, err)
		}
	}

	missing := make([]string, 0, len(missingSet))
	for imageRef := range missingSet {
		missing = append(missing, imageRef)
	}
	sort.Strings(missing)
	return missing, nil
}

func (c *ComposeClient) logComposeStart(action, projectName, serviceName, composeFile string, preflight *ComposePreflight, extra ...any) {
	if c.log == nil {
		return
	}
	attrs := []any{
		"action", action,
		"project", projectName,
		"service", serviceName,
		"compose_file", effectiveComposeFile(composeFile),
	}
	if preflight != nil {
		attrs = append(attrs,
			"loaded_project_name", preflight.LoadedProjectName,
			"target_service", preflight.TargetService,
			"requested_services", preflight.RequestedServices,
			"selected_services", preflight.SelectedServices,
			"project_services", preflight.ProjectServices,
			"missing_local_images", preflight.MissingLocalImages,
		)
	}
	attrs = append(attrs, extra...)
	c.log.Debug("compose action starting", attrs...)
}

func (c *ComposeClient) logComposeResult(action, projectName, serviceName string, result ComposeResult) {
	if c.log == nil {
		return
	}
	attrs := []any{
		"action", action,
		"project", projectName,
		"service", serviceName,
		"output", compactComposeOutput(result.Output),
	}
	if result.Preflight != nil {
		attrs = append(attrs,
			"loaded_project_name", result.Preflight.LoadedProjectName,
			"missing_local_images", result.Preflight.MissingLocalImages,
		)
	}
	if result.Error != nil {
		attrs = append(attrs, "error", result.Error)
		c.log.Warn("compose action failed", attrs...)
		return
	}
	c.log.Debug("compose action completed", attrs...)
}

func composeResultError(output string, err error) error {
	if err == nil {
		return nil
	}
	trimmed := strings.TrimSpace(output)
	if trimmed == "" {
		return err
	}
	if strings.Contains(trimmed, err.Error()) {
		return err
	}
	return fmt.Errorf("%w | compose output: %s", err, compactComposeOutput(trimmed))
}

func compactComposeOutput(output string) string {
	output = strings.TrimSpace(output)
	if output == "" {
		return ""
	}
	lines := strings.Split(output, "\n")
	const maxLines = 20
	if len(lines) > maxLines {
		lines = append(lines[:maxLines], fmt.Sprintf("... (%d more lines)", len(lines)-maxLines))
	}
	joined := strings.Join(lines, "\n")
	const maxChars = 4000
	if len(joined) > maxChars {
		return joined[:maxChars] + "..."
	}
	return joined
}

// Up starts a service (docker compose up -d <service>).
func (c *ComposeClient) Up(ctx context.Context, projectName, serviceName, composeFile string) ComposeResult {
	project, err := c.loadProject(ctx, projectName, composeFile)
	if err != nil {
		return ComposeResult{Error: err}
	}
	preflight, err := c.preflightProject(ctx, project, projectName, serviceName, composeFile)
	if err != nil {
		return ComposeResult{Error: err}
	}
	c.logComposeStart("up", projectName, serviceName, composeFile, preflight)

	service, output, err := c.newService()
	if err != nil {
		return ComposeResult{Error: err, Preflight: preflight}
	}

	err = service.Up(ctx, project, api.UpOptions{
		Create: api.CreateOptions{
			Services: []string{serviceName},
		},
		Start: api.StartOptions{
			Services: []string{serviceName},
		},
	})

	result := ComposeResult{Output: output.String(), Error: composeResultError(output.String(), err), Preflight: preflight}
	c.logComposeResult("up", projectName, serviceName, result)
	return result
}

// Down stops a service (docker compose down <service>).
func (c *ComposeClient) Down(ctx context.Context, projectName, serviceName, composeFile string) ComposeResult {
	project, err := c.loadProject(ctx, projectName, composeFile)
	if err != nil {
		return ComposeResult{Error: err}
	}
	preflight, err := c.preflightProject(ctx, project, projectName, serviceName, composeFile)
	if err != nil {
		return ComposeResult{Error: err}
	}
	c.logComposeStart("down", projectName, serviceName, composeFile, preflight)

	service, output, err := c.newService()
	if err != nil {
		return ComposeResult{Error: err, Preflight: preflight}
	}

	err = service.Down(ctx, projectName, api.DownOptions{
		Services: []string{serviceName},
	})

	result := ComposeResult{Output: output.String(), Error: composeResultError(output.String(), err), Preflight: preflight}
	c.logComposeResult("down", projectName, serviceName, result)
	return result
}

// Recreate recreates a service (docker compose up -d --force-recreate <service>).
func (c *ComposeClient) Recreate(ctx context.Context, projectName, serviceName, composeFile string) ComposeResult {
	project, err := c.loadProject(ctx, projectName, composeFile)
	if err != nil {
		return ComposeResult{Error: err}
	}
	preflight, err := c.preflightProject(ctx, project, projectName, serviceName, composeFile)
	if err != nil {
		return ComposeResult{Error: err}
	}
	c.logComposeStart("recreate", projectName, serviceName, composeFile, preflight, "recreate_mode", string(api.RecreateForce))

	service, output, err := c.newService()
	if err != nil {
		return ComposeResult{Error: err, Preflight: preflight}
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

	result := ComposeResult{Output: output.String(), Error: composeResultError(output.String(), err), Preflight: preflight}
	c.logComposeResult("recreate", projectName, serviceName, result)
	return result
}

// Build builds a service image (docker compose build <service>).
func (c *ComposeClient) Build(ctx context.Context, projectName, serviceName, composeFile string) ComposeResult {
	project, err := c.loadProject(ctx, projectName, composeFile)
	if err != nil {
		return ComposeResult{Error: err}
	}
	preflight, err := c.preflightProject(ctx, project, projectName, serviceName, composeFile)
	if err != nil {
		return ComposeResult{Error: err}
	}
	c.logComposeStart("build", projectName, serviceName, composeFile, preflight)

	service, output, err := c.newService()
	if err != nil {
		return ComposeResult{Error: err, Preflight: preflight}
	}

	err = service.Build(ctx, project, api.BuildOptions{
		Services: []string{serviceName},
	})

	result := ComposeResult{Output: output.String(), Error: composeResultError(output.String(), err), Preflight: preflight}
	c.logComposeResult("build", projectName, serviceName, result)
	return result
}
