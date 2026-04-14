// compose_client.go — Compose operations for safe-docker.
//
// safe-docker is a governance proxy for Docker Compose. It gates access to
// container lifecycle operations via policy and HITL approval. It can run
// on the host, inside the compose project it manages, or in a separate
// project managing one or many others.
//
// safe-docker uses the Compose SDK for project loading and container
// creation (networks, volumes, labels, dependency wiring) but deliberately
// suppresses the SDK's convergence engine. Convergence — where compose
// compares running containers against desired state and silently recreates
// diverged ones — is the opposite of governed access. A governance proxy
// should never mutate a container that wasn't explicitly asked about.
//
// Suppression requires two layers because the SDK's convergence is pervasive:
//
//  1. Project scoping (scopeProjectToService) — the project model passed to
//     the SDK is stripped to only the target service. Without this, the SDK
//     evaluates every service in the project and applies default convergence
//     (RecreateDiverged) to services outside the CreateOptions.Services filter.
//
//  2. RecreateNever — even for the target service, the SDK would detect config
//     hash divergence and rename-aside the container. RecreateNever suppresses
//     this for the one service we're operating on.
//
// Both are needed. RecreateNever alone still lets the SDK touch other services.
// Scoping alone still lets the SDK reconverge the target service.
//
// The config hash problem: the Compose SDK computes hashes from the caller's
// execution context (environment, working directory, compose-go version).
// When the context differs from the one that originally created the containers
// — which it will in any deployment where safe-docker isn't the host process
// that ran the initial `docker compose up` — the SDK sees every container as
// "diverged" and does a rename-aside + recreate cycle, producing phantoms.
//
// safe-docker's operations have different semantics from `docker compose`:
//
//   Up       — "Ensure this service has a running container."
//              Create if missing, start if stopped, no-op if running.
//              Never reconverges. Never detects config drift.
//
//   Down     — "Stop and remove this service's container."
//
//   Recreate — "Destroy and freshly create this service's container."
//              Requires HITL approval. Uses explicit Docker API removal
//              followed by compose create, bypassing rename-aside.
//
//   Build    — "Build this service's image."
//              Requires HITL approval.
//
// Config drift detection is not safe-docker's job. If an operator wants a
// fresh container, they go through the Recreate path with explicit approval.
package main

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"

	"github.com/compose-spec/compose-go/v2/cli"
	"github.com/compose-spec/compose-go/v2/types"
	"github.com/docker/cli/cli/command"
	"github.com/docker/cli/cli/flags"
	"github.com/docker/compose/v5/pkg/api"
	"github.com/docker/compose/v5/pkg/compose"
	mobycontainer "github.com/moby/moby/api/types/container"
	mobyclient "github.com/moby/moby/client"
)

const DefaultComposeFile = "/project/docker-compose.yml"

type ComposeClient struct {
	dockerCLI *command.DockerCli
	log       *slog.Logger
}

type ComposeServiceSummary struct {
	Name         string   `json:"name"`
	Image        string   `json:"image,omitempty"`
	HasBuild     bool     `json:"has_build"`
	BuildContext string   `json:"build_context,omitempty"`
	DependsOn    []string `json:"depends_on,omitempty"`
}

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

type ComposeResult struct {
	Output    string            `json:"output,omitempty"`
	Error     error             `json:"-"`
	Preflight *ComposePreflight `json:"preflight,omitempty"`
	Notes     []string          `json:"notes,omitempty"`
}

func NewComposeClient(socketPath string, log *slog.Logger) (*ComposeClient, error) {
	dockerCLI, err := command.NewDockerCli()
	if err != nil {
		return nil, fmt.Errorf("failed to create docker CLI: %w", err)
	}

	opts := &flags.ClientOptions{}
	if socketPath != "" && socketPath != "/var/run/docker.sock" {
		opts.Hosts = []string{"unix://" + socketPath}
	}

	if err := dockerCLI.Initialize(opts); err != nil {
		return nil, fmt.Errorf("failed to initialize docker CLI: %w", err)
	}

	return &ComposeClient{dockerCLI: dockerCLI, log: log}, nil
}

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

func (c *ComposeClient) runComposeCLI(ctx context.Context, projectName, composeFile string, args ...string) (string, error) {
	if composeFile == "" {
		composeFile = DefaultComposeFile
	}
	if pwd := strings.TrimSpace(os.Getenv("PWD")); pwd != "" && !strings.HasPrefix(composeFile, pwd+string(os.PathSeparator)) {
		candidate := filepath.Join(pwd, filepath.Base(composeFile))
		if _, err := os.Stat(candidate); err == nil {
			composeFile = candidate
		}
	}
	if _, err := os.Stat(composeFile); err != nil {
		return "", fmt.Errorf("compose file not found at %s: %w", composeFile, err)
	}
	projectDir := filepath.Dir(composeFile)
	cmdArgs := []string{"compose", "-p", projectName, "-f", composeFile}
	cmdArgs = append(cmdArgs, args...)
	cmd := exec.CommandContext(ctx, "docker", cmdArgs...)
	cmd.Dir = projectDir
	cmd.Env = os.Environ()
	output, err := cmd.CombinedOutput()
	return string(output), err
}

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

// Preflight inspects the compose project without executing any mutations.
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
			c.log.Debug("compose preflight image check failed", "project", projectName, "target_service", serviceName, "error", err)
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
			return types.Services{serviceName: svc}, nil
		}
	}
	return nil, fmt.Errorf("service %q not found in compose project %q", serviceName, project.Name)
}

// scopeProjectToService returns a shallow copy of the project containing only
// the target service with DependsOn cleared. This is necessary because the
// Compose SDK's convergence engine evaluates the full project graph on every
// Up call. RecreateNever only protects services listed in CreateOptions.Services
// — all other services in the project still get default RecreateDiverged
// treatment, causing phantom containers via rename-aside.
func scopeProjectToService(project *types.Project, serviceName string) (*types.Project, error) {
	for _, svc := range project.Services {
		if svc.Name == serviceName {
			svc.DependsOn = nil
			scoped := *project
			scoped.Services = types.Services{serviceName: svc}
			return &scoped, nil
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
		summary := ComposeServiceSummary{Name: svc.Name, Image: strings.TrimSpace(svc.Image), HasBuild: svc.Build != nil, DependsOn: dependsOn}
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
		_, err := dockerClient.ImageInspect(ctx, imageRef)
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
	attrs := []any{"action", action, "project", projectName, "service", serviceName, "compose_file", effectiveComposeFile(composeFile)}
	if preflight != nil {
		attrs = append(attrs, "loaded_project_name", preflight.LoadedProjectName, "target_service", preflight.TargetService, "requested_services", preflight.RequestedServices, "selected_services", preflight.SelectedServices, "project_services", preflight.ProjectServices, "missing_local_images", preflight.MissingLocalImages)
	}
	attrs = append(attrs, extra...)
	c.log.Debug("compose action starting", attrs...)
}

func (c *ComposeClient) logComposeResult(action, projectName, serviceName string, result ComposeResult) {
	if c.log == nil {
		return
	}
	attrs := []any{"action", action, "project", projectName, "service", serviceName, "output", compactComposeOutput(result.Output)}
	if result.Preflight != nil {
		attrs = append(attrs, "loaded_project_name", result.Preflight.LoadedProjectName, "missing_local_images", result.Preflight.MissingLocalImages)
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

// Up ensures the target service has a running container. If the container
// doesn't exist it is created; if it exists but is stopped it is started;
// if it is already running this is a no-op. Up never triggers convergence
// or config-drift detection — see file header for rationale.
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
	scoped, err := scopeProjectToService(project, serviceName)
	if err != nil {
		return ComposeResult{Error: err, Preflight: preflight}
	}
	service, output, err := c.newService()
	if err != nil {
		return ComposeResult{Error: err, Preflight: preflight}
	}
	// RecreateNever + scoped project: belt-and-suspenders against convergence.
	// Scoping hides other services from the SDK. RecreateNever prevents
	// reconvergence on the target service itself. See file header.
	err = service.Up(ctx, scoped, api.UpOptions{
		Create: api.CreateOptions{
			Services: []string{serviceName},
			Recreate: api.RecreateNever,
		},
		Start: api.StartOptions{Services: []string{serviceName}},
	})
	result := ComposeResult{Output: output.String(), Error: composeResultError(output.String(), err), Preflight: preflight}
	c.logComposeResult("up", projectName, serviceName, result)
	return result
}

// Down stops and removes the target service's container.
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
	err = service.Down(ctx, projectName, api.DownOptions{Services: []string{serviceName}})
	result := ComposeResult{Output: output.String(), Error: composeResultError(output.String(), err), Preflight: preflight}
	c.logComposeResult("down", projectName, serviceName, result)
	return result
}

// Recreate destroys and freshly recreates the target service's container.
// This is a dangerous action gated behind HITL approval. For this path we use
// the Docker Compose CLI directly to preserve normal Compose semantics/labels
// while still wrapping it in policy, auditing, and postcondition checks.
func (c *ComposeClient) Recreate(ctx context.Context, projectName, serviceName, composeFile string) ComposeResult {
	project, err := c.loadProject(ctx, projectName, composeFile)
	if err != nil {
		return ComposeResult{Error: err}
	}
	preflight, err := c.preflightProject(ctx, project, projectName, serviceName, composeFile)
	if err != nil {
		return ComposeResult{Error: err}
	}
	c.logComposeStart("recreate", projectName, serviceName, composeFile, preflight, "strategy", "docker_compose_cli_force_recreate")
	output, err := c.runComposeCLI(ctx, projectName, effectiveComposeFile(composeFile), "up", "-d", "--no-deps", "--force-recreate", serviceName)
	result := ComposeResult{
		Output:    output,
		Error:     composeResultError(output, err),
		Preflight: preflight,
		Notes:     []string{"Recreate uses `docker compose up -d --no-deps --force-recreate <service>` for Compose-native semantics, then verifies the resulting service container."},
	}
	if verified, verifyErr := c.listServiceContainers(ctx, projectName, serviceName); verifyErr != nil {
		if result.Error == nil {
			result.Error = fmt.Errorf("recreate postcondition failed: %w", verifyErr)
		} else {
			result.Error = fmt.Errorf("%w | recreate postcondition: %v", result.Error, verifyErr)
		}
	} else if len(verified) == 0 {
		postErr := fmt.Errorf("recreate did not produce a container for service %q in project %q", serviceName, projectName)
		if result.Error == nil {
			result.Error = postErr
		} else {
			result.Error = fmt.Errorf("%w | %v", result.Error, postErr)
		}
	}
	c.logComposeResult("recreate", projectName, serviceName, result)
	return result
}

// Build builds the target service's image. This is a dangerous action gated
// behind HITL approval.
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
	scoped, err := scopeProjectToService(project, serviceName)
	if err != nil {
		return ComposeResult{Error: err, Preflight: preflight}
	}
	service, output, err := c.newService()
	if err != nil {
		return ComposeResult{Error: err, Preflight: preflight}
	}
	err = service.Build(ctx, scoped, api.BuildOptions{Services: []string{serviceName}})
	result := ComposeResult{Output: output.String(), Error: composeResultError(output.String(), err), Preflight: preflight}
	c.logComposeResult("build", projectName, serviceName, result)
	return result
}

// BuildRecreate explicitly builds the service image and then force-recreates the
// service container in one Compose-native operation. This is a dangerous action
// gated behind HITL approval and requires both build + recreate permissions.
func (c *ComposeClient) BuildRecreate(ctx context.Context, projectName, serviceName, composeFile string) ComposeResult {
	project, err := c.loadProject(ctx, projectName, composeFile)
	if err != nil {
		return ComposeResult{Error: err}
	}
	preflight, err := c.preflightProject(ctx, project, projectName, serviceName, composeFile)
	if err != nil {
		return ComposeResult{Error: err}
	}
	c.logComposeStart("build_recreate", projectName, serviceName, composeFile, preflight, "strategy", "docker_compose_cli_build_force_recreate")
	output, err := c.runComposeCLI(ctx, projectName, effectiveComposeFile(composeFile), "up", "-d", "--no-deps", "--build", "--force-recreate", serviceName)
	result := ComposeResult{
		Output:    output,
		Error:     composeResultError(output, err),
		Preflight: preflight,
		Notes:     []string{"build_recreate uses `docker compose up -d --no-deps --build --force-recreate <service>` so the rebuilt image is applied immediately with Compose-native semantics, then verifies the resulting service container."},
	}
	if verified, verifyErr := c.listServiceContainers(ctx, projectName, serviceName); verifyErr != nil {
		if result.Error == nil {
			result.Error = fmt.Errorf("build_recreate postcondition failed: %w", verifyErr)
		} else {
			result.Error = fmt.Errorf("%w | build_recreate postcondition: %v", result.Error, verifyErr)
		}
	} else if len(verified) == 0 {
		postErr := fmt.Errorf("build_recreate did not produce a container for service %q in project %q", serviceName, projectName)
		if result.Error == nil {
			result.Error = postErr
		} else {
			result.Error = fmt.Errorf("%w | %v", result.Error, postErr)
		}
	}
	c.logComposeResult("build_recreate", projectName, serviceName, result)
	return result
}

func composeContainerName(c mobycontainer.Summary) string {
	for _, name := range c.Names {
		trimmed := strings.TrimSpace(strings.TrimPrefix(name, "/"))
		if trimmed != "" {
			return trimmed
		}
	}
	if len(c.ID) > 12 {
		return c.ID[:12]
	}
	return c.ID
}

func summarizeContainers(containers []mobycontainer.Summary) []string {
	summary := make([]string, 0, len(containers))
	for _, ctr := range containers {
		summary = append(summary, fmt.Sprintf("%s(state=%s,status=%s)", composeContainerName(ctr), ctr.State, ctr.Status))
	}
	sort.Strings(summary)
	return summary
}

func shouldCleanupRecreateContainer(c mobycontainer.Summary) bool {
	switch strings.ToLower(strings.TrimSpace(string(c.State))) {
	case "created", "exited", "dead":
		return true
	default:
		return false
	}
}

func (c *ComposeClient) listServiceContainers(ctx context.Context, projectName, serviceName string) ([]mobycontainer.Summary, error) {
	result, err := c.dockerCLI.Client().ContainerList(ctx, mobyclient.ContainerListOptions{All: true})
	if err != nil {
		return nil, fmt.Errorf("list service containers: %w", err)
	}
	matched := make([]mobycontainer.Summary, 0)
	for _, ctr := range result.Items {
		if ctr.Labels["com.docker.compose.project"] != projectName || ctr.Labels["com.docker.compose.service"] != serviceName {
			continue
		}
		matched = append(matched, ctr)
	}
	sort.Slice(matched, func(i, j int) bool {
		if matched[i].Created == matched[j].Created {
			return composeContainerName(matched[i]) < composeContainerName(matched[j])
		}
		return matched[i].Created < matched[j].Created
	})
	return matched, nil
}

func isNotFoundContainerErr(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "no such container") || strings.Contains(msg, "not found")
}

