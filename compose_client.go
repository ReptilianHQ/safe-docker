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
// This also avoids a practical problem: the Compose SDK computes config
// hashes from the caller's execution context (environment, working
// directory, compose-go version). When the caller's context differs from
// the one that originally created the containers — which it will in any
// deployment where safe-docker isn't the host process that ran the initial
// `docker compose up` — the SDK sees every container as "diverged" and
// does a rename-aside + recreate cycle, producing phantom containers.
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
	"encoding/json"
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

const (
	ComposeBackendSDK = "sdk"
	ComposeBackendCLI = "cli"
)

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

type ComposeDebug struct {
	Backend            string   `json:"backend"`
	Command            []string `json:"command,omitempty"`
	ApproximateDryRun  bool     `json:"approximate_dry_run,omitempty"`
	IsRealDryRun       bool     `json:"is_real_dry_run,omitempty"`
	Notes              []string `json:"notes,omitempty"`
	ConfigCommand      []string `json:"config_command,omitempty"`
	PSCommand          []string `json:"ps_command,omitempty"`
	WorkingDir         string   `json:"working_dir,omitempty"`
	ComposeFile        string   `json:"compose_file,omitempty"`
	LoadedProjectName  string   `json:"loaded_project_name,omitempty"`
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
	Debug              *ComposeDebug           `json:"debug,omitempty"`
	ConfigOutput       string                  `json:"config_output,omitempty"`
	PSOutput           string                  `json:"ps_output,omitempty"`
}

type ComposeResult struct {
	Output    string        `json:"output,omitempty"`
	Error     error         `json:"-"`
	Preflight *ComposePreflight `json:"preflight,omitempty"`
	Debug     *ComposeDebug `json:"debug,omitempty"`
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

func (c *ComposeClient) Preflight(ctx context.Context, backend, action, projectName, serviceName, composeFile string) (*ComposePreflight, error) {
	if backend == ComposeBackendCLI {
		return c.cliPreflight(ctx, action, projectName, serviceName, composeFile)
	}
	project, err := c.loadProject(ctx, projectName, composeFile)
	if err != nil {
		return nil, err
	}
	return c.preflightProject(ctx, project, projectName, serviceName, composeFile, &ComposeDebug{
		Backend:           ComposeBackendSDK,
		Command:           composeActionCommandPreview(action, projectName, serviceName, composeFile),
		ApproximateDryRun: false,
		IsRealDryRun:      false,
		Notes:             []string{"SDK preflight inspects the compose project in-process; no compose action was executed."},
		WorkingDir:        filepath.Dir(effectiveComposeFile(composeFile)),
		ComposeFile:       effectiveComposeFile(composeFile),
	})
}

func (c *ComposeClient) preflightProject(ctx context.Context, project *types.Project, projectName, serviceName, composeFile string, debug *ComposeDebug) (*ComposePreflight, error) {
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
		Debug:             debug,
	}
	if result.Debug != nil && result.Debug.LoadedProjectName == "" {
		result.Debug.LoadedProjectName = project.Name
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

func (c *ComposeClient) cliPreflight(ctx context.Context, action, projectName, serviceName, composeFile string) (*ComposePreflight, error) {
	project, err := c.loadProject(ctx, projectName, composeFile)
	if err != nil {
		return nil, err
	}
	workDir := filepath.Dir(effectiveComposeFile(composeFile))
	configCmd := composeCLICommand(projectName, serviceName, composeFile, "config", "--format", "json")
	psCmd := composeCLICommand(projectName, serviceName, composeFile, "ps", "--all", "--format", "json", serviceName)
	debug := &ComposeDebug{
		Backend:           ComposeBackendCLI,
		Command:           composeActionCommandPreview(action, projectName, serviceName, composeFile),
		ApproximateDryRun: true,
		IsRealDryRun:      false,
		Notes: []string{
			"CLI preflight is an approximation, not a true docker compose dry-run.",
			"It runs safe diagnostic commands only: docker compose config and docker compose ps --all.",
			"No approval is requested and no mutating compose action is executed during preflight.",
		},
		ConfigCommand: configCmd,
		PSCommand:     psCmd,
		WorkingDir:    workDir,
		ComposeFile:   effectiveComposeFile(composeFile),
	}
	preflight, err := c.preflightProject(ctx, project, projectName, serviceName, composeFile, debug)
	if err != nil {
		return nil, err
	}
	configOut, err := c.runComposeCLI(ctx, workDir, configCmd)
	if err != nil {
		return nil, err
	}
	preflight.ConfigOutput = compactComposeOutput(configOut)
	psOut, err := c.runComposeCLI(ctx, workDir, psCmd)
	if err != nil {
		return nil, err
	}
	preflight.PSOutput = compactComposeOutput(psOut)
	return preflight, nil
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

func (c *ComposeClient) logComposeStart(action, backend, projectName, serviceName, composeFile string, preflight *ComposePreflight, extra ...any) {
	if c.log == nil {
		return
	}
	attrs := []any{"action", action, "backend", backend, "project", projectName, "service", serviceName, "compose_file", effectiveComposeFile(composeFile)}
	if preflight != nil {
		attrs = append(attrs, "loaded_project_name", preflight.LoadedProjectName, "target_service", preflight.TargetService, "requested_services", preflight.RequestedServices, "selected_services", preflight.SelectedServices, "project_services", preflight.ProjectServices, "missing_local_images", preflight.MissingLocalImages)
	}
	attrs = append(attrs, extra...)
	c.log.Debug("compose action starting", attrs...)
}

func (c *ComposeClient) logComposeResult(action, backend, projectName, serviceName string, result ComposeResult) {
	if c.log == nil {
		return
	}
	attrs := []any{"action", action, "backend", backend, "project", projectName, "service", serviceName, "output", compactComposeOutput(result.Output), "debug", result.Debug}
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

func composeCLICommand(projectName, serviceName, composeFile string, args ...string) []string {
	base := []string{"docker", "compose", "-f", effectiveComposeFile(composeFile), "-p", projectName}
	return append(base, args...)
}

func composeActionCommandPreview(action, projectName, serviceName, composeFile string) []string {
	switch action {
	case "up":
		return composeCLICommand(projectName, serviceName, composeFile, "up", "-d", serviceName)
	case "down":
		return composeCLICommand(projectName, serviceName, composeFile, "down", serviceName)
	case "recreate":
		return composeCLICommand(projectName, serviceName, composeFile, "up", "-d", "--force-recreate", serviceName)
	case "build":
		return composeCLICommand(projectName, serviceName, composeFile, "build", serviceName)
	default:
		return composeCLICommand(projectName, serviceName, composeFile, action, serviceName)
	}
}

func (c *ComposeClient) runComposeCLI(ctx context.Context, workDir string, command []string) (string, error) {
	if len(command) == 0 {
		return "", fmt.Errorf("empty command")
	}
	cmd := exec.CommandContext(ctx, command[0], command[1:]...)
	cmd.Dir = workDir
	cmd.Env = os.Environ()
	output, err := cmd.CombinedOutput()
	out := string(output)
	if err != nil {
		return out, composeResultError(out, fmt.Errorf("compose CLI command failed: %w", err))
	}
	return out, nil
}

// Up ensures the target service has a running container. If the container
// doesn't exist it is created; if it exists but is stopped it is started;
// if it is already running this is a no-op. Up never triggers convergence
// or config-drift detection — see file header for rationale.
func (c *ComposeClient) Up(ctx context.Context, backend, projectName, serviceName, composeFile string) ComposeResult {
	if backend == ComposeBackendCLI {
		return c.cliAction(ctx, "up", projectName, serviceName, composeFile)
	}
	return c.sdkUp(ctx, projectName, serviceName, composeFile)
}

// Down stops and removes the target service's container.
func (c *ComposeClient) Down(ctx context.Context, backend, projectName, serviceName, composeFile string) ComposeResult {
	if backend == ComposeBackendCLI {
		return c.cliAction(ctx, "down", projectName, serviceName, composeFile)
	}
	return c.sdkDown(ctx, projectName, serviceName, composeFile)
}

// Recreate destroys the target service's container and creates a fresh one.
// This is a dangerous action gated behind HITL approval. The SDK path uses
// explicit Docker API removal followed by a compose Up with RecreateNever,
// bypassing the SDK's rename-aside cycle entirely.
func (c *ComposeClient) Recreate(ctx context.Context, backend, projectName, serviceName, composeFile string) ComposeResult {
	if backend == ComposeBackendCLI {
		return c.cliAction(ctx, "recreate", projectName, serviceName, composeFile)
	}
	return c.sdkRecreate(ctx, projectName, serviceName, composeFile)
}

// Build builds the target service's image. This is a dangerous action gated
// behind HITL approval.
func (c *ComposeClient) Build(ctx context.Context, backend, projectName, serviceName, composeFile string) ComposeResult {
	if backend == ComposeBackendCLI {
		return c.cliAction(ctx, "build", projectName, serviceName, composeFile)
	}
	return c.sdkBuild(ctx, projectName, serviceName, composeFile)
}

func (c *ComposeClient) cliAction(ctx context.Context, action, projectName, serviceName, composeFile string) ComposeResult {
	preflight, err := c.cliPreflight(ctx, action, projectName, serviceName, composeFile)
	if err != nil {
		return ComposeResult{Error: err}
	}
	command := composeActionCommandPreview(action, projectName, serviceName, composeFile)
	debug := &ComposeDebug{Backend: ComposeBackendCLI, Command: command, WorkingDir: filepath.Dir(effectiveComposeFile(composeFile)), ComposeFile: effectiveComposeFile(composeFile), LoadedProjectName: preflight.LoadedProjectName}
	c.logComposeStart(action, ComposeBackendCLI, projectName, serviceName, composeFile, preflight, "command", command)
	output, err := c.runComposeCLI(ctx, debug.WorkingDir, command)
	result := ComposeResult{Output: output, Error: err, Preflight: preflight, Debug: debug}
	c.logComposeResult(action, ComposeBackendCLI, projectName, serviceName, result)
	return result
}

func (c *ComposeClient) sdkUp(ctx context.Context, projectName, serviceName, composeFile string) ComposeResult {
	project, err := c.loadProject(ctx, projectName, composeFile)
	if err != nil {
		return ComposeResult{Error: err}
	}
	debug := &ComposeDebug{Backend: ComposeBackendSDK, Command: composeActionCommandPreview("up", projectName, serviceName, composeFile), WorkingDir: filepath.Dir(effectiveComposeFile(composeFile)), ComposeFile: effectiveComposeFile(composeFile), LoadedProjectName: project.Name}
	preflight, err := c.preflightProject(ctx, project, projectName, serviceName, composeFile, debug)
	if err != nil {
		return ComposeResult{Error: err}
	}
	c.logComposeStart("up", ComposeBackendSDK, projectName, serviceName, composeFile, preflight)
	service, output, err := c.newService()
	if err != nil {
		return ComposeResult{Error: err, Preflight: preflight, Debug: debug}
	}
	// RecreateNever: Up means "ensure running", not "converge to desired state".
	// Convergence is suppressed in all deployment modes — see file header.
	err = service.Up(ctx, project, api.UpOptions{
		Create: api.CreateOptions{
			Services: []string{serviceName},
			Recreate: api.RecreateNever,
		},
		Start: api.StartOptions{Services: []string{serviceName}},
	})
	result := ComposeResult{Output: output.String(), Error: composeResultError(output.String(), err), Preflight: preflight, Debug: debug}
	c.logComposeResult("up", ComposeBackendSDK, projectName, serviceName, result)
	return result
}

func (c *ComposeClient) sdkDown(ctx context.Context, projectName, serviceName, composeFile string) ComposeResult {
	project, err := c.loadProject(ctx, projectName, composeFile)
	if err != nil {
		return ComposeResult{Error: err}
	}
	debug := &ComposeDebug{Backend: ComposeBackendSDK, Command: composeActionCommandPreview("down", projectName, serviceName, composeFile), WorkingDir: filepath.Dir(effectiveComposeFile(composeFile)), ComposeFile: effectiveComposeFile(composeFile), LoadedProjectName: project.Name}
	preflight, err := c.preflightProject(ctx, project, projectName, serviceName, composeFile, debug)
	if err != nil {
		return ComposeResult{Error: err}
	}
	c.logComposeStart("down", ComposeBackendSDK, projectName, serviceName, composeFile, preflight)
	service, output, err := c.newService()
	if err != nil {
		return ComposeResult{Error: err, Preflight: preflight, Debug: debug}
	}
	err = service.Down(ctx, projectName, api.DownOptions{Services: []string{serviceName}})
	result := ComposeResult{Output: output.String(), Error: composeResultError(output.String(), err), Preflight: preflight, Debug: debug}
	c.logComposeResult("down", ComposeBackendSDK, projectName, serviceName, result)
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

func (c *ComposeClient) removeServiceContainers(ctx context.Context, projectName, serviceName string, containers []mobycontainer.Summary, reason string) error {
	for _, ctr := range containers {
		name := composeContainerName(ctr)
		if c.log != nil {
			c.log.Debug("compose recreate removing existing container", "project", projectName, "service", serviceName, "container_id", ctr.ID, "container", name, "state", ctr.State, "status", ctr.Status, "reason", reason)
		}
		if _, err := c.dockerCLI.Client().ContainerRemove(ctx, ctr.ID, mobyclient.ContainerRemoveOptions{Force: true}); err != nil && !isNotFoundContainerErr(err) {
			return fmt.Errorf("remove container %s: %w", name, err)
		}
	}
	return nil
}

func (c *ComposeClient) cleanupRecreateArtifacts(ctx context.Context, projectName, serviceName string, preserveIDs map[string]struct{}) ([]string, error) {
	containers, err := c.listServiceContainers(ctx, projectName, serviceName)
	if err != nil {
		return nil, err
	}
	removed := make([]string, 0)
	for _, ctr := range containers {
		if _, ok := preserveIDs[ctr.ID]; ok {
			continue
		}
		if !shouldCleanupRecreateContainer(ctr) {
			continue
		}
		name := composeContainerName(ctr)
		if _, err := c.dockerCLI.Client().ContainerRemove(ctx, ctr.ID, mobyclient.ContainerRemoveOptions{Force: true}); err != nil {
			if isNotFoundContainerErr(err) {
				continue
			}
			return removed, fmt.Errorf("remove stale container %s: %w", name, err)
		}
		removed = append(removed, name)
	}
	sort.Strings(removed)
	return removed, nil
}

func (c *ComposeClient) sdkRecreate(ctx context.Context, projectName, serviceName, composeFile string) ComposeResult {
	project, err := c.loadProject(ctx, projectName, composeFile)
	if err != nil {
		return ComposeResult{Error: err}
	}
	debug := &ComposeDebug{Backend: ComposeBackendSDK, Command: composeActionCommandPreview("recreate", projectName, serviceName, composeFile), WorkingDir: filepath.Dir(effectiveComposeFile(composeFile)), ComposeFile: effectiveComposeFile(composeFile), LoadedProjectName: project.Name, Notes: []string{"Recreate uses explicit Docker API removal then compose Up with RecreateNever, bypassing the SDK's rename-aside cycle."}}
	preflight, err := c.preflightProject(ctx, project, projectName, serviceName, composeFile, debug)
	if err != nil {
		return ComposeResult{Error: err}
	}
	c.logComposeStart("recreate", ComposeBackendSDK, projectName, serviceName, composeFile, preflight, "strategy", "remove_then_up")
	// Containers were already removed by Recreate() before calling this method.
	// The SDK sees "container missing" and creates a fresh one with proper
	// compose semantics (networks, volumes, labels).
	service, output, err := c.newService()
	if err != nil {
		return ComposeResult{Error: err, Preflight: preflight, Debug: debug}
	}
	err = service.Up(ctx, project, api.UpOptions{
		Create: api.CreateOptions{
			Services: []string{serviceName},
			Recreate: api.RecreateNever,
		},
		Start: api.StartOptions{Services: []string{serviceName}},
	})
	result := ComposeResult{Output: output.String(), Error: composeResultError(output.String(), err), Preflight: preflight, Debug: debug}
	removedArtifacts, cleanupErr := c.cleanupRecreateArtifacts(ctx, projectName, serviceName, nil)
	if len(removedArtifacts) > 0 {
		result.Output = strings.TrimSpace(result.Output + "\ncleanup removed stale containers: " + strings.Join(removedArtifacts, ", "))
	}
	if cleanupErr != nil {
		if c.log != nil {
			c.log.Warn("compose recreate cleanup failed", "project", projectName, "service", serviceName, "error", cleanupErr)
		}
		if result.Error == nil {
			result.Error = cleanupErr
		} else {
			result.Error = fmt.Errorf("%w | recreate cleanup: %v", result.Error, cleanupErr)
		}
	}
	c.logComposeResult("recreate", ComposeBackendSDK, projectName, serviceName, result)
	return result
}

func (c *ComposeClient) sdkBuild(ctx context.Context, projectName, serviceName, composeFile string) ComposeResult {
	project, err := c.loadProject(ctx, projectName, composeFile)
	if err != nil {
		return ComposeResult{Error: err}
	}
	debug := &ComposeDebug{Backend: ComposeBackendSDK, Command: composeActionCommandPreview("build", projectName, serviceName, composeFile), WorkingDir: filepath.Dir(effectiveComposeFile(composeFile)), ComposeFile: effectiveComposeFile(composeFile), LoadedProjectName: project.Name}
	preflight, err := c.preflightProject(ctx, project, projectName, serviceName, composeFile, debug)
	if err != nil {
		return ComposeResult{Error: err}
	}
	c.logComposeStart("build", ComposeBackendSDK, projectName, serviceName, composeFile, preflight)
	service, output, err := c.newService()
	if err != nil {
		return ComposeResult{Error: err, Preflight: preflight, Debug: debug}
	}
	err = service.Build(ctx, project, api.BuildOptions{Services: []string{serviceName}})
	result := ComposeResult{Output: output.String(), Error: composeResultError(output.String(), err), Preflight: preflight, Debug: debug}
	c.logComposeResult("build", ComposeBackendSDK, projectName, serviceName, result)
	return result
}

func dockerComposePluginPresent() bool {
	paths := []string{
		"/usr/local/lib/docker/cli-plugins/docker-compose",
		"/usr/libexec/docker/cli-plugins/docker-compose",
	}
	for _, path := range paths {
		if info, err := os.Stat(path); err == nil && !info.IsDir() {
			return true
		}
	}
	return false
}

func cliBackendHealth() map[string]any {
	status := "missing"
	if dockerComposePluginPresent() {
		status = "present"
	}
	return map[string]any{"docker_compose_plugin": status}
}

func decodeCLIConfigServices(configOutput string) []string {
	var cfg struct {
		Services map[string]json.RawMessage `json:"services"`
	}
	if err := json.Unmarshal([]byte(configOutput), &cfg); err != nil {
		return nil
	}
	services := make([]string, 0, len(cfg.Services))
	for name := range cfg.Services {
		services = append(services, name)
	}
	sort.Strings(services)
	return services
}
