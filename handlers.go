package main

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/docker/docker/api/types/container"
	"github.com/go-chi/chi/v5"
)

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
		writeError(w, http.StatusBadGateway, "logs failed")
		return
	}
	defer func() { _ = reader.Close() }()
	payload, err := stripDockerMuxHeader(reader)
	if err != nil {
		s.audit(r, "logs", service, resolvedName, "error", err.Error())
		writeError(w, http.StatusBadGateway, "log decode failed")
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
	s.composeHandler(w, r, "up")
}

func (s *Server) downHandler(w http.ResponseWriter, r *http.Request) {
	s.composeHandler(w, r, "down")
}

func (s *Server) recreateHandler(w http.ResponseWriter, r *http.Request) {
	s.composeHandler(w, r, "recreate")
}

func (s *Server) buildHandler(w http.ResponseWriter, r *http.Request) {
	s.composeHandler(w, r, "build")
}

func (s *Server) composeHandler(w http.ResponseWriter, r *http.Request, action string) {
	project, service, _, ok := s.authorizeAction(w, r, action)
	if !ok {
		return
	}

	// Intercept dangerous actions for HITL approval.
	if _, isDangerous := dangerousActions[action]; isDangerous {
		s.handleDangerousAction(w, r, action, project, service)
		return
	}

	s.executeCompose(w, r, action, project, service)
}

// executeCompose runs compose operations via the SDK (no CLI exec).
// Used by both composeHandler (non-dangerous) and approveHandler (post-approval).
func (s *Server) executeCompose(w http.ResponseWriter, r *http.Request, action, project, service string) {
	ctx, cancel := context.WithTimeout(r.Context(), time.Duration(s.cfg.Docker.TimeoutSeconds)*time.Second)
	defer cancel()

	// Get compose file path from project config (or use default)
	composeFile := ""
	if projectCfg, ok := s.cfg.Projects[project]; ok {
		composeFile = projectCfg.ComposeFile
	}

	var result ComposeResult
	switch action {
	case "up":
		result = s.compose.Up(ctx, project, service, composeFile)
	case "down":
		result = s.compose.Down(ctx, project, service, composeFile)
	case "recreate":
		result = s.compose.Recreate(ctx, project, service, composeFile)
	case "build":
		result = s.compose.Build(ctx, project, service, composeFile)
	default:
		writeError(w, http.StatusBadRequest, fmt.Sprintf("unsupported compose action: %s", action))
		return
	}

	if result.Error != nil {
		s.audit(r, action, service, "", "error", result.Error.Error())
		writeError(w, http.StatusBadGateway, action+" failed")
		return
	}
	s.audit(r, action, service, "", "success", "")
	writeJSON(w, http.StatusOK, map[string]any{
		"project": project,
		"service": service,
		"status":  action + " completed",
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
		writeError(w, http.StatusBadGateway, action+" failed")
		return
	}
	s.audit(r, action, service, resolvedName, "success", "")
	writeJSON(w, http.StatusOK, map[string]string{"project": project, "service": service, "container": resolvedName, "status": action + "ed"})
}
