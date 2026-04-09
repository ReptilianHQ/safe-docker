package main

import (
	"net/http"
	"slices"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
)

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
