package main

import (
	"net/http"
	"slices"

	"github.com/go-chi/chi/v5"
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
