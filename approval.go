package main

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// handleDangerousAction intercepts a dangerous compose action and requests
// human approval via webhook before allowing execution.
func (s *Server) handleDangerousAction(w http.ResponseWriter, r *http.Request, action, project, service string) {
	if s.cfg.Approval.WebhookURL == "" {
		writeError(w, http.StatusForbidden, "dangerous action requires approval webhook to be configured")
		return
	}

	// Validate webhook URL scheme — must be http:// or https://
	if !strings.HasPrefix(s.cfg.Approval.WebhookURL, "http://") && !strings.HasPrefix(s.cfg.Approval.WebhookURL, "https://") {
		s.log.Error("invalid webhook URL scheme", "url", s.cfg.Approval.WebhookURL)
		writeError(w, http.StatusInternalServerError, "invalid webhook URL scheme")
		return
	}

	ttl := time.Duration(s.cfg.Approval.TokenTTLSecs) * time.Second
	maxTTL := time.Duration(s.cfg.Approval.TokenTTLMaxSecs) * time.Second
	if ttl > maxTTL {
		ttl = maxTTL
	}
	expiresAt := time.Now().Add(ttl)

	token, err := generateToken()
	if err != nil {
		s.log.Error("failed to generate approval token", "error", err)
		writeError(w, http.StatusInternalServerError, "failed to generate approval token")
		return
	}

	ap := &pendingApproval{
		Action:    action,
		Project:   project,
		Service:   service,
		ExpiresAt: expiresAt,
		Used:      false,
	}
	s.approvalsMu.Lock()
	s.approvals[token] = ap
	s.approvalsMu.Unlock()

	// POST to webhook.
	webhookPayload := map[string]string{
		"approval_key": token,
		"action":       action,
		"service":      service,
		"project":      project,
		"expires_at":   expiresAt.UTC().Format(time.RFC3339),
		"message":      fmt.Sprintf("Agent requested: docker compose %s %s", action, service),
	}
	payloadBytes, _ := json.Marshal(webhookPayload)

	webhookCtx, webhookCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer webhookCancel()

	req, err := http.NewRequestWithContext(webhookCtx, http.MethodPost, s.cfg.Approval.WebhookURL, bytes.NewReader(payloadBytes))
	if err != nil {
		s.approvalsMu.Lock()
		delete(s.approvals, token)
		s.approvalsMu.Unlock()
		s.log.Error("failed to build webhook request", "error", err)
		writeError(w, http.StatusServiceUnavailable, "failed to reach approval webhook")
		return
	}
	req.Header.Set("Content-Type", "application/json")
	if s.cfg.Approval.WebhookSecret != "" {
		mac := hmac.New(sha256.New, []byte(s.cfg.Approval.WebhookSecret))
		mac.Write(payloadBytes)
		sig := hex.EncodeToString(mac.Sum(nil))
		req.Header.Set("X-Safe-Docker-Signature", "sha256="+sig)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil || resp.StatusCode >= 500 {
		s.approvalsMu.Lock()
		delete(s.approvals, token)
		s.approvalsMu.Unlock()
		var reason string
		var detail string
		if err != nil {
			reason = err.Error()
			detail = "failed to reach approval webhook"
		} else {
			bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
			detail = strings.TrimSpace(string(bodyBytes))
			if detail == "" {
				detail = fmt.Sprintf("webhook returned %d", resp.StatusCode)
			}
			reason = fmt.Sprintf("webhook returned %d: %s", resp.StatusCode, detail)
			_ = resp.Body.Close()
		}
		s.log.Error("approval webhook error", "reason", reason)
		writeError(w, http.StatusServiceUnavailable, fmt.Sprintf("approval notification failed: %s", detail))
		return
	}
	_ = resp.Body.Close()

	s.log.Info("approval pending",
		"action", action,
		"project", project,
		"service", service,
		"expires_at", expiresAt.UTC().Format(time.RFC3339),
		"caller", callerFromContext(r.Context()),
	)

	writeJSON(w, http.StatusAccepted, map[string]string{
		"status":  "pending_approval",
		"message": "approval requested — waiting for human confirmation",
	})
}

// approveHandler handles POST /v1/approve — executes a previously approved action.
func (s *Server) approveHandler(w http.ResponseWriter, r *http.Request) {
	var body struct {
		ApprovalKey string `json:"approval_key"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || strings.TrimSpace(body.ApprovalKey) == "" {
		writeError(w, http.StatusBadRequest, "approval_key is required")
		return
	}
	token := body.ApprovalKey

	s.approvalsMu.Lock()
	ap, exists := s.approvals[token]
	if !exists {
		s.approvalsMu.Unlock()
		writeError(w, http.StatusNotFound, "approval token not found")
		return
	}
	if time.Now().After(ap.ExpiresAt) {
		delete(s.approvals, token)
		s.approvalsMu.Unlock()
		writeError(w, http.StatusGone, "approval token has expired")
		return
	}
	if ap.Used {
		s.approvalsMu.Unlock()
		writeError(w, http.StatusConflict, "approval token already used")
		return
	}

	// Mark used and copy fields before releasing the lock.
	ap.Used = true
	action := ap.Action
	project := ap.Project
	service := ap.Service
	s.approvalsMu.Unlock()

	// Execute via Compose SDK (no CLI exec).
	ctx, cancel := context.WithTimeout(r.Context(), time.Duration(s.cfg.Docker.TimeoutSeconds)*time.Second)
	defer cancel()

	// Get compose file path from project config (or use default)
	composeFile := ""
	if projectCfg, ok := s.cfg.Projects[project]; ok {
		composeFile = projectCfg.ComposeFile
	}

	var result ComposeResult
	switch action {
	case "recreate":
		result = s.compose.Recreate(ctx, project, service, composeFile)
	case "build":
		result = s.compose.Build(ctx, project, service, composeFile)
	default:
		writeError(w, http.StatusBadRequest, fmt.Sprintf("unsupported approved action: %s", action))
		return
	}

	if result.Error != nil {
		s.audit(r, "approve:"+action, service, "", "error", result.Error.Error())
		writeError(w, http.StatusBadGateway, action+" failed")
		return
	}

	s.audit(r, "approve:"+action, service, "", "success", "")
	writeJSON(w, http.StatusOK, map[string]any{
		"status":  "executed",
		"project": project,
		"service": service,
	})
}

// generateToken creates a cryptographically random 12-byte hex token.
func generateToken() (string, error) {
	// Keep approval tokens short enough to fit comfortably in Telegram callback_data
	// once prefixed (e.g. "build:confirm:<token>"). 12 random bytes = 24 hex chars.
	b := make([]byte, 12)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generate token: %w", err)
	}
	return hex.EncodeToString(b), nil
}

// sweepOnce performs one pass of cleanup, removing expired tokens from the approvals map.
// Used by the background ticker and testable for unit tests.
func (s *Server) sweepOnce() {
	now := time.Now()
	s.approvalsMu.Lock()
	for token, ap := range s.approvals {
		if now.After(ap.ExpiresAt) {
			tokenPrefix := token
			if len(token) > 8 {
				tokenPrefix = token[:8] + "…"
			}
			s.log.Info("approval expired",
				"token", tokenPrefix,
				"action", ap.Action,
				"service", ap.Service,
				"project", ap.Project,
			)
			delete(s.approvals, token)
		}
	}
	s.approvalsMu.Unlock()
}

// sweepExpiredApprovals periodically removes expired tokens from the approvals map.
func (s *Server) sweepExpiredApprovals() {
	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		s.sweepOnce()
	}
}
