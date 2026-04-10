package main

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
)

type signedCallerToken struct {
	Caller string `json:"caller"`
	Aud    string `json:"aud,omitempty"`
	Iat    int64  `json:"iat,omitempty"`
	Exp    int64  `json:"exp,omitempty"`
	V      int    `json:"v"`
}

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
	if cooldown := s.cfg.Docker.RateLimitSeconds; cooldown > 0 && action != "status" && action != "logs" {
		key := project + "/" + service
		limit := time.Duration(cooldown) * time.Second
		s.rateMu.Lock()
		last, exists := s.lastAction[key]
		if exists && time.Since(last) < limit {
			s.rateMu.Unlock()
			remaining := limit - time.Since(last)
			s.audit(r, action, service, policy.Container, "denied", "rate limited")
			writeError(w, http.StatusTooManyRequests, fmt.Sprintf("rate limited — retry in %ds", int(remaining.Seconds())+1))
			return "", "", policy, false
		}
		s.lastAction[key] = time.Now()
		s.rateMu.Unlock()
	}
	return project, service, policy, true
}

func methodForAction(action string) string {
	if action == "status" || action == "logs" {
		return http.MethodGet
	}
	return http.MethodPost
}

func (s *Server) requireAPIKey(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := strings.TrimSpace(r.Header.Get("X-API-Key"))
		if token == "" {
			writeError(w, http.StatusUnauthorized, "X-API-Key header required")
			return
		}
		caller, err := s.authenticateCallerToken(token)
		if err != nil {
			writeError(w, http.StatusForbidden, "invalid API key")
			return
		}
		ctx := context.WithValue(r.Context(), callerContextKey{}, caller)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

type callerContextKey struct{}

func callerFromContext(ctx context.Context) string {
	caller, _ := ctx.Value(callerContextKey{}).(string)
	if caller == "" {
		return "unknown"
	}
	return caller
}

func canonicalTokenPayload(tok signedCallerToken) ([]byte, error) {
	m := map[string]any{
		"caller": tok.Caller,
		"exp":    tok.Exp,
		"v":      tok.V,
	}
	if tok.Aud != "" {
		m["aud"] = tok.Aud
	}
	if tok.Iat != 0 {
		m["iat"] = tok.Iat
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		v, err := json.Marshal(m[k])
		if err != nil {
			return nil, err
		}
		parts = append(parts, fmt.Sprintf("%s=%s", k, string(v)))
	}
	return []byte(strings.Join(parts, "\n")), nil
}

func signCallerToken(tok signedCallerToken, secret string) (string, error) {
	payload, err := json.Marshal(tok)
	if err != nil {
		return "", fmt.Errorf("marshal token: %w", err)
	}
	canonical, err := canonicalTokenPayload(tok)
	if err != nil {
		return "", fmt.Errorf("canonicalize token: %w", err)
	}
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(canonical)
	sig := hex.EncodeToString(mac.Sum(nil))
	return base64.RawURLEncoding.EncodeToString(payload) + "." + sig, nil
}

func mintCallerToken(cfg Config, caller string, ttl time.Duration) (string, signedCallerToken, error) {
	caller = strings.TrimSpace(caller)
	if caller == "" {
		return "", signedCallerToken{}, fmt.Errorf("caller is required")
	}
	allowed := false
	for _, allowedCaller := range cfg.Auth.AuthorizedCallers {
		if caller == allowedCaller {
			allowed = true
			break
		}
	}
	if !allowed {
		return "", signedCallerToken{}, fmt.Errorf("caller %q not authorized", caller)
	}
	secret := strings.TrimSpace(os.Getenv(cfg.Auth.TokenSecretEnv))
	if secret == "" {
		return "", signedCallerToken{}, fmt.Errorf("token secret env %q is not set", cfg.Auth.TokenSecretEnv)
	}
	now := time.Now().UTC()
	tok := signedCallerToken{
		Caller: caller,
		Aud:    "safe-docker",
		Iat:    now.Unix(),
		V:      1,
	}
	if ttl > 0 {
		tok.Exp = now.Add(ttl).Unix()
	}
	signed, err := signCallerToken(tok, secret)
	if err != nil {
		return "", signedCallerToken{}, err
	}
	return signed, tok, nil
}

func (s *Server) authenticateCallerToken(raw string) (string, error) {
	parts := strings.Split(raw, ".")
	if len(parts) != 2 {
		return "", fmt.Errorf("invalid token format")
	}
	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return "", fmt.Errorf("decode payload: %w", err)
	}
	sigBytes, err := hex.DecodeString(parts[1])
	if err != nil {
		return "", fmt.Errorf("decode signature: %w", err)
	}
	var tok signedCallerToken
	if err := json.Unmarshal(payloadBytes, &tok); err != nil {
		return "", fmt.Errorf("decode token json: %w", err)
	}
	if strings.TrimSpace(tok.Caller) == "" {
		return "", fmt.Errorf("missing caller")
	}
	if tok.V != 1 {
		return "", fmt.Errorf("unsupported token version")
	}
	if tok.Aud != "" && tok.Aud != "safe-docker" {
		return "", fmt.Errorf("invalid audience")
	}
	if tok.Exp > 0 {
		if now := time.Now().Unix(); tok.Exp < now {
			return "", fmt.Errorf("token expired")
		}
	}
	allowed := false
	for _, caller := range s.cfg.Auth.AuthorizedCallers {
		if tok.Caller == caller {
			allowed = true
			break
		}
	}
	if !allowed {
		return "", fmt.Errorf("caller not authorized")
	}
	canonical, err := canonicalTokenPayload(tok)
	if err != nil {
		return "", fmt.Errorf("canonicalize token: %w", err)
	}
	secret := os.Getenv(s.cfg.Auth.TokenSecretEnv)
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(canonical)
	want := mac.Sum(nil)
	if subtle.ConstantTimeCompare(sigBytes, want) != 1 {
		return "", fmt.Errorf("invalid signature")
	}
	return tok.Caller, nil
}
