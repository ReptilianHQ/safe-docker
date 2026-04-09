package main

import (
	"context"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5/middleware"
)

func (s *Server) structuredLogger() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ww := middleware.NewWrapResponseWriter(w, r.ProtoMajor)
			start := time.Now()
			defer func() {
				s.log.Info("http request",
					"method", r.Method,
					"path", r.URL.Path,
					"status", ww.Status(),
					"bytes", ww.BytesWritten(),
					"duration_ms", time.Since(start).Milliseconds(),
					"request_id", middleware.GetReqID(r.Context()),
					"remote_addr", r.RemoteAddr,
				)
			}()
			next.ServeHTTP(ww, r)
		})
	}
}

func (s *Server) requireAPIKey(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		key := r.Header.Get("X-API-Key")
		meta, ok := s.cfg.Auth.Keys[key]
		if strings.TrimSpace(key) == "" {
			writeError(w, http.StatusUnauthorized, "X-API-Key header required")
			return
		}
		if !ok {
			writeError(w, http.StatusForbidden, "invalid API key")
			return
		}
		ctx := context.WithValue(r.Context(), callerContextKey{}, meta.Label)
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
