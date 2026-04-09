package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"
)

func main() {
	configPath := flag.String("config", "policy.yaml", "path to YAML policy/config")
	flag.Parse()

	cfg, err := loadConfig(*configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "FATAL: load config: %v\n", err)
		os.Exit(1)
	}

	log := buildLogger(cfg.Logging)
	srv, err := newServer(cfg, log)
	if err != nil {
		log.Error("server init failed", "error", err)
		os.Exit(1)
	}
	defer func() { _ = srv.docker.Close() }()

	httpServer := &http.Server{
		Addr:         cfg.Server.ListenAddr,
		Handler:      srv.router(),
		ReadTimeout:  15 * time.Second,
		WriteTimeout: time.Duration(cfg.Docker.TimeoutSeconds+5) * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		log.Info("safe-docker listening", "addr", cfg.Server.ListenAddr)
		if err := httpServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Error("server error", "error", err)
			os.Exit(1)
		}
	}()

	<-quit
	log.Info("shutting down")
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := httpServer.Shutdown(ctx); err != nil {
		log.Error("graceful shutdown failed", "error", err)
		os.Exit(1)
	}
	log.Info("shutdown complete")
}
