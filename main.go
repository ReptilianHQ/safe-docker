package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"
)

func main() {
	args := os.Args[1:]
	if len(args) > 0 && args[0] == "auth" {
		runAuth(args[1:])
		return
	}
	runServer(args)
}

func runServer(args []string) {
	fs := flag.NewFlagSet("safe-docker", flag.ExitOnError)
	configPath := fs.String("config", "policy.yaml", "path to YAML policy/config")
	_ = fs.Parse(args)

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
		log.Info("safe-docker listening", "addr", cfg.Server.ListenAddr, "service", "safe-docker")
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

func runAuth(args []string) {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "usage: safe-docker auth mint --caller <name> [--ttl 1h] [--config policy.yaml]")
		os.Exit(2)
	}
	switch args[0] {
	case "mint":
		runAuthMint(args[1:])
	default:
		fmt.Fprintf(os.Stderr, "unknown auth command: %s\n", args[0])
		os.Exit(2)
	}
}

func runAuthMint(args []string) {
	fs := flag.NewFlagSet("safe-docker auth mint", flag.ExitOnError)
	configPath := fs.String("config", "policy.yaml", "path to YAML policy/config")
	caller := fs.String("caller", "", "authorized caller name to mint a token for")
	ttlRaw := fs.String("ttl", "", "optional token TTL (for example: 15m, 1h); omit for non-expiring token")
	jsonOut := fs.Bool("json", false, "emit JSON instead of raw token")
	_ = fs.Parse(args)

	cfg, err := loadConfig(*configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "FATAL: load config: %v\n", err)
		os.Exit(1)
	}

	var ttl time.Duration
	if strings.TrimSpace(*ttlRaw) != "" {
		ttl, err = time.ParseDuration(strings.TrimSpace(*ttlRaw))
		if err != nil {
			fmt.Fprintf(os.Stderr, "FATAL: parse ttl: %v\n", err)
			os.Exit(1)
		}
		if ttl <= 0 {
			fmt.Fprintln(os.Stderr, "FATAL: ttl must be > 0")
			os.Exit(1)
		}
	}

	token, tok, err := mintCallerToken(cfg, *caller, ttl)
	if err != nil {
		fmt.Fprintf(os.Stderr, "FATAL: mint token: %v\n", err)
		os.Exit(1)
	}

	if *jsonOut {
		resp := map[string]any{
			"api_key": token,
			"caller":  tok.Caller,
			"iat":     tok.Iat,
			"version": tok.V,
		}
		if tok.Exp > 0 {
			resp["exp"] = tok.Exp
			resp["expires_at"] = time.Unix(tok.Exp, 0).UTC().Format(time.RFC3339)
		}
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(resp)
		return
	}

	fmt.Println(token)
}
