package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
)

func trimContainerID(id string) string {
	if len(id) > 12 {
		return id[:12]
	}
	return id
}

func stripDockerMuxHeader(r io.Reader) ([]byte, error) {
	header := make([]byte, 8)
	var result []byte
	for {
		_, err := io.ReadFull(r, header)
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("read docker mux header: %w", err)
		}
		size := uint32(header[4])<<24 | uint32(header[5])<<16 | uint32(header[6])<<8 | uint32(header[7])
		if size == 0 {
			continue
		}
		payload := make([]byte, size)
		if _, err := io.ReadFull(r, payload); err != nil {
			return nil, fmt.Errorf("read docker mux payload: %w", err)
		}
		result = append(result, payload...)
	}
	return result, nil
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

func writeComposeError(w http.ResponseWriter, status int, action string, result ComposeResult) {
	response := map[string]any{
		"error": action + " failed",
	}
	if result.Error != nil {
		response["detail"] = result.Error.Error()
	}
	if result.Output != "" {
		response["output"] = compactComposeOutput(result.Output)
	}
	if result.Preflight != nil {
		response["preflight"] = result.Preflight
	}
	writeJSON(w, status, response)
}
