package llm

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/joeyvictorino/tasia/internal/rules"
)

// TestExplainSendsOnlyRedactedPack stands up a fake Ollama server, captures the
// exact request body, and asserts it carries the redacted FactPack and NEVER a
// planted secret value or raw file content.
func TestExplainSendsOnlyRedactedPack(t *testing.T) {
	const plantedSecret = "sk-FAKEVALUE123"

	var gotBody []byte
	var gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotBody, _ = io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"response":"Localhost-bind your inference port.","done":true}`))
	}))
	defer srv.Close()

	// A finding whose evidence contains a secret value the redactor must strip.
	findings := []rules.Finding{
		{
			ID: "exposed_inference", Severity: "HIGH",
			Title: "Inference API published to all interfaces",
			File:  "docker-compose.yml", Line: 5,
			Evidence: "OPENAI_API_KEY=" + plantedSecret,
			Why:      "reachable", Fix: "bind localhost",
		},
	}

	client := NewOllamaClient(strings.TrimPrefix(srv.URL, "http://"))
	prose, err := client.Explain("llama3.1", "BLOCKED", "HIGH", findings)
	if err != nil {
		t.Fatalf("Explain returned error: %v", err)
	}
	if !strings.Contains(prose, "Localhost-bind") {
		t.Errorf("expected model prose to be returned, got %q", prose)
	}

	if gotPath != "/api/generate" {
		t.Errorf("expected POST to /api/generate, got %q", gotPath)
	}

	body := string(gotBody)
	if strings.Contains(body, plantedSecret) {
		t.Fatalf("SECRET LEAK: planted secret value reached the request body")
	}
	if strings.Contains(body, "[REDACTED]") == false {
		t.Errorf("expected redacted evidence in payload, body was: %s", body)
	}

	// The payload must be exactly the {model,prompt,stream} shape and the prompt
	// must contain only the redacted pack (which carries decision/risk/findings).
	var req ollamaRequest
	if err := json.Unmarshal(gotBody, &req); err != nil {
		t.Fatalf("request body is not the expected JSON shape: %v", err)
	}
	if req.Model != "llama3.1" || req.Stream != false {
		t.Errorf("unexpected request fields: model=%q stream=%v", req.Model, req.Stream)
	}
	if !strings.Contains(req.Prompt, "exposed_inference") || !strings.Contains(req.Prompt, "BLOCKED") {
		t.Errorf("prompt missing redacted facts: %q", req.Prompt)
	}
	// Nothing from raw compose beyond what the deterministic finding carries.
	if strings.Contains(req.Prompt, plantedSecret) {
		t.Fatalf("SECRET LEAK: planted secret in prompt")
	}
}

func TestNewOllamaClientHostNormalization(t *testing.T) {
	cases := map[string]string{
		"":                    "localhost:11434",
		"localhost":           "localhost:11434",
		"localhost:11434":     "localhost:11434",
		"http://127.0.0.1:99": "127.0.0.1:99",
		"box:11500/":          "box:11500",
	}
	for in, want := range cases {
		if got := NewOllamaClient(in).Host; got != want {
			t.Errorf("NewOllamaClient(%q).Host = %q, want %q", in, got, want)
		}
	}
}

func TestExplainUnreachableReturnsError(t *testing.T) {
	// Port 1 is not listening; Explain must return an error (caller exits 2),
	// never panic and never silently succeed.
	client := NewOllamaClient("127.0.0.1:1")
	_, err := client.Explain("llama3.1", "PASS", "LOW", nil)
	if err == nil {
		t.Fatal("expected error when Ollama is unreachable")
	}
	if !strings.Contains(err.Error(), "could not reach Ollama") {
		t.Errorf("expected a clear unreachable message, got: %v", err)
	}
}
