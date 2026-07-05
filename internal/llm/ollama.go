package llm

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/dzh01/tasia/internal/rules"
)

// DefaultOllamaHost is the host:port used when --ollama-host is not given.
const DefaultOllamaHost = "localhost:11434"

// OllamaClient talks to a local Ollama /api/generate endpoint.
// It only ever transmits the redacted FactPack — never raw files or secret values.
type OllamaClient struct {
	Host string // "localhost", "localhost:11434", or "host:port"
	HTTP *http.Client
}

// NewOllamaClient builds a client for the given host. An empty host defaults
// to localhost:11434. A host without a port gets :11434 appended.
func NewOllamaClient(host string) *OllamaClient {
	host = strings.TrimSpace(host)
	if host == "" {
		host = DefaultOllamaHost
	}
	host = strings.TrimPrefix(host, "http://")
	host = strings.TrimPrefix(host, "https://")
	host = strings.TrimSuffix(host, "/")
	if !strings.Contains(host, ":") {
		host = host + ":11434"
	}
	return &OllamaClient{
		Host: host,
		HTTP: &http.Client{Timeout: 120 * time.Second},
	}
}

// URL returns the /api/generate endpoint.
func (c *OllamaClient) URL() string {
	return "http://" + c.Host + "/api/generate"
}

type ollamaRequest struct {
	Model  string `json:"model"`
	Prompt string `json:"prompt"`
	Stream bool   `json:"stream"`
}

type ollamaResponse struct {
	Response string `json:"response"`
	Done     bool   `json:"done"`
	Error    string `json:"error"`
}

// BuildPrompt wraps the redacted FactPack JSON in a short instruction. The
// returned string contains ONLY the redacted pack plus static instruction
// text — no raw file contents and no secret values.
func BuildPrompt(redactedJSON string) string {
	var b strings.Builder
	b.WriteString("You are a security reviewer summarizing a private AI deployment audit.\n")
	b.WriteString("The deterministic findings below are authoritative — do not invent, add, or remove findings.\n")
	b.WriteString("Write a short, plain-language summary for an engineer: what the biggest risks are and what to fix first.\n")
	b.WriteString("Do not ask for more data. Base your summary only on the JSON.\n\n")
	b.WriteString("Redacted findings JSON:\n")
	b.WriteString(redactedJSON)
	b.WriteString("\n\nSummary:\n")
	return b.String()
}

// Explain sends the redacted FactPack to the local model and returns the prose
// response. It never transmits anything other than the redacted pack. On any
// connection or protocol error it returns a descriptive error (callers should
// treat this as a tool/config error, exit 2 — never fail review/ci).
func (c *OllamaClient) Explain(model, decision, risk string, findings []rules.Finding) (string, error) {
	redacted := RedactPack(decision, risk, findings)
	prompt := BuildPrompt(redacted)

	reqBody, err := json.Marshal(ollamaRequest{Model: model, Prompt: prompt, Stream: false})
	if err != nil {
		return "", err
	}

	httpReq, err := http.NewRequest(http.MethodPost, c.URL(), bytes.NewReader(reqBody))
	if err != nil {
		return "", err
	}
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := c.HTTP.Do(httpReq)
	if err != nil {
		return "", fmt.Errorf("could not reach Ollama at %s: %w", c.Host, err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("ollama returned HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}

	var or ollamaResponse
	if err := json.Unmarshal(body, &or); err != nil {
		return "", fmt.Errorf("could not parse Ollama response: %w", err)
	}
	if or.Error != "" {
		return "", fmt.Errorf("ollama error: %s", or.Error)
	}
	return strings.TrimSpace(or.Response), nil
}
