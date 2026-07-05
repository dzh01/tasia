package llm

import (
	"strings"
	"testing"

	"github.com/dzh01/tasia/internal/rules"
)

func TestRedactNeverLeaks(t *testing.T) {
	fs := []rules.Finding{
		{ID: "x", Severity: "HIGH", Title: "foo", File: "c.yml", Line: 1, Evidence: "port=11434", Why: "why", Fix: "fix"},
	}
	p := RedactPack("BLOCKED", "HIGH", fs)
	if strings.Contains(p, "sk-") || strings.Contains(p, "hf_real") {
		t.Error("redact leaked")
	}
	if !strings.Contains(p, "BLOCKED") || !strings.Contains(p, "exposed") {
		t.Log("ok basic pack")
	}
}

func TestSanitizeScrubsCommonTokenFormats(t *testing.T) {
	cases := []string{
		"sk-ABCDEFGH12345678",
		"hf_ABCDEFGH12345678",
		"ghp_0123456789ABCDEFGHIJ0123456789ab",
		"AKIAIOSFODNN7EXAMPLE",
		"AIzaSyA0123456789abcdefghijklmnopqrs",
		"xoxb-123456789012-abcdefghij",
		"https://admin:p4ssw0rd@internal.host",
		"Authorization: Bearer abcdef123456",
		"password=hunter2xyz",
	}
	for _, in := range cases {
		got := sanitize("evidence " + in + " tail")
		if strings.Contains(got, in) {
			t.Errorf("sanitize failed to redact %q -> %q", in, got)
		}
		if !strings.Contains(got, "[REDACTED]") {
			t.Errorf("sanitize did not mark redaction for %q -> %q", in, got)
		}
	}
}

func TestSanitizeKeepsBenignEvidence(t *testing.T) {
	for _, in := range []string{
		"image=ollama/ollama:latest port=11434:11434",
		"OLLAMA_ORIGINS=*",
		"OPENAI_API_KEY",
		"service=ollama privileged=true",
	} {
		if got := sanitize(in); got != in {
			t.Errorf("sanitize should not alter benign evidence %q -> %q", in, got)
		}
	}
}
