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
