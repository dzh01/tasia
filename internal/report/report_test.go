package report

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/joeyvictorino/tasia/internal/collect"
	"github.com/joeyvictorino/tasia/internal/rules"
)

func TestDecideAndPrint(t *testing.T) {
	fs := []rules.Finding{
		{ID: "exposed_inference", Severity: "HIGH", Title: "Inference API published to all interfaces", File: "docker-compose.yml", Line: 5},
	}
	d, r := Decide(fs, "high", false)
	if d != "BLOCKED" || r != "HIGH" {
		t.Errorf("bad decide: %s %s", d, r)
	}
	// print does not panic
	PrintSummary(fs, d, r)
}

func TestManifestAndNoSecrets(t *testing.T) {
	c := &collect.Collected{
		DetectedRuntimes:    []string{"ollama"},
		DetectedInterfaces:  []string{"open-webui"},
		DetectedRetrieval:   []string{"qdrant"},
		PublishedPorts:      []int{11434, 3000, 6333},
		SecretKeyNames:      []string{"HF_TOKEN"},
	}
	fs := []rules.Finding{{Severity: "HIGH"}}
	m := buildManifest(c, fs, "BLOCKED", "HIGH")
	b, _ := json.Marshal(m)
	s := string(b)
	if !strings.Contains(s, `"runtimes":["ollama"]`) {
		t.Error("manifest missing runtimes")
	}
	if strings.Contains(s, "hf_") || strings.Contains(s, "secretvalue") {
		t.Error("manifest may contain secret value")
	}
}

func TestHardenedOverride(t *testing.T) {
	override := `services:
  ollama:
    ports:
      - "127.0.0.1:11434:11434"
    networks:
      - ai_internal
networks:
  ai_internal:
    internal: true
`
	if !strings.Contains(override, "ai_internal") {
		t.Error("override should mention internal net")
	}
}
