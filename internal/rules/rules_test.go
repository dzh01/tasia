package rules

import (
	"testing"

	"github.com/joeyvictorino/tasia/internal/collect"
	"github.com/joeyvictorino/tasia/internal/collect/compose"
)

func TestEvaluateExposedAndLatest(t *testing.T) {
	c := &collect.Collected{
		Root: "/tmp/test",
		ComposeFiles: []compose.File{
			{
				Path: "docker-compose.yml",
				Services: []compose.Service{
					{
						Name:  "ollama",
						Image: "ollama/ollama:latest",
						ImageLine: 3,
						Ports: []compose.PortMapping{{HostPort: 11434, TargetPort: 11434, Raw: "11434:11434", Line: 5}},
					},
					{
						Name:  "webui",
						Image: "ghcr.io/open-webui/open-webui:latest",
						Ports: []compose.PortMapping{{HostPort: 3000, TargetPort: 8080, Raw: "3000:8080", Line: 10}},
					},
				},
			},
		},
	}
	fs := Evaluate(c)
	if len(fs) == 0 {
		t.Fatal("expected findings")
	}
	hasExposed := false
	hasLatest := false
	for _, f := range fs {
		if f.ID == "exposed_inference" && f.Severity == "HIGH" && f.Line == 5 {
			hasExposed = true
		}
		if f.ID == "latest_image" {
			hasLatest = true
		}
	}
	if !hasExposed {
		t.Error("missing HIGH exposed_inference finding with line")
	}
	if !hasLatest {
		t.Error("missing latest image finding")
	}
}

func TestNoSecretValues(t *testing.T) {
	// ensure rule never invents values; here just env keys
	c := &collect.Collected{
		Root: ".",
		EnvFiles: []collect.EnvFile{{Path: ".env", KeyNames: []string{"HF_TOKEN", "OPENAI_API_KEY"}}},
		ComposeFiles: []compose.File{{Path: "c.yml", Services: []compose.Service{{Name:"x", Image:"ollama/ollama:0.1"}}}},
	}
	fs := Evaluate(c)
	for _, f := range fs {
		if containsAny(f.Evidence, []string{"sk-", "hf_", "realvalue"}) || containsAny(f.Why, []string{"sk-"}) {
			t.Errorf("possible secret leak in finding: %+v", f)
		}
	}
}

func containsAny(s string, bad []string) bool {
	for _, b := range bad {
		if len(b) > 0 && (len(s) > 0 && (s == b || len(s) > 3 && contains(s, b)) ) {
			return true
		}
	}
	return false
}

func contains(s, sub string) bool { return len(s) >= len(sub) && (s == sub || (len(sub)>0 && (s[0:len(sub)] == sub || contains(s[1:], sub))) ) }
