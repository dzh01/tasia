package report

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/joeyvictorino/tasia/internal/collect"
	"github.com/joeyvictorino/tasia/internal/collect/compose"
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
		DetectedRuntimes:   []string{"ollama"},
		DetectedInterfaces: []string{"open-webui"},
		DetectedRetrieval:  []string{"qdrant"},
		PublishedPorts:     []int{11434, 3000, 6333},
		SecretKeyNames:     []string{"HF_TOKEN"},
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
	c := &collect.Collected{
		Root: t.TempDir(),
		ComposeFiles: []compose.File{
			{
				Path: "docker-compose.yml",
				Services: []compose.Service{
					{Name: "ollama", Image: "ollama/ollama:latest", Ports: []compose.PortMapping{{HostPort: 11434, TargetPort: 11434, Raw: "11434:11434", Line: 5}}},
					{Name: "qdrant", Image: "qdrant/qdrant:latest", Ports: []compose.PortMapping{{HostPort: 6333, TargetPort: 6333, Raw: "6333:6333", Line: 12}}},
				},
			},
		},
	}
	fs := []rules.Finding{}
	override := buildHardenedOverride(c, fs)
	if !strings.Contains(override, "ai_internal") || !strings.Contains(override, "127.0.0.1:11434:11434") {
		t.Errorf("override did not generate expected localhost + internal net content; got:\n%s", override)
	}
	if !strings.Contains(override, "qdrant:\n    ports: []\n") && !strings.Contains(override, "ports: []\n    networks:\n      - ai_internal") {
		// accept either ordering as long as qdrant forces no published ports
		if !strings.Contains(override, "qdrant:") || strings.Contains(override, "127.0.0.1:6333") {
			t.Errorf("vector DB qdrant should force ports: [] not publish; got:\n%s", override)
		}
	}
}

// Golden-style tests that drive the actual shipped report generators and WriteArtifacts.
func TestGoldenHardeningPlanAndMemo(t *testing.T) {
	c := &collect.Collected{
		Root:               ".",
		DetectedRuntimes:   []string{"ollama"},
		DetectedInterfaces: []string{"open-webui"},
		DetectedRetrieval:  []string{"qdrant"},
		PublishedPorts:     []int{11434, 3000, 6333},
	}
	fs := []rules.Finding{
		{ID: "exposed_inference", Severity: "HIGH", Title: "Inference API published to all interfaces", File: "docker-compose.yml", Line: 5, Evidence: "port=11434:11434", Why: "The inference API may be reachable...", Fix: "Bind to 127..."},
		{ID: "exposed_vector", Severity: "HIGH", Title: "Vector DB published to host", File: "docker-compose.yml", Line: 12, Evidence: "port=6333:6333", Why: "Vector DB...", Fix: "Use internal net"},
	}
	decision, risk := "BLOCKED", "HIGH"

	plan := buildHardeningPlan(fs, decision, risk, c)
	if !strings.Contains(plan, "# Tasia Hardening Plan") ||
		!strings.Contains(plan, "## Decision\nBLOCKED") ||
		!strings.Contains(plan, "File: docker-compose.yml:5") ||
		!strings.Contains(plan, "Why it matters:") ||
		!strings.Contains(plan, "Recommended fix:") ||
		!strings.Contains(plan, "Suggested change:") {
		t.Errorf("HARDENING_PLAN.md content missing required sections")
	}

	memo := buildExecutiveMemo(fs, decision, risk, c)
	if !strings.Contains(memo, "# Private AI Deployment Memo") ||
		!strings.Contains(memo, "Do not ship this deployment as-is") {
		t.Errorf("EXECUTIVE_MEMO missing expected language")
	}

	mani := buildManifest(c, fs, decision, risk)
	if mani["decision"] != "BLOCKED" || mani["risk"] != "HIGH" {
		t.Error("manifest decision/risk wrong")
	}
}

func TestWriteArtifactsGolden(t *testing.T) {
	scratch := t.TempDir()
	c := &collect.Collected{Root: ".", PublishedPorts: []int{11434}}
	fs := []rules.Finding{{ID: "exposed_inference", Severity: "HIGH", Title: "x", File: "c.yml", Line: 3, Why: "w", Fix: "f"}}
	decision, risk := "BLOCKED", "HIGH"

	outDir := filepath.Join(scratch, ".tasia")
	if err := os.MkdirAll(outDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := WriteArtifacts(outDir, c, fs, decision, risk); err != nil {
		t.Fatalf("WriteArtifacts: %v", err)
	}

	// Assert files + key content (drives the real writers)
	for _, name := range []string{"HARDENING_PLAN.md", "EXECUTIVE_MEMO.md", "ai-stack-manifest.json", "docker-compose.hardened.override.yml", "findings.json", "findings.toon", "firewall-notes.md"} {
		p := filepath.Join(outDir, name)
		if _, err := os.Stat(p); err != nil {
			t.Errorf("missing artifact %s", name)
			continue
		}
		b, _ := os.ReadFile(p)
		s := string(b)
		if name == "HARDENING_PLAN.md" && (!strings.Contains(s, "File: c.yml:3") || !strings.Contains(s, "Why it matters:")) {
			t.Errorf("%s missing expected sections", name)
		}
		if name == "ai-stack-manifest.json" && !strings.Contains(s, `"decision": "BLOCKED"`) {
			t.Errorf("%s missing decision", name)
		}
	}

	// review-time WriteArtifacts must NOT imply an LLM was consulted.
	if _, err := os.Stat(filepath.Join(outDir, "LLM_REVIEW.md")); err == nil {
		t.Error("WriteArtifacts should not write LLM_REVIEW.md; it is produced only by `tasia explain`")
	}
}
