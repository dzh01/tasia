package collect

import (
	"os"
	"path/filepath"
	"testing"
)

func TestWalkAndCollectCompose(t *testing.T) {
	tmp := t.TempDir()
	cf := filepath.Join(tmp, "docker-compose.yml")
	y := `services:
  ollama:
    image: ollama/ollama:latest
    ports:
      - "11434:11434"
`
	if err := os.WriteFile(cf, []byte(y), 0644); err != nil {
		t.Fatal(err)
	}
	col, err := WalkAndCollect(tmp)
	if err != nil {
		t.Fatal(err)
	}
	if len(col.ComposeFiles) != 1 {
		t.Fatalf("expected 1 compose, got %d", len(col.ComposeFiles))
	}
	if len(col.PublishedPorts) == 0 || col.PublishedPorts[0] != 11434 {
		t.Errorf("ports not extracted: %v", col.PublishedPorts)
	}
	if len(col.DetectedRuntimes) == 0 || col.DetectedRuntimes[0] != "ollama" {
		t.Errorf("runtimes not detected: %v", col.DetectedRuntimes)
	}
}

func TestEnvNoValues(t *testing.T) {
	tmp := t.TempDir()
	envp := filepath.Join(tmp, ".env.local")
	if err := os.WriteFile(envp, []byte("HF_TOKEN=hf_abc123\nOTHER=val\nAPI_KEY=sk-xxx\n"), 0644); err != nil {
		t.Fatal(err)
	}
	col, err := WalkAndCollect(tmp)
	if err != nil {
		t.Fatal(err)
	}
	if len(col.SecretKeyNames) == 0 {
		t.Error("expected secret key names")
	}
	for _, k := range col.SecretKeyNames {
		if k == "hf_abc123" || k == "sk-xxx" {
			t.Errorf("value leaked into key names: %s", k)
		}
	}
}
