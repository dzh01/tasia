package compose

import (
	"os"
	"path/filepath"
	"testing"
)

func TestParseLinesAndPorts(t *testing.T) {
	tmp := t.TempDir()
	f := filepath.Join(tmp, "docker-compose.yml")
	content := `services:
  ollama:
    image: ollama/ollama:latest
    ports:
      - "11434:11434"
  qdrant:
    image: qdrant/qdrant:latest
    ports:
      - "6333:6333"
`
	if err := os.WriteFile(f, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
	parsed, err := Parse(f)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(parsed.Services) != 2 {
		t.Fatalf("expected 2 services, got %d", len(parsed.Services))
	}
	oll := parsed.Services[0]
	if oll.Name != "ollama" || oll.Image != "ollama/ollama:latest" {
		t.Errorf("bad ollama parse: %+v", oll)
	}
	if len(oll.Ports) == 0 || oll.Ports[0].HostPort != 11434 || oll.Ports[0].Line == 0 {
		t.Errorf("expected port line and 11434, got %+v", oll.Ports)
	}
}
