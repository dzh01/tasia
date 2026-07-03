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

	// Test localhost bind forms that previously produced HostPort=0
	loc := filepath.Join(tmp, "compose-localhost.yml")
	locContent := `services:
  ollama:
    image: ollama/ollama:0.3
    ports:
      - "127.0.0.1:11434:11434"
  web:
    image: ghcr.io/open-webui/open-webui:0.3
    ports:
      - "127.0.0.1:3000:8080"
`
	if err := os.WriteFile(loc, []byte(locContent), 0644); err != nil {
		t.Fatal(err)
	}
	parsed2, err := Parse(loc)
	if err != nil {
		t.Fatalf("parse loc: %v", err)
	}
	found11434 := false
	found3000 := false
	for _, s := range parsed2.Services {
		for _, p := range s.Ports {
			if p.HostPort == 11434 {
				found11434 = true
			}
			if p.HostPort == 3000 {
				found3000 = true
			}
		}
	}
	if !found11434 || !found3000 {
		t.Errorf("localhost prefixed ports not parsed correctly: %+v", parsed2.Services)
	}
}
