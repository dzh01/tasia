package rules

import (
	"strings"
	"testing"

	"github.com/dzh01/tasia/internal/collect"
	"github.com/dzh01/tasia/internal/collect/compose"
)

func TestEvaluateExposedAndLatest(t *testing.T) {
	c := &collect.Collected{
		Root: "/tmp/test",
		ComposeFiles: []compose.File{
			{
				Path: "docker-compose.yml",
				Services: []compose.Service{
					{
						Name:      "ollama",
						Image:     "ollama/ollama:latest",
						ImageLine: 3,
						Ports:     []compose.PortMapping{{HostPort: 11434, TargetPort: 11434, Raw: "11434:11434", Line: 5}},
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

func TestPermissiveCORSAndComposeEnvKeys(t *testing.T) {
	c := &collect.Collected{
		Root: "/tmp/test",
		ComposeFiles: []compose.File{
			{
				Path: "docker-compose.yml",
				Services: []compose.Service{
					{
						Name:        "ollama",
						Image:       "ollama/ollama:0.3",
						Ports:       []compose.PortMapping{{HostPort: 11434, Raw: "11434:11434", Line: 5}},
						Environment: []string{"OLLAMA_ORIGINS=*", "HF_TOKEN=hf_xxx"},
					},
				},
			},
		},
	}
	fs := Evaluate(c)
	hasCORS := false
	hasEnvKey := false
	for _, f := range fs {
		if f.ID == "permissive_cors" && f.Severity == "HIGH" {
			hasCORS = true
		}
		if f.ID == "env_token_key" && strings.Contains(f.Evidence, "HF_TOKEN") {
			hasEnvKey = true
		}
	}
	if !hasCORS {
		t.Error("missing HIGH permissive_cors finding for OLLAMA_ORIGINS=*")
	}
	if !hasEnvKey {
		t.Error("missing env token key from compose environment")
	}
}

func TestEnvKeyLineNumbers(t *testing.T) {
	c := &collect.Collected{
		Root:     ".",
		EnvFiles: []collect.EnvFile{{Path: ".env", Keys: []collect.EnvKey{{Name: "OPENAI_API_KEY", Line: 2}, {Name: "HF_TOKEN", Line: 5}}}},
	}
	fs := Evaluate(c)
	want := map[string]int{"OPENAI_API_KEY": 2, "HF_TOKEN": 5}
	got := map[string]int{}
	for _, f := range fs {
		if f.ID == "env_token_key" {
			got[f.Evidence] = f.Line
		}
	}
	for k, ln := range want {
		if got[k] != ln {
			t.Errorf("env_token_key %s: got line %d, want %d", k, got[k], ln)
		}
	}
}

func TestNewComponentDetection(t *testing.T) {
	c := &collect.Collected{
		Root: ".",
		ComposeFiles: []compose.File{{
			Path: "docker-compose.yml",
			Services: []compose.Service{
				// llama.cpp inference by image name, exposed to all interfaces
				{Name: "llamacpp", Image: "ghcr.io/ggerganov/llama.cpp:server", Ports: []compose.PortMapping{{HostPort: 8080, TargetPort: 8080, Raw: "8080:8080", Line: 3}}},
				// LM Studio by port 1234 with an unknown image
				{Name: "lmstudio", Image: "someone/lmstudio-headless:1.0", Ports: []compose.PortMapping{{HostPort: 1234, TargetPort: 1234, Raw: "1234:1234", Line: 6}}},
				// Weaviate vector DB
				{Name: "weaviate", Image: "semitechnologies/weaviate:1.25", Ports: []compose.PortMapping{{HostPort: 8081, TargetPort: 8080, Raw: "8081:8080", Line: 9}}},
				// Milvus vector DB on 19530
				{Name: "milvus", Image: "milvusdb/milvus:v2.4", Ports: []compose.PortMapping{{HostPort: 19530, TargetPort: 19530, Raw: "19530:19530", Line: 12}}},
			},
		}},
	}
	fs := Evaluate(c)
	// two inference exposures (llama.cpp + LM Studio) and two vector (weaviate + milvus)
	infCount, vecCount := 0, 0
	for _, f := range fs {
		// per-service exposure findings must carry a real line number
		if f.ID == "exposed_inference" || f.ID == "exposed_vector" {
			if f.Line == 0 {
				t.Errorf("finding %s has no line number: %+v", f.ID, f)
			}
		}
		if f.ID == "exposed_inference" {
			infCount++
		}
		if f.ID == "exposed_vector" {
			vecCount++
		}
	}
	if infCount != 2 {
		t.Errorf("expected 2 exposed_inference (llama.cpp + LM Studio), got %d", infCount)
	}
	if vecCount != 2 {
		t.Errorf("expected 2 exposed_vector (weaviate + milvus), got %d", vecCount)
	}
}

func TestDatastoreExposureSeverity(t *testing.T) {
	// Redis alongside AI (ollama) => HIGH
	withAI := &collect.Collected{
		Root: ".",
		ComposeFiles: []compose.File{{
			Path: "docker-compose.yml",
			Services: []compose.Service{
				{Name: "ollama", Image: "ollama/ollama:0.3", Ports: []compose.PortMapping{{HostPort: 11434, TargetPort: 11434, Raw: "11434:11434", Line: 3}}},
				{Name: "redis", Image: "redis:7", Ports: []compose.PortMapping{{HostPort: 6379, TargetPort: 6379, Raw: "6379:6379", Line: 6}}},
			},
		}},
	}
	var redisSev string
	for _, f := range Evaluate(withAI) {
		if f.ID == "exposed_datastore" {
			redisSev = f.Severity
			if f.Line != 6 {
				t.Errorf("redis datastore finding line: got %d want 6", f.Line)
			}
		}
	}
	if redisSev != SeverityHigh {
		t.Errorf("redis alongside AI should be HIGH, got %q", redisSev)
	}

	// Postgres with no AI component => MEDIUM
	noAI := &collect.Collected{
		Root: ".",
		ComposeFiles: []compose.File{{
			Path: "docker-compose.yml",
			Services: []compose.Service{
				{Name: "db", Image: "postgres:16", Ports: []compose.PortMapping{{HostPort: 5432, TargetPort: 5432, Raw: "5432:5432", Line: 3}}},
				{Name: "app", Image: "myorg/app:1.2", Ports: []compose.PortMapping{{HostPort: 9000, TargetPort: 9000, Raw: "9000:9000", Line: 6}}},
			},
		}},
	}
	var pgSev string
	for _, f := range Evaluate(noAI) {
		if f.ID == "exposed_datastore" {
			pgSev = f.Severity
		}
	}
	if pgSev != SeverityMedium {
		t.Errorf("postgres with no AI component should be MEDIUM, got %q", pgSev)
	}
}

func TestNetworkModeHostExposure(t *testing.T) {
	c := &collect.Collected{
		Root: ".",
		ComposeFiles: []compose.File{{
			Path: "docker-compose.yml",
			Services: []compose.Service{
				{Name: "ollama", Image: "ollama/ollama:0.3", NetworkMode: "host", NetworkModeLine: 4},
			},
		}},
	}
	var found *Finding
	for _, f := range Evaluate(c) {
		if f.ID == "exposed_inference" {
			ff := f
			found = &ff
		}
	}
	if found == nil {
		t.Fatal("network_mode: host inference exposure not detected")
	}
	if found.Severity != SeverityHigh || found.Line != 4 || !strings.Contains(found.Evidence, "network_mode: host") {
		t.Errorf("bad host-network finding: %+v", *found)
	}
}

func TestHostIPLocalhostNotFlagged(t *testing.T) {
	// Long-form port explicitly bound to 127.0.0.1 must NOT be an exposure.
	c := &collect.Collected{
		Root: ".",
		ComposeFiles: []compose.File{{
			Path: "docker-compose.yml",
			Services: []compose.Service{
				{Name: "ollama", Image: "ollama/ollama:0.3",
					Ports: []compose.PortMapping{{HostPort: 11434, TargetPort: 11434, Raw: "11434", HostIP: "127.0.0.1", Line: 5}}},
			},
		}},
	}
	for _, f := range Evaluate(c) {
		if f.ID == "exposed_inference" {
			t.Errorf("localhost-bound (host_ip 127.0.0.1) port must not be flagged: %+v", f)
		}
	}
}

func TestLongFormDockerSocket(t *testing.T) {
	c := &collect.Collected{
		Root: ".",
		ComposeFiles: []compose.File{{
			Path: "docker-compose.yml",
			Services: []compose.Service{
				{Name: "ui", Image: "portainer/portainer:2.0", VolumesLine: 4,
					Volumes: []string{"/var/run/docker.sock:/var/run/docker.sock"}},
			},
		}},
	}
	found := false
	for _, f := range Evaluate(c) {
		if f.ID == "docker_socket_mount" && f.Severity == SeverityCritical {
			found = true
		}
	}
	if !found {
		t.Error("docker.sock mount (long-form) not detected")
	}
}

func TestNoSecretValues(t *testing.T) {
	// ensure rule never invents values; here just env keys
	c := &collect.Collected{
		Root:         ".",
		EnvFiles:     []collect.EnvFile{{Path: ".env", Keys: []collect.EnvKey{{Name: "HF_TOKEN", Line: 1}, {Name: "OPENAI_API_KEY", Line: 2}}}},
		ComposeFiles: []compose.File{{Path: "c.yml", Services: []compose.Service{{Name: "x", Image: "ollama/ollama:0.1"}}}},
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
		if len(b) > 0 && (len(s) > 0 && (s == b || len(s) > 3 && contains(s, b))) {
			return true
		}
	}
	return false
}

func contains(s, sub string) bool {
	return len(s) >= len(sub) && (s == sub || (len(sub) > 0 && (s[0:len(sub)] == sub || contains(s[1:], sub))))
}
