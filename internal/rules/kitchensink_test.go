package rules

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/joeyvictorino/tasia/internal/collect"
)

// TestKitchenSinkFixture walks the top-level testdata/kitchensink stack and
// asserts every rule fires end-to-end (collect -> evaluate), with file+line
// evidence and no secret values anywhere.
func TestKitchenSinkFixture(t *testing.T) {
	dir, err := filepath.Abs(filepath.Join("..", "..", "testdata", "kitchensink"))
	if err != nil {
		t.Fatal(err)
	}
	c, err := collect.WalkAndCollect(dir)
	if err != nil {
		t.Fatalf("collect: %v", err)
	}
	fs := Evaluate(c)

	seen := map[string]bool{}
	for _, f := range fs {
		seen[f.ID] = true
		// No planted or placeholder value should ever appear.
		if strings.Contains(f.Evidence, "replace-me") || strings.Contains(f.Evidence, "placeholder") {
			t.Errorf("finding %s leaked an env value: %q", f.ID, f.Evidence)
		}
	}

	want := []string{
		"exposed_inference", "exposed_ui", "exposed_vector", "exposed_datastore",
		"docker_socket_mount", "privileged_container", "permissive_cors",
		"latest_image", "broad_bind_mount", "env_token_key",
		"no_internal_network", "no_ai_stack_manifest",
	}
	for _, id := range want {
		if !seen[id] {
			t.Errorf("expected rule %q to fire on kitchensink fixture", id)
		}
	}

	// Redis alongside AI components must be HIGH; every port-exposure finding
	// must carry a line number.
	for _, f := range fs {
		if f.ID == "exposed_datastore" && f.Severity != SeverityHigh {
			t.Errorf("redis datastore should be HIGH alongside AI, got %s", f.Severity)
		}
		if strings.HasPrefix(f.ID, "exposed_") && f.Line == 0 {
			t.Errorf("exposure finding %s missing line number", f.ID)
		}
	}
}
