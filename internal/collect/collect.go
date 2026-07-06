package collect

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/dzh01/tasia/internal/collect/compose"
)

// Collected holds the aggregated data from scanning a tree.
// Pure data for rules and reports.
type Collected struct {
	Root               string
	ComposeFiles       []compose.File
	EnvFiles           []EnvFile
	Dockerfiles        []Dockerfile
	OtherConfigs       []string // Modelfile etc later
	DetectedRuntimes   []string
	DetectedInterfaces []string
	DetectedRetrieval  []string
	PublishedPorts     []int
	SecretKeyNames     []string
	HasManifest        bool
}

// EnvFile tracks .env* without values.
type EnvFile struct {
	Path string
	Keys []EnvKey
}

// EnvKey is a secret-looking key name and the 1-based line it appears on.
// Values are never captured.
type EnvKey struct {
	Name string
	Line int
}

// KeyNames returns just the key names (values are never stored).
func (e EnvFile) KeyNames() []string {
	out := make([]string, 0, len(e.Keys))
	for _, k := range e.Keys {
		out = append(out, k.Name)
	}
	return out
}

// Dockerfile basic.
type Dockerfile struct {
	Path    string
	Content string
}

// WalkAndCollect walks the dir and extracts relevant data.
func WalkAndCollect(root string) (*Collected, error) {
	c := &Collected{Root: root}

	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			// skip .git, .tasia, node_modules etc
			name := d.Name()
			if name == ".git" || name == ".tasia" || name == "node_modules" || name == "vendor" {
				return filepath.SkipDir
			}
			return nil
		}

		rel, _ := filepath.Rel(root, path)
		lower := strings.ToLower(d.Name())

		switch {
		case lower == "docker-compose.yml" || lower == "docker-compose.yaml" ||
			lower == "compose.yml" || lower == "compose.yaml":
			f, perr := compose.Parse(path)
			if perr != nil {
				// Unparseable compose: warn and skip. Note: this is fail-open —
				// see roadmap for surfacing an unparseable_config finding instead.
				fmt.Fprintf(os.Stderr, "warn: parse %s: %v\n", path, perr)
				return nil
			}
			c.ComposeFiles = append(c.ComposeFiles, *f)
			extractFromCompose(c, f)
		case strings.HasPrefix(lower, ".env"):
			ef, perr := parseEnvKeys(path)
			if perr == nil {
				if r, err := filepath.Rel(root, path); err == nil {
					ef.Path = r
				}
				c.EnvFiles = append(c.EnvFiles, ef)
				c.SecretKeyNames = append(c.SecretKeyNames, ef.KeyNames()...)
			}
		case lower == "dockerfile":
			content, _ := os.ReadFile(path)
			c.Dockerfiles = append(c.Dockerfiles, Dockerfile{Path: rel, Content: string(content)})
		case lower == "modelfile":
			c.OtherConfigs = append(c.OtherConfigs, rel)
		case lower == "ai-stack-manifest.json":
			c.HasManifest = true
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	// dedup secrets etc
	c.SecretKeyNames = dedup(c.SecretKeyNames)
	c.PublishedPorts = dedupInts(c.PublishedPorts)

	// runtime / interface / retrieval detection from collected service images
	for _, cf := range c.ComposeFiles {
		for _, svc := range cf.Services {
			name := strings.ToLower(svc.Image)
			for label, needles := range map[string][]string{
				"ollama":    {"ollama"},
				"vllm":      {"vllm"},
				"llama.cpp": {"llama.cpp", "llamacpp"},
				"lm-studio": {"lmstudio", "lm-studio"},
			} {
				if containsAny(name, needles) {
					c.DetectedRuntimes = append(c.DetectedRuntimes, label)
				}
			}
			for label, needles := range map[string][]string{
				"open-webui": {"open-webui", "openwebui"},
				"gradio":     {"gradio"},
			} {
				if containsAny(name, needles) {
					c.DetectedInterfaces = append(c.DetectedInterfaces, label)
				}
			}
			for label, needles := range map[string][]string{
				"qdrant":   {"qdrant"},
				"chroma":   {"chroma"},
				"weaviate": {"weaviate"},
				"milvus":   {"milvus"},
				"redis":    {"redis", "valkey"},
				"postgres": {"postgres", "pgvector"},
			} {
				if containsAny(name, needles) {
					c.DetectedRetrieval = append(c.DetectedRetrieval, label)
				}
			}
		}
	}
	c.DetectedRuntimes = sortStrings(dedup(c.DetectedRuntimes))
	c.DetectedInterfaces = sortStrings(dedup(c.DetectedInterfaces))
	c.DetectedRetrieval = sortStrings(dedup(c.DetectedRetrieval))

	return c, nil
}

func containsAny(s string, needles []string) bool {
	for _, n := range needles {
		if strings.Contains(s, n) {
			return true
		}
	}
	return false
}

func sortStrings(ss []string) []string {
	sort.Strings(ss)
	return ss
}

func extractFromCompose(c *Collected, f *compose.File) {
	for _, svc := range f.Services {
		// ports
		for _, p := range svc.Ports {
			if p.HostPort > 0 {
				c.PublishedPorts = append(c.PublishedPorts, p.HostPort)
			}
		}
		// compose environment secret key names (values ignored)
		for _, e := range svc.Environment {
			if idx := strings.Index(e, "="); idx > 0 {
				k := strings.TrimSpace(e[:idx])
				if LooksLikeSecretKeyName(k) {
					c.SecretKeyNames = append(c.SecretKeyNames, k)
				}
			} else if LooksLikeSecretKeyName(e) {
				c.SecretKeyNames = append(c.SecretKeyNames, strings.TrimSpace(e))
			}
		}
		// images for detection later too
		// mounts, privileged, etc handled in rules or here
	}
}

func parseEnvKeys(path string) (EnvFile, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return EnvFile{}, err
	}
	keys := []EnvKey{}
	// naive: lines with KEY= , ignore values completely
	lines := strings.Split(string(b), "\n")
	re := regexp.MustCompile(`^\s*(?:export\s+)?([A-Za-z0-9_]+)\s*=`)
	for i, ln := range lines {
		m := re.FindStringSubmatch(ln)
		if m != nil {
			k := m[1]
			// only collect likely secret names, but per spec we collect token key names
			if LooksLikeSecretKeyName(k) {
				keys = append(keys, EnvKey{Name: k, Line: i + 1})
			}
		}
	}
	// Path will be made relative by caller (WalkAndCollect) for consistency with compose files
	return EnvFile{Path: path, Keys: keys}, nil
}

// LooksLikeSecretKeyName reports whether an environment key name suggests it
// holds a credential. It inspects only the name, never the value. This is the
// single source of truth shared by the collector and the rules engine.
func LooksLikeSecretKeyName(k string) bool {
	uk := strings.ToUpper(k)
	return strings.Contains(uk, "TOKEN") || strings.Contains(uk, "KEY") || strings.Contains(uk, "SECRET") ||
		strings.Contains(uk, "PASS") || strings.Contains(uk, "API") || strings.Contains(uk, "HF_") ||
		strings.Contains(uk, "AUTH")
}

func dedup(ss []string) []string {
	m := map[string]bool{}
	out := []string{}
	for _, s := range ss {
		if !m[s] {
			m[s] = true
			out = append(out, s)
		}
	}
	return out
}

func dedupInts(is []int) []int {
	m := map[int]bool{}
	out := []int{}
	for _, i := range is {
		if !m[i] {
			m[i] = true
			out = append(out, i)
		}
	}
	return out
}
