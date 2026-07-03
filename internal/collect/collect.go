package collect

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/joeyvictorino/tasia/internal/collect/compose"
)

// Collected holds the aggregated data from scanning a tree.
// Pure data for rules and reports.
type Collected struct {
	Root            string
	ComposeFiles    []compose.File
	EnvFiles        []EnvFile
	Dockerfiles     []Dockerfile
	OtherConfigs    []string // Modelfile etc later
	DetectedRuntimes []string
	DetectedInterfaces []string
	DetectedRetrieval  []string
	PublishedPorts  []int
	SecretKeyNames  []string
	HasManifest     bool
}

// EnvFile tracks .env* without values.
type EnvFile struct {
	Path      string
	KeyNames  []string
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
				// still record file? for now continue, but surface?
				fmt.Fprintf(os.Stderr, "warn: parse %s: %v\n", path, perr)
				return nil
			}
			c.ComposeFiles = append(c.ComposeFiles, *f)
			extractFromCompose(c, f)
		case strings.HasPrefix(lower, ".env"):
			ef, perr := parseEnvKeys(path)
			if perr == nil {
				c.EnvFiles = append(c.EnvFiles, ef)
				c.SecretKeyNames = append(c.SecretKeyNames, ef.KeyNames...)
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

	// simple runtime detection from collected services
	for _, cf := range c.ComposeFiles {
		for _, svc := range cf.Services {
			name := strings.ToLower(svc.Image)
			switch {
			case strings.Contains(name, "ollama"):
				c.DetectedRuntimes = append(c.DetectedRuntimes, "ollama")
			case strings.Contains(name, "open-webui"):
				c.DetectedInterfaces = append(c.DetectedInterfaces, "open-webui")
			case strings.Contains(name, "vllm"):
				c.DetectedRuntimes = append(c.DetectedRuntimes, "vllm")
			case strings.Contains(name, "qdrant"):
				c.DetectedRetrieval = append(c.DetectedRetrieval, "qdrant")
			case strings.Contains(name, "chroma"):
				c.DetectedRetrieval = append(c.DetectedRetrieval, "chroma")
			}
		}
	}
	c.DetectedRuntimes = dedup(c.DetectedRuntimes)
	c.DetectedInterfaces = dedup(c.DetectedInterfaces)
	c.DetectedRetrieval = dedup(c.DetectedRetrieval)

	return c, nil
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
				if looksLikeSecretKey(k) {
					c.SecretKeyNames = append(c.SecretKeyNames, k)
				}
			} else if looksLikeSecretKey(e) {
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
	keys := []string{}
	// naive: lines with KEY= , ignore values completely
	lines := strings.Split(string(b), "\n")
	re := regexp.MustCompile(`^\s*([A-Za-z0-9_]+)\s*=`)
	for _, ln := range lines {
		m := re.FindStringSubmatch(ln)
		if m != nil {
			k := m[1]
			// only collect likely secret names, but per spec we collect token key names
			if looksLikeSecretKey(k) {
				keys = append(keys, k)
			}
		}
	}
	rel := path // caller can make rel
	return EnvFile{Path: rel, KeyNames: keys}, nil
}

func looksLikeSecretKey(k string) bool {
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
