package rules

import (
	"fmt"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/joeyvictorino/tasia/internal/collect"
	"github.com/joeyvictorino/tasia/internal/collect/compose"
)

// Severity levels
const (
	SeverityCritical = "CRITICAL"
	SeverityHigh     = "HIGH"
	SeverityMedium   = "MEDIUM"
	SeverityLow      = "LOW"
)

// Finding is the core output model. Always includes file:line where possible.
type Finding struct {
	ID       string
	Severity string
	Title    string
	File     string
	Line     int
	Evidence string
	Why      string
	Fix      string
}

// Evaluate applies all deterministic rules to collected data. Returns sorted findings.
func Evaluate(c *collect.Collected) []Finding {
	var fs []Finding

	// For each compose file, analyze services
	for _, cf := range c.ComposeFiles {
		relPath, _ := filepath.Rel(c.Root, cf.Path)
		if relPath == "" || strings.HasPrefix(relPath, "..") {
			relPath = cf.Path
		}
		for _, svc := range cf.Services {
			fs = append(fs, evaluateService(cf, relPath, svc)...)
		}
		// network separation check at compose level
		fs = append(fs, checkNetworkSeparation(cf, relPath)...)
	}

	// env token keys
	for _, ef := range c.EnvFiles {
		for _, k := range ef.KeyNames {
			fs = append(fs, Finding{
				ID:       "env_token_key",
				Severity: SeverityMedium,
				Title:    fmt.Sprintf(".env contains token key name: %s", k),
				File:     ef.Path,
				Line:     0, // env lines not parsed for lineno yet
				Evidence: k,
				Why:      "Token or secret key names in env files indicate credentials may be present. Never commit real secrets; use .env.example.",
				Fix:      "Move real secrets out of repo; add .env to .gitignore; provide .env.example with placeholders only.",
			})
		}
	}

	// missing ai stack manifest
	hasManifest := c.HasManifest
	for _, f := range c.OtherConfigs {
		if strings.Contains(strings.ToLower(f), "ai-stack-manifest") {
			hasManifest = true
		}
	}
	if !hasManifest {
		// only report if we saw compose (i.e. an AI stack)
		if len(c.ComposeFiles) > 0 {
			fs = append(fs, Finding{
				ID:       "no_ai_stack_manifest",
				Severity: SeverityLow,
				Title:    "no AI stack manifest",
				File:     ".",
				Line:     0,
				Evidence: "missing ai-stack-manifest.json",
				Why:      "Without an inventory of runtimes, interfaces and retrieval, future reviews and audits are harder.",
				Fix:      "Generate or commit ai-stack-manifest.json (Tasia can produce one).",
			})
		}
	}

	// docker socket and privileged from Dockerfiles or compose already handled in service
	// later: broad bind mounts etc.

	// dedup same-ish
	fs = dedupFindings(fs)
	return fs
}

func evaluateService(cf compose.File, relCompose string, svc compose.Service) []Finding {
	var out []Finding

	img := strings.ToLower(svc.Image)
	isOllama := strings.Contains(img, "ollama")
	isWebUI := strings.Contains(img, "open-webui") || strings.Contains(img, "gradio")
	isQdrant := strings.Contains(img, "qdrant")
	isChroma := strings.Contains(img, "chroma")
	isVllm := strings.Contains(img, "vllm")
	isVector := isQdrant || isChroma

	// exposed inference / UI / vector on host ports
	for _, p := range svc.Ports {
		if p.HostPort <= 0 {
			continue
		}
		hostAll := !strings.HasPrefix(p.Raw, "127.0.0.1") && !strings.HasPrefix(p.Raw, "localhost")

		switch {
		case isOllama || isVllm:
			if hostAll {
				out = append(out, Finding{
					ID:       "exposed_inference",
					Severity: SeverityHigh,
					Title:    "Inference API published to all interfaces",
					File:     relCompose,
					Line:     p.Line,
					Evidence: fmt.Sprintf("image=%s port=%s", svc.Image, p.Raw),
					Why:      "The inference API may be reachable by unintended systems on the host network.",
					Fix:      "Bind to localhost unless remote access is intentionally required. Use internal Docker network for other services.",
				})
			}
		case isWebUI:
			if hostAll {
				out = append(out, Finding{
					ID:       "exposed_ui",
					Severity: SeverityHigh,
					Title:    "Open WebUI/Gradio UI published to all interfaces",
					File:     relCompose,
					Line:     p.Line,
					Evidence: fmt.Sprintf("image=%s port=%s", svc.Image, p.Raw),
					Why:      "Web UI for chatting with models should not be reachable from outside the host by default.",
					Fix:      "Bind to 127.0.0.1 or put behind auth proxy. Consider internal-only network.",
				})
			}
		case isVector:
			if hostAll {
				out = append(out, Finding{
					ID:       "exposed_vector",
					Severity: SeverityHigh,
					Title:    "Vector DB published to host",
					File:     relCompose,
					Line:     p.Line,
					Evidence: fmt.Sprintf("image=%s port=%s", svc.Image, p.Raw),
					Why:      "Vector database contains embeddings that may encode sensitive retrieved data.",
					Fix:      "Do not publish vector DB ports to host. Access only via internal Docker network from trusted services.",
				})
			}
		default:
			if hostAll && p.HostPort != 0 {
				// generic high for other AI-ish
			}
		}
	}

	// privileged
	if svc.Privileged {
		out = append(out, Finding{
			ID:       "privileged_container",
			Severity: SeverityCritical,
			Title:    "privileged: true",
			File:     relCompose,
			Line:     svc.PrivLine,
			Evidence: fmt.Sprintf("service=%s privileged=true", svc.Name),
			Why:      "Privileged containers have full host access and defeat container isolation.",
			Fix:      "Remove privileged: true. Use specific capabilities only if absolutely required.",
		})
	}

	// image :latest
	if strings.HasSuffix(svc.Image, ":latest") || !strings.Contains(svc.Image, ":") {
		out = append(out, Finding{
			ID:       "latest_image",
			Severity: SeverityMedium,
			Title:    "image uses latest",
			File:     relCompose,
			Line:     svc.ImageLine,
			Evidence: svc.Image,
			Why:      "latest tag is mutable and makes reproducible deploys and rollbacks impossible.",
			Fix:      "Pin to a specific version tag or digest.",
		})
	}

	// docker socket mount (common dangerous pattern)
	for _, v := range svc.Volumes {
		if strings.Contains(v, "/var/run/docker.sock") {
			out = append(out, Finding{
				ID:       "docker_socket_mount",
				Severity: SeverityCritical,
				Title:    "Docker socket mounted",
				File:     relCompose,
				Line:     0,
				Evidence: v,
				Why:      "Mounting the Docker socket gives the container full control of the Docker daemon on the host.",
				Fix:      "Remove docker.sock mount. Use rootless Docker or dedicated build service instead.",
			})
		}
	}

	// broad bind mount like .:/app
	for _, v := range svc.Volumes {
		if strings.HasPrefix(v, ".:") || strings.HasPrefix(v, "./:") || strings.Contains(v, ":/app") && !strings.Contains(v, "ro") {
			out = append(out, Finding{
				ID:       "broad_bind_mount",
				Severity: SeverityMedium,
				Title:    "broad bind mount",
				File:     relCompose,
				Line:     0,
				Evidence: v,
				Why:      "Broad host-to-container bind mounts can expose source, secrets, or allow escape.",
				Fix:      "Use more specific mounts or named volumes; prefer read-only where possible.",
			})
		}
	}

	return out
}

func checkNetworkSeparation(cf compose.File, relCompose string) []Finding {
	var out []Finding
	hasInternal := false
	for _, n := range cf.Networks {
		if n.Internal {
			hasInternal = true
		}
	}
	// if services publish ports and no internal net, note MEDIUM
	if !hasInternal {
		hasPub := false
		for _, s := range cf.Services {
			for _, p := range s.Ports {
				if p.HostPort > 0 {
					hasPub = true
				}
			}
		}
		if hasPub && len(cf.Services) > 1 {
			out = append(out, Finding{
				ID:       "no_internal_network",
				Severity: SeverityMedium,
				Title:    "no internal Docker network separation",
				File:     relCompose,
				Line:     0,
				Evidence: "no internal: true network defined",
				Why:      "Published services share the host network namespace by default; internal networks limit lateral movement.",
				Fix:      "Define an internal network and attach AI services to it. Publish only the minimum gateway if needed.",
			})
		}
	}
	return out
}

func dedupFindings(in []Finding) []Finding {
	seen := map[string]bool{}
	out := []Finding{}
	for _, f := range in {
		key := f.ID + "|" + f.File + "|" + strconv.Itoa(f.Line) + "|" + f.Evidence
		if !seen[key] {
			seen[key] = true
			out = append(out, f)
		}
	}
	return out
}
