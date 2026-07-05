package rules

import (
	"fmt"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/dzh01/tasia/internal/collect"
	"github.com/dzh01/tasia/internal/collect/compose"
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
	ID       string `json:"id"`
	Severity string `json:"severity"`
	Title    string `json:"title"`
	File     string `json:"file"`
	Line     int    `json:"line"`
	Evidence string `json:"evidence"`
	Why      string `json:"why"`
	Fix      string `json:"fix"`
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
		stackHasAI := composeHasAIComponent(cf)
		for _, svc := range cf.Services {
			fs = append(fs, evaluateService(cf, relPath, svc, stackHasAI)...)
		}
		// network separation check at compose level
		fs = append(fs, checkNetworkSeparation(cf, relPath)...)
	}

	// env token keys
	for _, ef := range c.EnvFiles {
		for _, k := range ef.Keys {
			fs = append(fs, Finding{
				ID:       "env_token_key",
				Severity: SeverityMedium,
				Title:    fmt.Sprintf(".env contains token key name: %s", k.Name),
				File:     ef.Path,
				Line:     k.Line,
				Evidence: k.Name,
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

func evaluateService(cf compose.File, relCompose string, svc compose.Service, stackHasAI bool) []Finding {
	var out []Finding

	// A service on the host network publishes every listening port on all
	// interfaces without any ports: mapping — the most common real exposure.
	if strings.EqualFold(svc.NetworkMode, "host") {
		if f, ok := hostNetworkFinding(svc, relCompose, stackHasAI); ok {
			out = append(out, f)
		}
	}

	// exposed inference / UI / vector / datastore on host ports
	for _, p := range svc.Ports {
		if p.HostPort <= 0 {
			continue
		}
		if !p.IsAllInterfaces() {
			continue
		}
		// Classify by image first, then fall back to the published port number
		// so bare/unknown images (e.g. LM Studio on 1234) are still caught.
		switch classifyService(svc.Image, p.HostPort) {
		case catInference:
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
		case catUI:
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
		case catVector:
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
		case catDatastore:
			sev := SeverityMedium
			why := "Data store published to the host is reachable beyond the container network; unauthenticated defaults are common."
			if stackHasAI {
				sev = SeverityHigh
				why = "Data store backing an AI stack (may hold prompts, chats, or embeddings) is published to all interfaces alongside AI services."
			}
			out = append(out, Finding{
				ID:       "exposed_datastore",
				Severity: sev,
				Title:    "Data store (Redis/Postgres) published to host",
				File:     relCompose,
				Line:     p.Line,
				Evidence: fmt.Sprintf("image=%s port=%s", svc.Image, p.Raw),
				Why:      why,
				Fix:      "Do not publish the data store port to the host. Bind to 127.0.0.1 or use an internal Docker network with credentials.",
			})
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
				Line:     svc.VolumesLine,
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
				Line:     svc.VolumesLine,
				Evidence: v,
				Why:      "Broad host-to-container bind mounts can expose source, secrets, or allow escape.",
				Fix:      "Use more specific mounts or named volumes; prefer read-only where possible.",
			})
		}
	}

	// environment: token key names (from compose) + permissive CORS patterns (HIGH)
	for _, e := range svc.Environment {
		kv := strings.SplitN(e, "=", 2)
		k := strings.TrimSpace(kv[0])
		v := ""
		if len(kv) > 1 {
			v = strings.TrimSpace(kv[1])
		}
		uk := strings.ToUpper(k)
		if looksLikeSecretKeyName(k) {
			out = append(out, Finding{
				ID:       "env_token_key",
				Severity: SeverityMedium,
				Title:    fmt.Sprintf("service env contains token key name: %s", k),
				File:     relCompose,
				Line:     svc.EnvLine,
				Evidence: k,
				Why:      "Token/secret key names in compose environment may indicate credentials. Values are not inspected or emitted.",
				Fix:      "Inject real secrets at deploy time (e.g. secrets, sops, platform env); commit only placeholders.",
			})
		}
		if uk == "OLLAMA_ORIGINS" || strings.Contains(uk, "CORS") || strings.Contains(uk, "ALLOW_ORIGINS") {
			if v == "*" || strings.Contains(v, "*") || strings.TrimSpace(v) == "" {
				out = append(out, Finding{
					ID:       "permissive_cors",
					Severity: SeverityHigh,
					Title:    "permissive CORS (e.g. OLLAMA_ORIGINS=*)",
					File:     relCompose,
					Line:     svc.EnvLine,
					Evidence: e,
					Why:      "Wildcard or empty CORS on AI endpoints allows arbitrary web pages to make cross-origin requests to the model or UI.",
					Fix:      "Set explicit allowlist for OLLAMA_ORIGINS (or equivalent), e.g. http://localhost:*, or remove the var and use a reverse proxy with controlled CORS.",
				})
			}
		}
	}

	return out
}

func looksLikeSecretKeyName(k string) bool {
	uk := strings.ToUpper(k)
	return strings.Contains(uk, "TOKEN") || strings.Contains(uk, "KEY") || strings.Contains(uk, "SECRET") ||
		strings.Contains(uk, "PASS") || strings.Contains(uk, "API") || strings.Contains(uk, "HF_") ||
		strings.Contains(uk, "AUTH")
}

// svcCategory buckets a service for exposure rules.
type svcCategory int

const (
	catOther svcCategory = iota
	catInference
	catUI
	catVector
	catDatastore
)

func imageIsInference(img string) bool {
	for _, s := range []string{"ollama", "vllm", "llama.cpp", "llamacpp", "lmstudio", "lm-studio"} {
		if strings.Contains(img, s) {
			return true
		}
	}
	return false
}

func imageIsUI(img string) bool {
	for _, s := range []string{"open-webui", "openwebui", "gradio"} {
		if strings.Contains(img, s) {
			return true
		}
	}
	return false
}

func imageIsVector(img string) bool {
	for _, s := range []string{"qdrant", "chroma", "weaviate", "milvus"} {
		if strings.Contains(img, s) {
			return true
		}
	}
	return false
}

func imageIsDatastore(img string) bool {
	for _, s := range []string{"redis", "valkey", "postgres", "pgvector"} {
		if strings.Contains(img, s) {
			return true
		}
	}
	return false
}

// classifyService categorizes a service by image name, then falls back to the
// published host port so bare/unknown images on well-known AI ports are caught
// (e.g. LM Studio / llama.cpp on 1234, Milvus on 19530).
func classifyService(image string, hostPort int) svcCategory {
	img := strings.ToLower(image)
	switch {
	case imageIsInference(img):
		return catInference
	case imageIsUI(img):
		return catUI
	case imageIsVector(img):
		return catVector
	case imageIsDatastore(img):
		return catDatastore
	}
	switch hostPort {
	case 11434, 1234:
		return catInference
	case 7860:
		return catUI
	case 6333, 19530:
		return catVector
	case 6379, 5432:
		return catDatastore
	}
	return catOther
}

// hostNetworkFinding returns an exposure finding for a recognized AI/datastore
// service running on the host network (network_mode: host). Such a service is
// reachable on all host interfaces with no ports: mapping to inspect.
func hostNetworkFinding(svc compose.Service, relCompose string, stackHasAI bool) (Finding, bool) {
	base := Finding{
		File:     relCompose,
		Line:     svc.NetworkModeLine,
		Evidence: fmt.Sprintf("image=%s network_mode: host", svc.Image),
		Fix:      "Remove network_mode: host and publish only the needed ports bound to 127.0.0.1, or attach to an internal Docker network.",
	}
	switch classifyService(svc.Image, 0) {
	case catInference:
		base.ID, base.Severity = "exposed_inference", SeverityHigh
		base.Title = "Inference API on host network (all interfaces)"
		base.Why = "network_mode: host puts the inference API on every host interface with no port isolation."
	case catUI:
		base.ID, base.Severity = "exposed_ui", SeverityHigh
		base.Title = "UI on host network (all interfaces)"
		base.Why = "network_mode: host exposes the model UI on every host interface."
	case catVector:
		base.ID, base.Severity = "exposed_vector", SeverityHigh
		base.Title = "Vector DB on host network (all interfaces)"
		base.Why = "network_mode: host exposes the vector database on every host interface."
	case catDatastore:
		base.ID = "exposed_datastore"
		base.Title = "Data store on host network (all interfaces)"
		if stackHasAI {
			base.Severity = SeverityHigh
		} else {
			base.Severity = SeverityMedium
		}
		base.Why = "network_mode: host exposes the data store on every host interface."
	default:
		return Finding{}, false
	}
	return base, true
}

// composeHasAIComponent reports whether a compose file contains an inference,
// UI, or vector service — used to raise data-store exposure to HIGH.
func composeHasAIComponent(cf compose.File) bool {
	for _, s := range cf.Services {
		img := strings.ToLower(s.Image)
		if imageIsInference(img) || imageIsUI(img) || imageIsVector(img) {
			return true
		}
		for _, p := range s.Ports {
			switch p.HostPort {
			case 11434, 1234, 7860, 6333, 19530:
				return true
			}
		}
	}
	return false
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
		line := 0
		for _, s := range cf.Services {
			if line == 0 && s.PortsLine > 0 {
				line = s.PortsLine
			}
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
				Line:     line,
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
