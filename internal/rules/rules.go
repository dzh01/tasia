package rules

import (
	"fmt"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/dzh01/tasia/internal/collect"
	"github.com/dzh01/tasia/internal/collect/compose"
)

// Severity ranks a finding from informational (LOW) to must-fix (CRITICAL).
type Severity string

const (
	SeverityCritical Severity = "CRITICAL"
	SeverityHigh     Severity = "HIGH"
	SeverityMedium   Severity = "MEDIUM"
	SeverityLow      Severity = "LOW"
)

// Rank orders severities so callers can compare and sort without duplicating
// the ordering. Higher means more severe; unknown severities rank lowest.
func (s Severity) Rank() int {
	switch s {
	case SeverityCritical:
		return 4
	case SeverityHigh:
		return 3
	case SeverityMedium:
		return 2
	case SeverityLow:
		return 1
	default:
		return 0
	}
}

// Finding is the core output model. Always includes file:line where possible.
type Finding struct {
	ID       string   `json:"id"`
	Severity Severity `json:"severity"`
	Title    string   `json:"title"`
	File     string   `json:"file"`
	Line     int      `json:"line"`
	Evidence string   `json:"evidence"`
	Why      string   `json:"why"`
	Fix      string   `json:"fix"`
}

// Evaluate applies every deterministic rule to the collected configuration and
// returns the de-duplicated findings.
func Evaluate(c *collect.Collected) []Finding {
	var findings []Finding

	for _, cf := range c.ComposeFiles {
		relPath := composePath(c.Root, cf.Path)
		stackHasAI := composeHasAIComponent(cf)
		for _, svc := range cf.Services {
			findings = append(findings, evaluateService(relPath, svc, stackHasAI)...)
		}
		findings = append(findings, networkSeparationFinding(cf, relPath)...)
	}

	findings = append(findings, envFileFindings(c.EnvFiles)...)
	findings = append(findings, missingManifestFinding(c)...)

	return dedupeFindings(findings)
}

// composePath renders a compose file's path relative to the scan root, falling
// back to the absolute path when it lies outside the root.
func composePath(root, path string) string {
	rel, err := filepath.Rel(root, path)
	if err != nil || rel == "" || strings.HasPrefix(rel, "..") {
		return path
	}
	return rel
}

// evaluateService runs every per-service rule in a readable checklist. Each rule
// is a small, independent function; adding one is a single line here.
func evaluateService(relCompose string, svc compose.Service, stackHasAI bool) []Finding {
	var out []Finding
	appendIf := func(f Finding, ok bool) {
		if ok {
			out = append(out, f)
		}
	}

	appendIf(hostNetworkFinding(svc, relCompose, stackHasAI))
	out = append(out, exposedPortFindings(svc, relCompose, stackHasAI)...)
	appendIf(privilegedFinding(svc, relCompose))
	appendIf(latestImageFinding(svc, relCompose))
	out = append(out, dockerSocketFindings(svc, relCompose)...)
	out = append(out, broadBindMountFindings(svc, relCompose)...)
	out = append(out, environmentFindings(svc, relCompose)...)

	return out
}

// exposureTemplate holds the copy shared by every port-exposure finding of a
// given service category, so the rule reads as data rather than repeated code.
type exposureTemplate struct {
	id, title, why, fix string
}

var exposureTemplates = map[svcCategory]exposureTemplate{
	catInference: {
		id:    "exposed_inference",
		title: "Inference API published to all interfaces",
		why:   "The inference API may be reachable by unintended systems on the host network.",
		fix:   "Bind to localhost unless remote access is intentionally required. Use internal Docker network for other services.",
	},
	catUI: {
		id:    "exposed_ui",
		title: "Open WebUI/Gradio UI published to all interfaces",
		why:   "Web UI for chatting with models should not be reachable from outside the host by default.",
		fix:   "Bind to 127.0.0.1 or put behind auth proxy. Consider internal-only network.",
	},
	catVector: {
		id:    "exposed_vector",
		title: "Vector DB published to host",
		why:   "Vector database contains embeddings that may encode sensitive retrieved data.",
		fix:   "Do not publish vector DB ports to host. Access only via internal Docker network from trusted services.",
	},
}

// exposedPortFindings flags every host-published port that belongs to a
// recognized AI or data-store service.
func exposedPortFindings(svc compose.Service, relCompose string, stackHasAI bool) []Finding {
	var out []Finding
	for _, port := range svc.Ports {
		if port.HostPort <= 0 || !port.IsAllInterfaces() {
			continue
		}
		category := classifyService(svc.Image, port.HostPort)
		evidence := fmt.Sprintf("image=%s port=%s", svc.Image, port.Raw)

		if category == catDatastore {
			out = append(out, datastoreExposure(relCompose, port.Line, evidence, stackHasAI))
			continue
		}
		if tmpl, ok := exposureTemplates[category]; ok {
			out = append(out, Finding{
				ID:       tmpl.id,
				Severity: SeverityHigh,
				Title:    tmpl.title,
				File:     relCompose,
				Line:     port.Line,
				Evidence: evidence,
				Why:      tmpl.why,
				Fix:      tmpl.fix,
			})
		}
	}
	return out
}

// datastoreExposure escalates to HIGH when the data store sits alongside AI
// components (it likely holds prompts, chats, or embeddings).
func datastoreExposure(relCompose string, line int, evidence string, stackHasAI bool) Finding {
	severity := SeverityMedium
	why := "Data store published to the host is reachable beyond the container network; unauthenticated defaults are common."
	if stackHasAI {
		severity = SeverityHigh
		why = "Data store backing an AI stack (may hold prompts, chats, or embeddings) is published to all interfaces alongside AI services."
	}
	return Finding{
		ID:       "exposed_datastore",
		Severity: severity,
		Title:    "Data store (Redis/Postgres) published to host",
		File:     relCompose,
		Line:     line,
		Evidence: evidence,
		Why:      why,
		Fix:      "Do not publish the data store port to the host. Bind to 127.0.0.1 or use an internal Docker network with credentials.",
	}
}

func privilegedFinding(svc compose.Service, relCompose string) (Finding, bool) {
	if !svc.Privileged {
		return Finding{}, false
	}
	return Finding{
		ID:       "privileged_container",
		Severity: SeverityCritical,
		Title:    "privileged: true",
		File:     relCompose,
		Line:     svc.PrivLine,
		Evidence: fmt.Sprintf("service=%s privileged=true", svc.Name),
		Why:      "Privileged containers have full host access and defeat container isolation.",
		Fix:      "Remove privileged: true. Use specific capabilities only if absolutely required.",
	}, true
}

func latestImageFinding(svc compose.Service, relCompose string) (Finding, bool) {
	if !strings.HasSuffix(svc.Image, ":latest") && !untagged(svc.Image) {
		return Finding{}, false
	}
	return Finding{
		ID:       "latest_image",
		Severity: SeverityMedium,
		Title:    "image uses latest",
		File:     relCompose,
		Line:     svc.ImageLine,
		Evidence: svc.Image,
		Why:      "latest tag is mutable and makes reproducible deploys and rollbacks impossible.",
		Fix:      "Pin to a specific version tag or digest.",
	}, true
}

func dockerSocketFindings(svc compose.Service, relCompose string) []Finding {
	var out []Finding
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
	return out
}

func broadBindMountFindings(svc compose.Service, relCompose string) []Finding {
	var out []Finding
	for _, v := range svc.Volumes {
		broad := strings.HasPrefix(v, ".:") || strings.HasPrefix(v, "./:") || strings.Contains(v, ":/app")
		if broad && !isReadOnlyMount(v) {
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
	return out
}

// environmentFindings inspects compose environment entries for secret key names
// and permissive CORS settings. Values are never emitted, only key names.
func environmentFindings(svc compose.Service, relCompose string) []Finding {
	var out []Finding
	for _, entry := range svc.Environment {
		key, value, _ := strings.Cut(entry, "=")
		key = strings.TrimSpace(key)
		value = strings.TrimSpace(value)

		if collect.LooksLikeSecretKeyName(key) {
			out = append(out, Finding{
				ID:       "env_token_key",
				Severity: SeverityMedium,
				Title:    fmt.Sprintf("service env contains token key name: %s", key),
				File:     relCompose,
				Line:     svc.EnvLine,
				Evidence: key,
				Why:      "Token/secret key names in compose environment may indicate credentials. Values are not inspected or emitted.",
				Fix:      "Inject real secrets at deploy time (e.g. secrets, sops, platform env); commit only placeholders.",
			})
		}
		if isCORSKey(key) && isPermissiveOrigin(value) {
			out = append(out, Finding{
				ID:       "permissive_cors",
				Severity: SeverityHigh,
				Title:    "permissive CORS (e.g. OLLAMA_ORIGINS=*)",
				File:     relCompose,
				Line:     svc.EnvLine,
				Evidence: entry,
				Why:      "Wildcard or empty CORS on AI endpoints allows arbitrary web pages to make cross-origin requests to the model or UI.",
				Fix:      "Set explicit allowlist for OLLAMA_ORIGINS (or equivalent), e.g. http://localhost:*, or remove the var and use a reverse proxy with controlled CORS.",
			})
		}
	}
	return out
}

func isCORSKey(key string) bool {
	upper := strings.ToUpper(key)
	return upper == "OLLAMA_ORIGINS" || strings.Contains(upper, "CORS") || strings.Contains(upper, "ALLOW_ORIGINS")
}

func isPermissiveOrigin(value string) bool {
	return value == "" || strings.Contains(value, "*")
}

// envFileFindings reports secret-looking key names discovered in .env* files.
func envFileFindings(envFiles []collect.EnvFile) []Finding {
	var out []Finding
	for _, ef := range envFiles {
		for _, key := range ef.Keys {
			out = append(out, Finding{
				ID:       "env_token_key",
				Severity: SeverityMedium,
				Title:    fmt.Sprintf(".env contains token key name: %s", key.Name),
				File:     ef.Path,
				Line:     key.Line,
				Evidence: key.Name,
				Why:      "Token or secret key names in env files indicate credentials may be present. Never commit real secrets; use .env.example.",
				Fix:      "Move real secrets out of repo; add .env to .gitignore; provide .env.example with placeholders only.",
			})
		}
	}
	return out
}

// missingManifestFinding notes an AI stack that lacks an inventory manifest.
func missingManifestFinding(c *collect.Collected) []Finding {
	if len(c.ComposeFiles) == 0 || c.HasManifest {
		return nil
	}
	for _, f := range c.OtherConfigs {
		if strings.Contains(strings.ToLower(f), "ai-stack-manifest") {
			return nil
		}
	}
	return []Finding{{
		ID:       "no_ai_stack_manifest",
		Severity: SeverityLow,
		Title:    "no AI stack manifest",
		File:     ".",
		Line:     0,
		Evidence: "missing ai-stack-manifest.json",
		Why:      "Without an inventory of runtimes, interfaces and retrieval, future reviews and audits are harder.",
		Fix:      "Generate or commit ai-stack-manifest.json (Tasia can produce one).",
	}}
}

// untagged reports whether an image reference has no explicit tag, inspecting
// only the final path segment so a registry host port (myreg:5000/img) or a
// digest (img@sha256:...) is not mistaken for a tag.
func untagged(image string) bool {
	seg := image
	if i := strings.LastIndex(seg, "/"); i >= 0 {
		seg = seg[i+1:]
	}
	if strings.Contains(seg, "@") { // pinned by digest
		return false
	}
	return !strings.Contains(seg, ":")
}

// isReadOnlyMount reports whether a volume string's mode field is read-only.
func isReadOnlyMount(v string) bool {
	parts := strings.Split(v, ":")
	return len(parts) > 0 && parts[len(parts)-1] == "ro"
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

// imageKeywords maps a category to the image-name substrings that identify it.
var imageKeywords = map[svcCategory][]string{
	catInference: {"ollama", "vllm", "llama.cpp", "llamacpp", "lmstudio", "lm-studio"},
	catUI:        {"open-webui", "openwebui", "gradio"},
	catVector:    {"qdrant", "chroma", "weaviate", "milvus"},
	catDatastore: {"redis", "valkey", "postgres", "pgvector"},
}

// portCategory maps a well-known host port to its service category, so bare or
// unknown images are still classified (e.g. LM Studio on 1234, Milvus on 19530).
var portCategory = map[int]svcCategory{
	11434: catInference,
	1234:  catInference,
	7860:  catUI,
	6333:  catVector,
	19530: catVector,
	6379:  catDatastore,
	5432:  catDatastore,
}

// classifyService categorizes a service by image name first, then falls back to
// the published host port. Image name is checked in a fixed category order so
// classification is deterministic.
func classifyService(image string, hostPort int) svcCategory {
	img := strings.ToLower(image)
	for _, category := range []svcCategory{catInference, catUI, catVector, catDatastore} {
		if containsAny(img, imageKeywords[category]) {
			return category
		}
	}
	return portCategory[hostPort] // catOther (zero value) when unknown
}

func containsAny(s string, needles []string) bool {
	for _, n := range needles {
		if strings.Contains(s, n) {
			return true
		}
	}
	return false
}

// hostNetworkFinding returns an exposure finding for a recognized AI/datastore
// service running on the host network (network_mode: host). Such a service is
// reachable on all host interfaces with no ports: mapping to inspect.
func hostNetworkFinding(svc compose.Service, relCompose string, stackHasAI bool) (Finding, bool) {
	if !strings.EqualFold(svc.NetworkMode, "host") {
		return Finding{}, false
	}
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
	isAI := func(c svcCategory) bool {
		return c == catInference || c == catUI || c == catVector
	}
	for _, svc := range cf.Services {
		if isAI(classifyService(svc.Image, 0)) {
			return true
		}
		for _, port := range svc.Ports {
			if isAI(portCategory[port.HostPort]) {
				return true
			}
		}
	}
	return false
}

// networkSeparationFinding flags a multi-service stack that publishes ports but
// defines no internal-only network to limit lateral movement.
func networkSeparationFinding(cf compose.File, relCompose string) []Finding {
	for _, n := range cf.Networks {
		if n.Internal {
			return nil
		}
	}
	if len(cf.Services) <= 1 {
		return nil
	}

	publishLine := 0
	published := false
	for _, svc := range cf.Services {
		if publishLine == 0 && svc.PortsLine > 0 {
			publishLine = svc.PortsLine
		}
		for _, port := range svc.Ports {
			if port.HostPort > 0 {
				published = true
			}
		}
	}
	if !published {
		return nil
	}

	return []Finding{{
		ID:       "no_internal_network",
		Severity: SeverityMedium,
		Title:    "no internal Docker network separation",
		File:     relCompose,
		Line:     publishLine,
		Evidence: "no internal: true network defined",
		Why:      "Services share the default Docker bridge network and can reach each other freely; an internal network limits lateral movement.",
		Fix:      "Define an internal network and attach AI services to it. Publish only the minimum gateway if needed.",
	}}
}

// dedupeFindings removes findings that are identical in id, location, and
// evidence (the same issue reported by more than one rule path).
func dedupeFindings(in []Finding) []Finding {
	seen := make(map[string]bool, len(in))
	out := make([]Finding, 0, len(in))
	for _, f := range in {
		key := strings.Join([]string{f.ID, f.File, strconv.Itoa(f.Line), f.Evidence}, "\x00")
		if !seen[key] {
			seen[key] = true
			out = append(out, f)
		}
	}
	return out
}
