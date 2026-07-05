package report

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/dzh01/tasia/internal/collect"
	"github.com/dzh01/tasia/internal/rules"
)

// Decide computes the overall decision and risk from the findings. A finding at
// or above the fail-on threshold blocks; --strict blocks on MEDIUM and above.
func Decide(findings []rules.Finding, failOn string, strict bool) (decision, risk string) {
	threshold := rules.Severity(strings.ToUpper(failOn))
	if threshold == "" {
		threshold = rules.SeverityHigh
	}

	maxSeverity := rules.SeverityLow
	blocked := false
	for _, f := range findings {
		if f.Severity.Rank() > maxSeverity.Rank() {
			maxSeverity = f.Severity
		}
		if f.Severity.Rank() >= threshold.Rank() {
			blocked = true
		}
		if strict && f.Severity.Rank() >= rules.SeverityMedium.Rank() {
			blocked = true
		}
	}

	decision = "PASS"
	if blocked {
		decision = "BLOCKED"
	}
	return decision, string(maxSeverity)
}

// severityOrder is the display order for grouped output, most severe first.
var severityOrder = []rules.Severity{
	rules.SeverityCritical, rules.SeverityHigh, rules.SeverityMedium, rules.SeverityLow,
}

// PrintSummary prints the terminal view used by review and ci.
func PrintSummary(findings []rules.Finding, decision, risk string) {
	fmt.Println("TASIA")
	fmt.Printf("Decision: %s\n", decision)
	fmt.Printf("Risk: %s\n", risk)

	// group by severity for nice output
	bySev := groupBySev(findings)
	for _, sev := range severityOrder {
		list := bySev[sev]
		if len(list) == 0 {
			continue
		}
		for _, f := range list {
			loc := ""
			if f.Line > 0 {
				loc = fmt.Sprintf("%s:%d", f.File, f.Line)
			} else {
				loc = f.File
			}
			fmt.Printf("[%s] %s %s\n", f.Severity, loc, f.Title)
		}
	}

	if decision == "BLOCKED" {
		fmt.Printf("\n%d finding(s) require attention before shipping this private AI stack.\n", len(findings))
	} else {
		fmt.Println("\nNo blocking findings.")
	}
}

// FindingsToJSON for --format json
func FindingsToJSON(findings []rules.Finding, decision, risk string) (string, error) {
	type out struct {
		Decision string          `json:"decision"`
		Risk     string          `json:"risk"`
		Findings []rules.Finding `json:"findings"`
	}
	o := out{Decision: decision, Risk: risk, Findings: findings}
	b, err := json.MarshalIndent(o, "", "  ")
	return string(b), err
}

// WriteArtifacts creates the full .tasia/ pack.
func WriteArtifacts(outDir string, c *collect.Collected, findings []rules.Finding, decision, risk string) error {
	// HARDENING_PLAN.md
	plan := buildHardeningPlan(findings, decision, risk, c)
	if err := os.WriteFile(filepath.Join(outDir, "HARDENING_PLAN.md"), []byte(plan), 0644); err != nil {
		return err
	}

	// EXECUTIVE_MEMO.md
	memo := buildExecutiveMemo(findings, decision, risk, c)
	if err := os.WriteFile(filepath.Join(outDir, "EXECUTIVE_MEMO.md"), []byte(memo), 0644); err != nil {
		return err
	}

	// ai-stack-manifest.json
	manifest := buildManifest(c, findings, decision, risk)
	mb, _ := json.MarshalIndent(manifest, "", "  ")
	if err := os.WriteFile(filepath.Join(outDir, "ai-stack-manifest.json"), mb, 0644); err != nil {
		return err
	}

	// docker-compose.hardened.override.yml
	override := buildHardenedOverride(c, findings)
	if err := os.WriteFile(filepath.Join(outDir, "docker-compose.hardened.override.yml"), []byte(override), 0644); err != nil {
		return err
	}

	// firewall-notes.md
	fw := buildFirewallNotes(c, findings)
	if err := os.WriteFile(filepath.Join(outDir, "firewall-notes.md"), []byte(fw), 0644); err != nil {
		return err
	}

	// findings.json
	fj, _ := json.MarshalIndent(findings, "", "  ")
	if err := os.WriteFile(filepath.Join(outDir, "findings.json"), fj, 0644); err != nil {
		return err
	}

	// findings.toon (compact agent format)
	toon := buildFindingsToon(findings)
	if err := os.WriteFile(filepath.Join(outDir, "findings.toon"), []byte(toon), 0644); err != nil {
		return err
	}

	// LLM_REVIEW.md is intentionally NOT written here. It is produced only by
	// `tasia explain` so the pack never implies an LLM was consulted.

	return nil
}

func buildHardeningPlan(findings []rules.Finding, decision, risk string, c *collect.Collected) string {
	var b strings.Builder
	b.WriteString("# Tasia Hardening Plan\n\n")
	b.WriteString(fmt.Sprintf("## Decision\n%s\n\n", decision))
	b.WriteString(fmt.Sprintf("## Risk\n%s\n\n", risk))
	b.WriteString("## Summary\n")
	if decision == "BLOCKED" {
		b.WriteString("This stack exposes inference, UI, and/or vector database services beyond the minimum safe boundary.\n\n")
	} else {
		b.WriteString("Stack passes basic hardening checks.\n\n")
	}

	b.WriteString("## Findings\n")
	if len(findings) == 0 {
		b.WriteString("No findings.\n")
		return b.String()
	}

	// group
	bySev := groupBySev(findings)
	for _, sev := range severityOrder {
		list := bySev[sev]
		for _, f := range list {
			b.WriteString(fmt.Sprintf("### %s: %s\n", f.Severity, f.Title))
			loc := f.File
			if f.Line > 0 {
				loc = fmt.Sprintf("%s:%d", f.File, f.Line)
			}
			b.WriteString(fmt.Sprintf("File: %s\n", loc))
			b.WriteString(fmt.Sprintf("Evidence: %s\n\n", f.Evidence))
			b.WriteString("Why it matters:\n")
			b.WriteString(f.Why + "\n\n")
			b.WriteString("Recommended fix:\n")
			b.WriteString(f.Fix + "\n\n")
			// suggested change for ports
			if strings.Contains(f.ID, "exposed_") || strings.Contains(f.Title, "published") {
				b.WriteString("Suggested change:\n")
				// naive from evidence or common
				if strings.Contains(f.Evidence, "11434") {
					b.WriteString(`"11434:11434" → "127.0.0.1:11434:11434"`)
				} else if strings.Contains(f.Evidence, "3000") || strings.Contains(f.Evidence, "8080") {
					b.WriteString(`"3000:8080" → "127.0.0.1:3000:8080"`)
				} else if strings.Contains(f.Evidence, "6333") {
					b.WriteString(`"6333:6333" → remove port or use internal network only`)
				} else {
					b.WriteString("Bind published ports to 127.0.0.1: or remove host publication.")
				}
				b.WriteString("\n\n")
			}
		}
	}
	return b.String()
}

func buildExecutiveMemo(findings []rules.Finding, decision, risk string, c *collect.Collected) string {
	var b strings.Builder
	b.WriteString("# Private AI Deployment Memo\n\n")
	b.WriteString("## Summary\n")
	b.WriteString("This local/private AI deployment should not be treated as production-ready until inference, UI, and retrieval services are restricted and documented.\n\n")
	b.WriteString("## Business Risk\n")
	b.WriteString("If this stack processes sensitive internal data, exposed services may create unauthorized access paths to model interfaces or retrieval infrastructure.\n\n")
	b.WriteString("## Recommendation\n")
	if decision == "BLOCKED" {
		b.WriteString("Do not ship this deployment as-is. Apply the hardening plan, document the AI stack manifest, and re-run Tasia.\n")
	} else {
		b.WriteString("Proceed but consider documenting the stack and re-running periodically.\n")
	}
	b.WriteString("\nGenerated by Tasia.\n")
	return b.String()
}

func buildManifest(c *collect.Collected, findings []rules.Finding, decision, risk string) map[string]interface{} {
	// simple aggregation
	ports := append([]int{}, c.PublishedPorts...)
	sort.Ints(ports)
	secrets := append([]string{}, c.SecretKeyNames...)
	sort.Strings(secrets)
	return map[string]interface{}{
		"tool":                   "tasia",
		"runtimes":               c.DetectedRuntimes,
		"interfaces":             c.DetectedInterfaces,
		"retrieval_databases":    c.DetectedRetrieval,
		"published_ports":        ports,
		"secret_key_names_found": secrets,
		"risk":                   risk,
		"decision":               decision,
		"compose_files":          len(c.ComposeFiles),
	}
}

func buildHardenedOverride(c *collect.Collected, findings []rules.Finding) string {
	var b strings.Builder
	b.WriteString("services:\n")
	// For every compose service we saw, suggest hardened version
	seen := map[string]bool{}
	for _, cf := range c.ComposeFiles {
		for _, svc := range cf.Services {
			key := svc.Name
			if seen[key] {
				continue
			}
			seen[key] = true

			imgLower := strings.ToLower(svc.Image)
			isVector := strings.Contains(imgLower, "qdrant") || strings.Contains(imgLower, "chroma") || strings.Contains(imgLower, "weaviate") || strings.Contains(imgLower, "milvus")
			b.WriteString(fmt.Sprintf("  %s:\n", svc.Name))
			// ports suggestion
			if isVector {
				// Vector DBs must not publish ports to host; access only via internal network
				b.WriteString("    ports: []\n")
			} else {
				hasPub := false
				for _, p := range svc.Ports {
					if p.HostPort > 0 {
						hasPub = true
						safe := fmt.Sprintf("\"127.0.0.1:%d:%d\"", p.HostPort, p.TargetPort)
						b.WriteString("    ports:\n")
						b.WriteString(fmt.Sprintf("      - %s\n", safe))
						break
					}
				}
				if !hasPub {
					b.WriteString("    ports: []\n")
				}
			}
			b.WriteString("    networks:\n      - ai_internal\n")
			if isVector {
				b.WriteString("    # vector DBs should not publish ports; access via internal network only\n")
			}
		}
	}
	b.WriteString("networks:\n  ai_internal:\n    internal: true\n")
	return b.String()
}

func buildFirewallNotes(c *collect.Collected, findings []rules.Finding) string {
	var b strings.Builder
	b.WriteString("# Firewall / Network Notes\n\n")
	b.WriteString("Suggested host firewall / docker network posture for private AI:\n\n")
	b.WriteString("- Do not expose 11434 (Ollama), 3000/8080 (WebUI), 6333 (Qdrant) etc. to the wider LAN.\n")
	b.WriteString("- Prefer Docker internal networks (as in the override).\n")
	b.WriteString("- If remote access to inference is required, front it with authenticated proxy + mTLS or Tailscale/Headscale.\n")
	b.WriteString("- Consider host firewall rules to allow only localhost for these ports.\n\n")
	b.WriteString("Tasia did not modify your host firewall.\n")
	return b.String()
}

func buildFindingsToon(findings []rules.Finding) string {
	var b strings.Builder
	b.WriteString(fmt.Sprintf("findings[%d]:\n", len(findings)))
	for _, f := range findings {
		loc := f.File
		if f.Line > 0 {
			loc = fmt.Sprintf("%s:%d", f.File, f.Line)
		}
		b.WriteString(fmt.Sprintf("  - id: %s\n", f.ID))
		b.WriteString(fmt.Sprintf("    sev: %s\n", f.Severity))
		b.WriteString(fmt.Sprintf("    file: %s\n", loc))
		b.WriteString(fmt.Sprintf("    why: %s\n", strings.ReplaceAll(f.Why, "\n", " ")))
		b.WriteString(fmt.Sprintf("    fix: %s\n", strings.ReplaceAll(f.Fix, "\n", " ")))
	}
	return b.String()
}

func groupBySev(fs []rules.Finding) map[rules.Severity][]rules.Finding {
	m := map[rules.Severity][]rules.Finding{}
	for _, f := range fs {
		m[f.Severity] = append(m[f.Severity], f)
	}
	return m
}
