package llm

import (
	"encoding/json"
	"regexp"

	"github.com/dzh01/tasia/internal/rules"
)

// secretPatterns is a defense-in-depth net. By construction, deterministic
// findings only ever put non-secret data in Evidence (key names, ports, image
// names, or the flagged config token itself). This catches anything that slips
// through — common token formats and credentials embedded in URLs.
var secretPatterns = []*regexp.Regexp{
	regexp.MustCompile(`sk-[A-Za-z0-9_-]{8,}`),                              // OpenAI-style
	regexp.MustCompile(`hf_[A-Za-z0-9]{8,}`),                                // Hugging Face
	regexp.MustCompile(`gh[posru]_[A-Za-z0-9]{16,}`),                        // GitHub tokens
	regexp.MustCompile(`xox[baprs]-[A-Za-z0-9-]{10,}`),                      // Slack
	regexp.MustCompile(`AKIA[0-9A-Z]{16}`),                                  // AWS access key id
	regexp.MustCompile(`AIza[0-9A-Za-z_-]{20,}`),                            // Google API key
	regexp.MustCompile(`eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+`), // JWT
	regexp.MustCompile(`(?i)://[^/\s:@]+:[^/\s@]+@`),                        // user:pass@ in URL
	regexp.MustCompile(`(?i)\bbearer\s+[A-Za-z0-9._~+/=-]{6,}`),             // Bearer <token>
	regexp.MustCompile(`(?i)\b(token|secret|password|apikey|api_key)\s*[:=]\s*\S{6,}`),
}

// RedactFindings removes any potential secret values. Only keeps structure, ids, titles, files, lines, why/fix (already non-secret).
// Never include Evidence if it could have values, but our rules keep evidence clean.
func RedactFindings(fs []rules.Finding) []rules.Finding {
	out := make([]rules.Finding, len(fs))
	for i, f := range fs {
		out[i] = rules.Finding{
			ID:       f.ID,
			Severity: f.Severity,
			Title:    f.Title,
			File:     f.File,
			Line:     f.Line,
			Evidence: sanitize(f.Evidence),
			Why:      f.Why,
			Fix:      f.Fix,
		}
	}
	return out
}

func sanitize(e string) string {
	for _, re := range secretPatterns {
		e = re.ReplaceAllString(e, "[REDACTED]")
	}
	return e
}

// FactPack is the minimal redacted payload sent to local LLM.
type FactPack struct {
	Decision string          `json:"decision"`
	Risk     string          `json:"risk"`
	Findings []rules.Finding `json:"findings"`
}

// RedactPack returns json of redacted facts.
func RedactPack(decision, risk string, fs []rules.Finding) string {
	p := FactPack{Decision: decision, Risk: risk, Findings: RedactFindings(fs)}
	b, _ := json.MarshalIndent(p, "", "  ")
	return string(b)
}
