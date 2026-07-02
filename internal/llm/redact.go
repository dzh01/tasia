package llm

import (
	"encoding/json"
	"strings"

	"github.com/joeyvictorino/tasia/internal/rules"
)

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
	// strip obvious secrets patterns if somehow present
	low := strings.ToLower(e)
	if strings.Contains(low, "sk-") || strings.Contains(low, "hf_") {
		return "[REDACTED]"
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
