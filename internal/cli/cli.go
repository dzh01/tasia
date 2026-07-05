package cli

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/dzh01/tasia/internal/collect"
	"github.com/dzh01/tasia/internal/llm"
	"github.com/dzh01/tasia/internal/report"
	"github.com/dzh01/tasia/internal/rules"
)

// Build metadata, overridden at release time via -ldflags.
var (
	Version = "dev"
	Commit  = "none"
	Date    = "unknown"
)

// Run parses args and dispatches commands. Thin layer.
func Run(args []string) error {
	if len(args) == 0 {
		printUsage()
		return nil
	}

	cmd := args[0]
	switch cmd {
	case "review":
		return runReview(args[1:])
	case "ci":
		return runCI(args[1:])
	case "install":
		return runInstall(args[1:])
	case "uninstall":
		return runUninstall(args[1:])
	case "explain":
		return runExplain(args[1:])
	case "version", "--version", "-v":
		fmt.Printf("tasia %s (commit %s, built %s)\n", Version, Commit, Date)
		return nil
	case "help", "-h", "--help":
		printUsage()
		return nil
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n", cmd)
		printUsage()
		return fmt.Errorf("unknown command")
	}
}

func printUsage() {
	fmt.Println(`Tasia — private AI stack hardening gate

Usage:
  tasia review [--path .] [--format text|json] [--fail-on high|medium|critical] [--no-write] [--strict]
  tasia ci [--path .] [--fail-on high]
  tasia install --pre-push
  tasia uninstall --pre-push
  tasia explain [--path .] [--ollama llama3.1] [--ollama-host localhost:11434]
  tasia version
  tasia help

Review local/private AI deployment configs, block risky patterns, generate hardening pack.`)
}

func runReview(args []string) error {
	fs := flag.NewFlagSet("review", flag.ContinueOnError)
	path := fs.String("path", ".", "path to scan")
	format := fs.String("format", "text", "output format: text or json")
	failOn := fs.String("fail-on", "", "fail level: critical, high, medium")
	noWrite := fs.Bool("no-write", false, "do not write .tasia/ artifacts")
	strict := fs.Bool("strict", false, "treat warnings as blocking too")
	if err := fs.Parse(args); err != nil {
		return err
	}

	absPath, err := filepath.Abs(*path)
	if err != nil {
		return err
	}

	// Collect
	collected, err := collect.WalkAndCollect(absPath)
	if err != nil {
		return err
	}

	// Rules
	findings := rules.Evaluate(collected)

	// Decide
	decision, risk := report.Decide(findings, *failOn, *strict)

	// Write unless no-write (do this first so side-effects don't affect format)
	wrotePath := ""
	if !*noWrite {
		outDir := filepath.Join(absPath, ".tasia")
		if err := os.MkdirAll(outDir, 0755); err != nil {
			return err
		}
		if err := report.WriteArtifacts(outDir, collected, findings, decision, risk); err != nil {
			return err
		}
		wrotePath = outDir
	}

	// Terminal (json must be pure on stdout)
	if *format == "json" {
		out, _ := report.FindingsToJSON(findings, decision, risk)
		fmt.Println(out)
		if wrotePath != "" {
			fmt.Fprintf(os.Stderr, "Wrote .tasia/ hardening pack to %s\n", wrotePath)
		}
	} else {
		report.PrintSummary(findings, decision, risk)
		if wrotePath != "" {
			fmt.Printf("\nWrote .tasia/ hardening pack to %s\n", wrotePath)
		}
	}

	// Exit behavior for review: do not auto-exit non-zero here unless?
	// The spec uses ci for blocking. Review just reports.
	return nil
}

func runCI(args []string) error {
	fs := flag.NewFlagSet("ci", flag.ContinueOnError)
	path := fs.String("path", ".", "path to scan")
	failOn := fs.String("fail-on", "high", "fail level: critical, high, medium, low")
	if err := fs.Parse(args); err != nil {
		return err
	}

	absPath, err := filepath.Abs(*path)
	if err != nil {
		return err
	}

	collected, err := collect.WalkAndCollect(absPath)
	if err != nil {
		return err
	}
	findings := rules.Evaluate(collected)
	decision, risk := report.Decide(findings, *failOn, false)

	report.PrintSummary(findings, decision, risk)

	if decision == "BLOCKED" {
		fmt.Fprintf(os.Stderr, "CI blocked: %s risk findings present\n", risk)
		os.Exit(1)
	}
	return nil
}

func runInstall(args []string) error {
	fs := flag.NewFlagSet("install", flag.ContinueOnError)
	prePush := fs.Bool("pre-push", false, "install pre-push git hook")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if !*prePush {
		fmt.Println("usage: tasia install --pre-push")
		return nil
	}

	gitRoot, err := findGitRoot()
	if err != nil {
		return err
	}
	hookDir := filepath.Join(gitRoot, ".git", "hooks")
	if err := os.MkdirAll(hookDir, 0755); err != nil {
		return err
	}
	hookPath := filepath.Join(hookDir, "pre-push")

	// Resolve tasia from PATH at hook-run time so the hook keeps working if the
	// binary is upgraded or moved. Fail closed (block the push) if it is missing.
	hookContent := "#!/bin/sh\n" +
		"# Installed by tasia install --pre-push\n" +
		"if ! command -v tasia >/dev/null 2>&1; then\n" +
		"  echo \"tasia not found in PATH — install it or run: tasia uninstall --pre-push\" >&2\n" +
		"  exit 1\n" +
		"fi\n" +
		"tasia ci --path . --fail-on high || exit 1\n"

	if err := os.WriteFile(hookPath, []byte(hookContent), 0755); err != nil {
		return err
	}
	fmt.Printf("Installed pre-push hook at %s\n", hookPath)
	fmt.Println("It will run: tasia ci --path . --fail-on high (tasia resolved from PATH)")
	return nil
}

func runUninstall(args []string) error {
	// Support tasia uninstall --pre-push
	fs := flag.NewFlagSet("uninstall", flag.ContinueOnError)
	prePush := fs.Bool("pre-push", false, "remove pre-push git hook")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if !*prePush {
		fmt.Println("usage: tasia uninstall --pre-push")
		return nil
	}
	gitRoot, err := findGitRoot()
	if err != nil {
		return err
	}
	hookPath := filepath.Join(gitRoot, ".git", "hooks", "pre-push")
	if _, err := os.Stat(hookPath); os.IsNotExist(err) {
		fmt.Println("No pre-push hook to remove.")
		return nil
	}
	if err := os.Remove(hookPath); err != nil {
		return err
	}
	fmt.Printf("Removed %s\n", hookPath)
	return nil
}

// findGitRoot walks upward from cwd to locate the directory containing .git
func findGitRoot() (string, error) {
	dir, err := os.Getwd()
	if err != nil {
		return "", err
	}
	for {
		if st, err := os.Stat(filepath.Join(dir, ".git")); err == nil && st.IsDir() {
			return dir, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir || parent == "" {
			break
		}
		dir = parent
	}
	return "", fmt.Errorf("no .git directory found (run from inside a git repo)")
}

func runExplain(args []string) error {
	fs := flag.NewFlagSet("explain", flag.ContinueOnError)
	path := fs.String("path", ".", "path to scan")
	ollama := fs.String("ollama", "", "ollama model name for local explanation (e.g. llama3.1)")
	ollamaHost := fs.String("ollama-host", llm.DefaultOllamaHost, "host[:port] of local Ollama")
	if err := fs.Parse(args); err != nil {
		return err
	}

	absPath, err := filepath.Abs(*path)
	if err != nil {
		return err
	}
	collected, err := collect.WalkAndCollect(absPath)
	if err != nil {
		return err
	}
	findings := rules.Evaluate(collected)
	decision, risk := report.Decide(findings, "high", false)

	redacted := llm.RedactPack(decision, risk, findings)

	outDir := filepath.Join(absPath, ".tasia")
	if err := os.MkdirAll(outDir, 0755); err != nil {
		return err
	}

	// Without a model we cannot call Ollama. Write the redacted facts and the
	// exact command to populate prose. This never fails and never transmits.
	if *ollama == "" {
		review := "# LLM_REVIEW.md\n\n" +
			"Deterministic rule findings are the source of truth. This file is optional prose only.\n\n" +
			"Run with `--ollama <model>` to generate a human-readable summary from the redacted facts below:\n\n" +
			"    tasia explain --ollama llama3.1\n\n" +
			"## Redacted facts sent to the local model\n\n" +
			"```json\n" + redacted + "\n```\n"
		if err := os.WriteFile(filepath.Join(outDir, "LLM_REVIEW.md"), []byte(review), 0644); err != nil {
			return err
		}
		fmt.Printf("Wrote redacted facts to %s (no model called; pass --ollama <model> for prose).\n", filepath.Join(outDir, "LLM_REVIEW.md"))
		return nil
	}

	// Real call: send ONLY the redacted pack to the local Ollama.
	client := llm.NewOllamaClient(*ollamaHost)
	fmt.Printf("Sending redacted findings (decision=%s risk=%s, %d findings) to local model %q at %s ...\n",
		decision, risk, len(findings), *ollama, client.Host)

	prose, err := client.Explain(*ollama, decision, risk, findings)
	if err != nil {
		// LLM problems are tool/config errors (exit 2), never a review failure.
		return fmt.Errorf("local LLM explanation failed (deterministic findings are unaffected): %v\n"+
			"Is Ollama running? Try: ollama serve  and  ollama pull %s", err, *ollama)
	}

	review := "# LLM_REVIEW.md\n\n" +
		"> Generated by a local Ollama model (`" + *ollama + "`) from redacted facts only.\n" +
		"> Deterministic rule findings remain the source of truth; this prose is advisory.\n\n" +
		"## Summary\n\n" + prose + "\n\n" +
		"## Redacted facts provided to the model\n\n" +
		"```json\n" + redacted + "\n```\n"
	if err := os.WriteFile(filepath.Join(outDir, "LLM_REVIEW.md"), []byte(review), 0644); err != nil {
		return err
	}
	fmt.Printf("Wrote %s\n", filepath.Join(outDir, "LLM_REVIEW.md"))
	return nil
}
