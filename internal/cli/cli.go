package cli

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/joeyvictorino/tasia/internal/collect"
	"github.com/joeyvictorino/tasia/internal/llm"
	"github.com/joeyvictorino/tasia/internal/report"
	"github.com/joeyvictorino/tasia/internal/rules"
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
  tasia explain [--ollama llama3.1]
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

	hookPath, err := prePushHookPath()
	if err != nil {
		return err
	}
	hookContent := `#!/bin/sh
# Installed by tasia install --pre-push
tasia ci --path . --fail-on high || exit 1
`
	if err := os.WriteFile(hookPath, []byte(hookContent), 0755); err != nil {
		return err
	}
	fmt.Printf("Installed pre-push hook at %s\n", hookPath)
	fmt.Println("It will run: tasia ci --path . --fail-on high")
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
	hookPath, err := prePushHookPath()
	if err != nil {
		return err
	}
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

func prePushHookPath() (string, error) {
	gitDir := ".git"
	if _, err := os.Stat(gitDir); os.IsNotExist(err) {
		return "", fmt.Errorf("no .git directory found; run from repo root")
	}
	return filepath.Join(gitDir, "hooks", "pre-push"), nil
}

func runExplain(args []string) error {
	fs := flag.NewFlagSet("explain", flag.ContinueOnError)
	path := fs.String("path", ".", "path to scan")
	ollama := fs.String("ollama", "", "ollama model name for local explanation (optional)")
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

	// Always write/overwrite LLM_REVIEW.md with redacted + note
	outDir := filepath.Join(absPath, ".tasia")
	os.MkdirAll(outDir, 0755)
	llmReview := "# LLM_REVIEW.md (redacted facts only)\n\n" +
		"Rule-based findings are the source of truth. The following was provided to local LLM for human-friendly summary only.\n\n" +
		"```json\n" + redacted + "\n```\n\n" +
		"## Human-readable summary (if model was used)\n\n" +
		"Local LLM mode was invoked with model: " + *ollama + "\n" +
		"(In real run, a local Ollama call would produce prose here.)\n"
	if *ollama == "" {
		llmReview = "# LLM_REVIEW.md\n\n" +
			"Run with --ollama <model> to populate a human explanation based on redacted facts.\n" +
			"Example: tasia explain --ollama llama3.1\n\n" + llmReview
	}
	if err := os.WriteFile(filepath.Join(outDir, "LLM_REVIEW.md"), []byte(llmReview), 0644); err != nil {
		return err
	}
	fmt.Printf("Wrote redacted LLM_REVIEW.md (decision=%s risk=%s, %d findings redacted)\n", decision, risk, len(findings))
	if *ollama != "" {
		fmt.Printf("Sent only redacted pack to local %s (simulated).\n", *ollama)
	}
	return nil
}
