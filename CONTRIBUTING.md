# Contributing to Tasia

Thank you for your interest.

## Development

- Go 1.21+
- `go test ./...`
- `go run ./cmd/tasia review --path examples/messy-ollama-stack`

## Adding rules

1. Add detection / extraction in `internal/collect` if new config types.
2. Add rule logic in `internal/rules/rules.go` returning `rules.Finding` with id, severity, title, file, line, evidence, why, fix.
3. Never emit secret values.
4. Add table-driven test in `internal/rules/rules_test.go` or `*_test.go`.
5. Update docs/rules.md if user-facing.

## Reporting issues

Use the issue templates. Include:
- `tasia --version` (or commit)
- The compose / config snippet (redact secrets)
- Full output of `tasia review --format json`

## Code of conduct

Be respectful. Focus on the problem of private AI deployments shipping with overly permissive exposure.
