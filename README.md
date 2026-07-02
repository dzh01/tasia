# Tasia
Harden private AI stacks before they ship.

Tasia reviews local/private AI deployment configs, flags risky exposure patterns, blocks unsafe pushes, and generates a hardening pack your team can act on.

Private AI is not automatically private.

## Quickstart

```bash
# Install
go install github.com/joeyvictorino/tasia/cmd/tasia@latest

# Review a directory
tasia review --path .

# Example on a known-messy stack
tasia review --path examples/messy-ollama-stack
```

Tasia will:
- Walk compose files, .env*, Dockerfiles
- Extract services, published ports, images, mounts, env key names
- Apply deterministic rules
- Print Decision + Risk + findings with file:line
- Write `.tasia/` pack (never mutates your sources)

## What Tasia catches

| Finding | Severity |
|---------|----------|
| Inference API (Ollama/vLLM/...) published to all interfaces | HIGH |
| Open WebUI / Gradio UI published to all interfaces | HIGH |
| Vector DB (Qdrant/Chroma/...) published to host | HIGH |
| Docker socket mounted | CRITICAL |
| `privileged: true` | CRITICAL |
| `.env` contains token/secret key names (values never printed) | MEDIUM |
| `image: ...:latest` | MEDIUM |
| Broad bind mounts (e.g. `.:/app`) | MEDIUM |
| Permissive CORS e.g. `OLLAMA_ORIGINS=*` | HIGH |
| No internal Docker network separation | MEDIUM |
| No AI stack manifest | LOW |

## What Tasia generates

After `tasia review --path .` you get `.tasia/`:

- `HARDENING_PLAN.md` — decision, risk, every finding with location + why + exact fix + suggested change
- `EXECUTIVE_MEMO.md` — business-oriented summary for leadership
- `ai-stack-manifest.json` — inventory of runtimes / interfaces / retrieval / ports / secrets keys found
- `docker-compose.hardened.override.yml` — safe compose overrides (bind localhost + internal net)
- `firewall-notes.md`
- `findings.json`
- `findings.toon` — compact agent-readable format
- `LLM_REVIEW.md` — optional local-LLM human summary (see below)

## Example: messy Ollama stack

See `examples/messy-ollama-stack/docker-compose.yml`.

Running review yields:

```
TASIA
Decision: BLOCKED
Risk: HIGH
[HIGH] docker-compose.yml:5 Inference API published to all interfaces
[HIGH] docker-compose.yml:9 Open WebUI/Gradio UI published to all interfaces
[HIGH] docker-compose.yml:13 Vector DB published to host
...
Wrote .tasia/ hardening pack
```

## Git pre-push mode

```bash
tasia install --pre-push
```

Creates `.git/hooks/pre-push` that runs:

```
tasia ci --path . --fail-on high
```

A push containing exposed services will be blocked with exit 1.

Remove with `tasia uninstall --pre-push`.

## CI mode

```bash
tasia ci --path . --fail-on high
```

Exit codes:
- `0` = pass
- `1` = blocked findings
- `2` = tool/config error

## Optional local LLM mode

```bash
tasia explain --ollama llama3.1
```

Only redacted findings (no values, no secrets) are sent to your local Ollama. The deterministic rules remain authoritative. LLM only produces nicer prose in `LLM_REVIEW.md`.

The LLM is never required. Tasia is fully functional without it.

## Options for review

```
tasia review --path . --format text|json
tasia review --path . --fail-on high
tasia review --path . --no-write
tasia review --path . --strict
```

## What Tasia does not do

- Does not scan the public internet
- Does not read or print secret values
- Does not auto-edit your files
- Does not require cloud accounts or telemetry
- Does not claim to prove security or compliance

## Threat model

See `docs/threat-model.md`.

## Roadmap

See `docs/roadmap.md`.

v0.1 — Compose hardening (current)

v0.2 — GitHub Action + SARIF, more detections

## Contributing

See `CONTRIBUTING.md`.

## Name

The name is a nod to my daughter Anastasia — and to the AI stacks this tool protects.

The utility stands on its own.
