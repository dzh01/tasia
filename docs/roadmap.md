# Roadmap

## v0.1 — Compose hardening (current)

- `review`, `ci`, `install`/`uninstall --pre-push`, `explain`, `version`
- 12 deterministic rules with real line numbers via yaml.v3 nodes
- Detection: Ollama, vLLM, llama.cpp, LM Studio, Open WebUI, Gradio,
  Qdrant, Chroma, Weaviate, Milvus, Redis, Postgres
- Full `.tasia/` hardening pack (never edits your files)
- Optional local `explain` via Ollama (redacted findings only)
- Prebuilt binaries (darwin/linux, arm64/amd64) with checksums

## v0.2

- GitHub Action + SARIF output
- `network_mode: host` rule
- Caddyfile / nginx auth checks
- Chroma / Weaviate auth hints
- Dockerfile `USER root` / `EXPOSE` analysis

## v0.3

- Kubernetes / Helm basics
- Ignore / policy file (`.tasiaignore`)
- Configurable rule severities

## v1.0

Stable rule IDs, findings JSON schema, documented public API, versioned rule catalog.
