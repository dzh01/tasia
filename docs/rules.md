# Tasia Rules

All rules are deterministic. Every finding carries `id`, `severity`, `title`,
`file`, `line` (from YAML nodes / env line numbers where applicable), `evidence`,
`why`, and `fix`. Secret **values** are never read, stored, or emitted — only key
names.

## Detection

Services are classified by image name first, then by published host port so bare
or unknown images on well-known ports are still caught.

| Category | Image match (substring, case-insensitive) | Fallback host ports |
|----------|--------------------------------------------|---------------------|
| Inference | `ollama`, `vllm`, `llama.cpp`, `llamacpp`, `lmstudio`, `lm-studio` | 11434, 1234 |
| UI | `open-webui`, `openwebui`, `gradio` | 7860 |
| Vector DB | `qdrant`, `chroma`, `weaviate`, `milvus` | 6333, 19530 |
| Data store | `redis`, `valkey`, `postgres`, `pgvector` | 6379, 5432 |

A port bound to `127.0.0.1:` or `localhost:` is considered safe and does not
trigger an exposure finding.

## Rules implemented (v0.1)

| id | severity | fires when |
|----|----------|------------|
| `exposed_inference` | HIGH | An inference service publishes a port to all interfaces (not localhost-bound). |
| `exposed_ui` | HIGH | Open WebUI / Gradio UI publishes a port to all interfaces. |
| `exposed_vector` | HIGH | A vector DB (Qdrant/Chroma/Weaviate/Milvus) publishes a port to the host. |
| `exposed_datastore` | HIGH / MEDIUM | Redis/Postgres publishes a port to all interfaces. **HIGH** when an AI component (inference/UI/vector) is present in the same compose file, otherwise **MEDIUM**. |
| `docker_socket_mount` | CRITICAL | A service mounts `/var/run/docker.sock`. |
| `privileged_container` | CRITICAL | A service sets `privileged: true`. |
| `permissive_cors` | HIGH | `OLLAMA_ORIGINS` / `*CORS*` / `*ALLOW_ORIGINS*` is `*`, contains `*`, or is empty. |
| `latest_image` | MEDIUM | An image uses `:latest` or has no tag. |
| `broad_bind_mount` | MEDIUM | A broad host bind mount (e.g. `.:/app`) that is not read-only. |
| `env_token_key` | MEDIUM | A token/secret/API/auth key **name** appears in a `.env*` file or a compose `environment:` block (values never inspected or emitted). Reports the real line number. |
| `no_internal_network` | MEDIUM | A multi-service compose file publishes ports but defines no `internal: true` network. |
| `no_ai_stack_manifest` | LOW | An AI compose stack has no `ai-stack-manifest.json`. |

## Not yet implemented (roadmap)

`network_mode: host`, SARIF output, Caddyfile / nginx auth checks, Dockerfile
`USER root` / `EXPOSE` analysis, Kubernetes manifests. See `docs/roadmap.md`.
