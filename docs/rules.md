# Tasia Rules

All rules are deterministic. Findings always include file + line when available from YAML nodes.

## High-value rules implemented (v0.1)

- exposed_inference (HIGH): Ollama, vLLM, llama.cpp style ports bound without localhost
- exposed_ui (HIGH): Open WebUI, Gradio UIs on 0.0.0.0 / all-interfaces
- exposed_vector (HIGH): Qdrant, Chroma etc. published to host
- docker_socket_mount (CRITICAL)
- privileged_container (CRITICAL)
- latest_image (MEDIUM)
- broad_bind_mount (MEDIUM)
- env_token_key (MEDIUM): token/secret/api key names present in .env* (values never shown)
- no_internal_network (MEDIUM)
- no_ai_stack_manifest (LOW)

Future rules (post v0.1): OLLAMA_ORIGINS=*, network_mode: host, Caddyfile auth, etc.
