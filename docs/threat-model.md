# Threat Model

Tasia is a local static analyzer for deployment artifacts.

## In scope

- Misconfigurations in compose, Dockerfiles, env files that cause private AI services to be reachable beyond localhost or the intended container network.
- Accidental secret key name leakage (names only).
- Mutable image tags.

## Out of scope

- Runtime exploitation or active scanning of running services.
- Analysis of application source or model weights.
- Network ACLs on the actual host or cloud provider.
- Proving compliance.

## Assumptions

- The user runs Tasia on their own machine / CI against their own files.
- No secrets are committed (Tasia helps spot the risk).
- Findings are reviewed by humans before action.
