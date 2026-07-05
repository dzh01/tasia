# Demo script

The exact sequence for the launch GIF. Every command is copy-pasteable from the
repo root with `tasia` on your `PATH` (`go build -o tasia ./cmd/tasia && export PATH=$PWD:$PATH`).

## The winning demo (end to end)

```bash
# 1. Review the deliberately-messy stack -> BLOCKED, 3 HIGH findings with file:line
tasia review --path examples/messy-ollama-stack

# 2. Show the generated hardening plan (decision, risk, per-finding fix)
sed -n '1,40p' examples/messy-ollama-stack/.tasia/HARDENING_PLAN.md

# 3. Show the suggested compose override (Tasia NEVER edits your files)
cat examples/messy-ollama-stack/.tasia/docker-compose.hardened.override.yml

# 4. The hardened stack passes clean
tasia review --path examples/hardened-ollama-stack

# 5. CI mode exit codes (0 = pass, 1 = blocked, 2 = tool error)
tasia ci --path examples/hardened-ollama-stack ; echo "exit: $?"   # 0
tasia ci --path examples/messy-ollama-stack ;    echo "exit: $?"   # 1
```

## Pre-push block (separate clip)

```bash
# scratch repo with the messy stack
tmp=$(mktemp -d); git init -q "$tmp"; cp examples/messy-ollama-stack/docker-compose.yml "$tmp/"
cd "$tmp"; git add -A; git -c user.email=d@d -c user.name=d commit -qm init
git init -q --bare ../remote.git; git remote add origin ../remote.git

tasia install --pre-push          # installs .git/hooks/pre-push
git push origin master            # BLOCKED: CI blocked: HIGH risk findings present

# harden and the same push succeeds
sed -i '' 's/"11434:11434"/"127.0.0.1:11434:11434"/;s/"3000:8080"/"127.0.0.1:3000:8080"/;s/"6333:6333"/"127.0.0.1:6333:6333"/' docker-compose.yml
git commit -qam harden
git push origin master            # PASS -> push accepted
```

## Rendering the GIF

`docs/demo.gif` is rendered from `docs/demo.tape` with
[ascii-gif](https://github.com/tamnd/ascii-gif) (a styled vhs wrapper).
Rendering needs `ttyd` and `ffmpeg`:

```bash
brew install ttyd ffmpeg                                   # macOS
go install github.com/tamnd/ascii-gif/cmd/ascii-gif@latest
go build -o tasia ./cmd/tasia
export PATH="$PWD:$PATH"
ascii-gif render docs/demo.tape -o docs/demo.gif
```

Run from the repo root with `tasia` on `PATH`. ascii-gif prepends the window
styling; the tape holds only the terminal actions.
