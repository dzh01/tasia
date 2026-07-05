# vhs tape for the Tasia launch GIF.
# Render: brew install vhs ttyd ffmpeg && go build -o tasia ./cmd/tasia && PATH=$PWD:$PATH vhs docs/demo.tape
# Produces docs/demo.gif

Output docs/demo.gif

Require tasia

Set Shell "bash"
Set FontSize 15
Set Width 1200
Set Height 760
Set Theme "Dracula"
Set Padding 18
Set TypingSpeed 45ms

Type "# Private AI is not automatically private. Let's check a stack:"
Enter
Sleep 800ms

Type "tasia review --path examples/messy-ollama-stack"
Enter
Sleep 3s

Type "# BLOCKED, HIGH risk, each finding has file:line. Now the fix pack:"
Enter
Sleep 800ms

Type "cat examples/messy-ollama-stack/.tasia/docker-compose.hardened.override.yml"
Enter
Sleep 3s

Type "# Suggestions only — Tasia never edits your files. Hardened stack:"
Enter
Sleep 800ms

Type "tasia review --path examples/hardened-ollama-stack"
Enter
Sleep 3s

Type "# PASS. Gate it in CI or as a git pre-push hook."
Enter
Sleep 2500ms
