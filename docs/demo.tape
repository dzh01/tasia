# Demo tape for the README GIF, rendered with ascii-gif.
# https://github.com/tamnd/ascii-gif (wraps vhs; needs ttyd + ffmpeg)
#
# Render from the repo root with tasia on PATH:
#   go build -o tasia ./cmd/tasia && export PATH=$PWD:$PATH
#   ascii-gif render docs/demo.tape -o docs/demo.gif
#
# ascii-gif prepends the window styling; this tape holds only the action.
# The hidden block pre-generates .tasia so the visible commands can use
# --no-write (keeps absolute paths out of the frame).

Hide
Type "rm -rf examples/*/.tasia && tasia review --path examples/messy-ollama-stack >/dev/null 2>&1 && clear"
Enter
Sleep 700ms
Show
Type "tasia review --path examples/messy-ollama-stack --no-write"
Enter
Sleep 3800ms
Type "cat examples/messy-ollama-stack/.tasia/docker-compose.hardened.override.yml"
Enter
Sleep 3800ms
Type "tasia review --path examples/hardened-ollama-stack --no-write"
Enter
Sleep 3000ms
