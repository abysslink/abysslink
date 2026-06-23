# Abysslink README demo — rendered with VHS (https://github.com/charmbracelet/vhs)
#
#   vhs demo/abysslink.tape        # -> demo/abysslink.gif
#
# Deterministic + fast: runs only infra-free commands (--help / version), so it
# never hangs on a missing tailnet and always renders the same. Output is sliced
# with `sed` to (a) keep each frame tight and (b) drop cobra's "Global Flags"
# block, which prints the absolute config path and would leak a real home dir.

Output demo/abysslink.gif
Require abysslink

Set Shell        "bash"
Set FontSize     16
Set Width        1100
Set Height       520
Set Padding      20
Set TypingSpeed  25ms
Set Theme        "Catppuccin Mocha"

# Clean, neutral prompt — no real home path leaks into the frame.
Hide
Type `export PS1='\[\033[36m\]abysslink\[\033[0m\] \[\033[90m\]~/dev\[\033[0m\] $ '` Enter
Type "clear" Enter
Show

Sleep 600ms

# 1 · The workflow, front and center — init, converge, pair, check. With exit codes.
Type "abysslink --help | sed -n '1,19p'"  Sleep 250ms  Enter
Sleep 2.6s
Type "clear" Enter

# 2 · Every mutating command is dry-run by default; weakening a default is explicit.
Type "abysslink up --help | sed -n '1,21p'"  Sleep 250ms  Enter
Sleep 2.6s
Type "clear" Enter

# 3 · Verify the binary you're about to trust.
Type "abysslink version --provenance"  Sleep 250ms  Enter
Sleep 2.2s
Type "clear" Enter

# 4 · The kill switch is one word — and it's reversible.
Type "abysslink panic --help | sed -n '1,14p'"  Sleep 250ms  Enter
Sleep 2.6s
Type "clear" Enter

# 5 · One-scan phone enrollment — credential pull without copy-pasting keys.
Type "abysslink enroll phone --help | sed -n '1,16p'"  Sleep 250ms  Enter
Sleep 2.6s
Type "clear" Enter

# 6 · Session-typed notification — the rig knows which pane needs attention.
Type "abysslink notify --help | sed -n '1,13p'"  Sleep 250ms  Enter
Sleep 2.6s
Type "clear" Enter

# 7 · Agent kill-switch (Apoptosis) — freeze a runaway agent from your pocket.
Type "abysslink arm --help | sed -n '1,15p'"  Sleep 250ms  Enter
Sleep 2.6s

Sleep 1s
