# Abysslink README demo — rendered with VHS (https://github.com/charmbracelet/vhs)
#
#   vhs demo/abysslink.tape        # run from the repo root
#                                  # -> demo/abysslink.gif + demo/abysslink.mp4
#
# Three real value moments, all read-only / dry-run — nothing mutates the host:
#   1. `abysslink up`            — the convergence plan (dry-run is the default)
#   2. `abysslink quorum eval`   — the compiled deny-floor rejecting Funnel
#   3. `abysslink threat-model`  — the live ✓/✗ defense table
#
# Deterministic + leak-free: the hidden setup points HOME at a throwaway
# sandbox and installs demo/abysslink.demo.yaml (generic identity: dev@rig),
# so no real hostname, user, IP, or home path can appear in a frame.
# Theme matches the product palette in internal/ui/theme.go.

Output demo/abysslink.gif
Output demo/abysslink.mp4
Require abysslink

Set Shell        "bash"
Set FontSize     18
Set Width        1200
Set Height       600
Set Padding      24
Set TypingSpeed  20ms
Set Framerate    24
Set Theme        {"name":"abyss","background":"#0f1117","foreground":"#F8F8F2","black":"#1a1d27","brightBlack":"#64748B","red":"#FF5F87","brightRed":"#FF5F87","green":"#04B575","brightGreen":"#04B575","yellow":"#FFD060","brightYellow":"#FFD060","blue":"#6E80F7","brightBlue":"#6E80F7","magenta":"#B57BFF","brightMagenta":"#B57BFF","cyan":"#2CE0F5","brightCyan":"#2CE0F5","white":"#F8F8F2","brightWhite":"#F8F8F2","cursor":"#2CE0F5","selection":"#B57BFF"}

# Invisible setup: sandbox HOME + sanitized config + neutral prompt.
Hide
Type `export HOME=/tmp/abysslink-demo-home && mkdir -p "$HOME/.config/abysslink" && cp demo/abysslink.demo.yaml "$HOME/.config/abysslink/abysslink.yaml"` Enter
Type `export PS1='\[\033[36m\]dev@rig\[\033[0m\] \[\033[90m\]~\[\033[0m\] $ '` Enter
Type "clear" Enter
Show

Sleep 400ms

# 1 · The product promise: converge the whole stack, preview first, apply explicitly.
Type "# preview every change before it happens"  Sleep 250ms  Enter
Type "abysslink up"  Sleep 250ms  Enter
Sleep 3s
Type "clear" Enter

# 2 · The deny-floor: public exposure is un-askable, and the command never runs.
Type "# dangerous actions hit a compiled deny-floor"  Sleep 250ms  Enter
Type "abysslink quorum eval -- tailscale funnel 443"  Sleep 250ms  Enter
Sleep 2.3s
Type "clear" Enter

# 3 · The receipts: every defense in the threat model, checked live.
Type "# every defense, verified live"  Sleep 250ms  Enter
Type "abysslink threat-model"  Sleep 250ms  Enter
Sleep 3.1s
