#!/usr/bin/env bash
# p4 live probes — §6.2 of 13-p4-plan.md, driving the helper directly
# (no plugin integration; that is M3). Assertions are by file existence
# and spawn output, never by trusting a tool's exit code.
#
# Usage: ./probes.sh            (from native/linux-sandbox, or anywhere;
#                              helper resolved relative to this script)
# Env:   HELPER=<path> overrides ../../bin/opencode-sandbox
#        SCRATCH=<path> overrides /tmp/opencode

set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
HELPER="${HELPER:-$HERE/../../bin/opencode-sandbox}"
SCRATCH="${SCRATCH:-/tmp/opencode}"
mkdir -p "$SCRATCH"

PASS=0; FAIL=0; RESULTS=()

note() { RESULTS+=("$1"); }
pass() { PASS=$((PASS+1)); note "PASS  $1"; }
fail() { FAIL=$((FAIL+1)); note "FAIL  $1  -- $2"; }

# --- runners ------------------------------------------------------------
# $1 = mode (ro|rw), $2 = command; extra env via ENV_<NAME> not needed —
# callers prepend `env VAR=...` around helper invocation themselves.
run_sbx() { # mode cmd [extra env via global EXTRA_ENV as string]
	local mode="$1" cmd="$2"; shift 2
	env OPENCODE_SANDBOX_MODE="$mode" OPENCODE_SANDBOX_SCRATCH="$SCRATCH" \
	    OPENCODE_REAL_BASH=/bin/bash "$@" \
	    "$HELPER" -c "$cmd" 2>&1
}

assert_absent() { # name path
	if [ -e "$2" ] || [ -L "$2" ]; then fail "$1" "$2 exists"; else pass "$1"; fi
}
assert_present() { # name path
	if [ -e "$2" ]; then pass "$1"; else fail "$1" "$2 missing"; fi
}

cleanup_names() { # remove probe artifacts listed on stdin, one per line
	while IFS= read -r f; do [ -n "$f" ] && rm -f -- "$f" 2>/dev/null; done
}

echo "helper: $HELPER"
"$HELPER" --probe | sed 's/^/  /'
echo "scratch: $SCRATCH  home: $HOME"
echo

# ========================================================================
# RO PROFILE
# ========================================================================

# --- write vectors into $HOME: all must be ABSENT ------------------------
run_sbx ro 'echo x > "$HOME/.p4_ro_redirect"' >/dev/null
assert_absent "ro: redirect to HOME" "$HOME/.p4_ro_redirect"

run_sbx ro "python3 -c \"open('$HOME/.p4_ro_py','w').write('x')\"" >/dev/null
assert_absent "ro: python open() write" "$HOME/.p4_ro_py"

run_sbx ro 'cat > "$HOME/.p4_ro_heredoc" <<EOF
payload
EOF' >/dev/null
assert_absent "ro: heredoc write" "$HOME/.p4_ro_heredoc"

run_sbx ro 'cp /etc/hostname "$HOME/.p4_ro_cp" 2>/dev/null; \
  touch "$HOME/.p4_ro_touch" 2>/dev/null; \
  mkdir "$HOME/.p4_ro_mkdir" 2>/dev/null; \
  echo x | tee "$HOME/.p4_ro_tee" >/dev/null 2>&1; \
  dd if=/dev/zero of="$HOME/.p4_ro_dd" bs=1 count=1 2>/dev/null; \
  install -m644 /etc/hostname "$HOME/.p4_ro_install" 2>/dev/null; \
  ln -s /etc/hostname "$HOME/.p4_ro_ln" 2>/dev/null; \
  true' >/dev/null
assert_absent "ro: cp"       "$HOME/.p4_ro_cp"
assert_absent "ro: touch"    "$HOME/.p4_ro_touch"
assert_absent "ro: mkdir"    "$HOME/.p4_ro_mkdir"
assert_absent "ro: tee"      "$HOME/.p4_ro_tee"
assert_absent "ro: dd"       "$HOME/.p4_ro_dd"
assert_absent "ro: install"  "$HOME/.p4_ro_install"
assert_absent "ro: ln -s"    "$HOME/.p4_ro_ln"

# mv + rm: seed two files, attempt move-out and delete inside sandbox
echo seed > "$HOME/.p4_ro_mv_src"
echo seed > "$HOME/.p4_ro_rm_src"
run_sbx ro 'mv "$HOME/.p4_ro_mv_src" "$HOME/.p4_ro_mv_dst" 2>/dev/null; \
  rm -f "$HOME/.p4_ro_rm_src" 2>/dev/null; true' >/dev/null
assert_present "ro: mv src survives" "$HOME/.p4_ro_mv_src"
assert_absent  "ro: mv dst absent"   "$HOME/.p4_ro_mv_dst"
assert_present "ro: rm target survives" "$HOME/.p4_ro_rm_src"
rm -f "$HOME/.p4_ro_mv_src" "$HOME/.p4_ro_rm_src"

# tar extract into HOME
mkdir -p "$SCRATCH/p4fix" && echo payload > "$SCRATCH/p4fix/.p4_ro_tar"
tar -cf "$SCRATCH/p4-fixture.tar" -C "$SCRATCH/p4fix" .p4_ro_tar
run_sbx ro "tar xf '$SCRATCH/p4-fixture.tar' -C \"\$HOME\" 2>/dev/null; true" >/dev/null
assert_absent "ro: tar extract" "$HOME/.p4_ro_tar"
rm -f "$SCRATCH/p4-fixture.tar" "$SCRATCH/p4fix/.p4_ro_tar"

# O_TMPFILE + os.link via /proc/self/fd
cat > "$SCRATCH/p4-otmp.py" <<'PY'
import os
fd = os.open("/tmp", os.O_RDWR | os.O_TMPFILE, 0o600)
os.write(fd, b"x")
os.link(f"/proc/self/fd/{fd}", os.path.expanduser("~/.p4_ro_tmpfile"))
PY
run_sbx ro "python3 '$SCRATCH/p4-otmp.py' 2>/dev/null; true" >/dev/null
assert_absent "ro: O_TMPFILE+os.link" "$HOME/.p4_ro_tmpfile"
rm -f "$SCRATCH/p4-otmp.py"

# cross-directory hardlink: source inside scratch, target in HOME
echo x > "$SCRATCH/p4-hlsrc"
run_sbx ro "ln '$SCRATCH/p4-hlsrc' \"\$HOME/.p4_ro_hlink\" 2>/dev/null; true" >/dev/null
assert_absent "ro: cross-dir hardlink" "$HOME/.p4_ro_hlink"
rm -f "$SCRATCH/p4-hlsrc"

# symlink-follow write: symlink inside scratch -> $HOME target
ln -sf "$HOME/.p4_ro_symtarget" "$SCRATCH/p4-symlink"
run_sbx ro "echo x > '$SCRATCH/p4-symlink' 2>/dev/null; true" >/dev/null
assert_absent "ro: symlink-follow write" "$HOME/.p4_ro_symtarget"
rm -f "$SCRATCH/p4-symlink"

# --- scratch writes ALLOWED ----------------------------------------------
run_sbx ro "echo ok > '$SCRATCH/p4_ro_scratch'; mkdir '$SCRATCH/p4_ro_dir' 2>/dev/null; true" >/dev/null
assert_present "ro: scratch file write" "$SCRATCH/p4_ro_scratch"
assert_present "ro: scratch mkdir"      "$SCRATCH/p4_ro_dir"
rm -f "$SCRATCH/p4_ro_scratch"; rmdir "$SCRATCH/p4_ro_dir" 2>/dev/null

# --- chmod gap (documented): succeeds, restore afterwards -----------------
echo seed > "$HOME/.p4_ro_chmod" && chmod 644 "$HOME/.p4_ro_chmod"
run_sbx ro 'chmod 000 "$HOME/.p4_ro_chmod" 2>/dev/null; true' >/dev/null
MODE="$(stat -c %a "$HOME/.p4_ro_chmod" 2>/dev/null)"
if [ "$MODE" = "0" ]; then pass "ro: chmod gap (documented, mode=000)"; \
  else fail "ro: chmod gap (documented)" "mode=$MODE (expected 0)"; fi
chmod 644 "$HOME/.p4_ro_chmod"; rm -f "$HOME/.p4_ro_chmod"

# --- sudo NNP -------------------------------------------------------------
run_sbx ro 'sudo -n touch "$HOME/.p4_ro_sudo" 2>/dev/null; true' >/dev/null
assert_absent "ro: sudo -n blocked (NNP)" "$HOME/.p4_ro_sudo"

# --- docker socket masked -------------------------------------------------
# A live daemon prints a "Server Version:" line; a masked socket yields
# "permission denied while trying to connect" and no server section.
OUT="$(run_sbx ro 'docker info 2>&1')"
if echo "$OUT" | grep -qiE "permission denied|cannot connect|is the docker daemon"; then
  pass "ro: docker info blocked"
else
  fail "ro: docker info blocked" "$(echo "$OUT" | tail -2)"
fi

# --- interop spawn attempts (12-escape-gap) --------------------------------
WSLDIR="$(run_sbx ro 'ls /run/WSL 2>/dev/null | grep -c interop' | tail -1)"
if [ "$WSLDIR" = "0" ]; then pass "ro: /run/WSL masked (no interop)"; \
  else fail "ro: /run/WSL masked" "$WSLDIR interop sockets visible"; fi

OUT="$(run_sbx ro 'pwsh.exe -NoProfile -Command "Set-Content -Path C:\\p4_escape.txt -Value x" 2>&1; echo MARKER')"
if echo "$OUT" | grep -q "MARKER"; then pass "ro: pwsh.exe Set-Content spawn fails"; \
  else fail "ro: pwsh.exe Set-Content" "no marker — output: $OUT"; fi

OUT="$(run_sbx ro 'cmd.exe /c echo hi 2>&1')"
if echo "$OUT" | grep -qE "^hi$"; then fail "ro: cmd.exe spawn" "executed"; \
  else pass "ro: cmd.exe spawn fails"; fi

OUT="$(run_sbx ro 'wsl.exe -- bash -c "echo wslnested" 2>&1')"
if echo "$OUT" | grep -q "wslnested"; then fail "ro: wsl.exe nested" "executed"; \
  else pass "ro: wsl.exe nested spawn fails"; fi

# powershell.exe -EncodedCommand ("hi" in UTF-16LE base64)
ENC="$(printf 'echo hi' | iconv -t UTF-16LE 2>/dev/null | base64 -w0)"
if [ -z "$ENC" ]; then ENC="aABpAA==" ; fi
OUT="$(run_sbx ro "powershell.exe -NoProfile -EncodedCommand '$ENC' 2>&1")"
if echo "$OUT" | grep -qE "^hi$"; then fail "ro: powershell -EncodedCommand" "executed"; \
  else pass "ro: powershell -EncodedCommand spawn fails"; fi

echo 'Write-Output "pwfile-ok"' > "$SCRATCH/p4-write.ps1"
OUT="$(run_sbx ro "pwsh.exe -NoProfile -File '$SCRATCH/p4-write.ps1' 2>&1")"
if echo "$OUT" | grep -q "pwfile-ok"; then fail "ro: pwsh.exe -File" "executed"; \
  else pass "ro: pwsh.exe -File spawn fails"; fi
rm -f "$SCRATCH/p4-write.ps1"

# --- /dev/null, git, exit code ---------------------------------------------
OUT="$(run_sbx ro 'echo x > /dev/null && echo devnull-ok')"
[ "$OUT" = "devnull-ok" ] && pass "ro: /dev/null writable" \
  || fail "ro: /dev/null writable" "$OUT"

OUT="$(run_sbx ro 'cd /tmp/opencode/p4-m1 2>/dev/null && git status --porcelain >/dev/null 2>&1 && echo git-ok' \
      OPENCODE_SANDBOX_SCRATCH="$SCRATCH")"
[ "$OUT" = "git-ok" ] && pass "ro: git status works" \
  || fail "ro: git status works" "$OUT"

run_sbx ro 'exit 42' >/dev/null; RC=$?
[ "$RC" = "42" ] && pass "ro: exit 42 propagates" \
  || fail "ro: exit 42 propagates" "rc=$RC"

# --- network: --unshare-net evidence ----------------------------------------
OUT="$(run_sbx ro 'curl -s -m 3 -o /dev/null -w "%{http_code}" http://127.0.0.1:8791/ 2>/dev/null; echo rc=$?')"
if echo "$OUT" | grep -qE "rc=[1-9]"; then pass "ro: curl unreachable (unshare-net)"; \
  else fail "ro: curl unreachable" "got: $OUT"; fi

# ========================================================================
# RW PROFILE
# ========================================================================
run_sbx rw 'echo x > "$HOME/.p4_rw_probe"' >/dev/null
assert_present "rw: home write allowed" "$HOME/.p4_rw_probe"
rm -f "$HOME/.p4_rw_probe"

OUT="$(run_sbx rw 'pwsh.exe -NoProfile -Command "echo interop-ok" 2>&1 | tr -d "\r"')"
if echo "$OUT" | grep -q "interop-ok"; then pass "rw: pwsh.exe works (interop unmasked)"; \
  else fail "rw: pwsh.exe works" "got: $OUT"; fi

OUT="$(run_sbx rw 'docker info 2>&1')"
if echo "$OUT" | grep -qiE "permission denied|cannot connect|is the docker daemon"; then
  pass "rw: docker info still blocked (floor)"
else
  fail "rw: docker info still blocked" "$(echo "$OUT" | tail -2)"
fi

OUT="$(run_sbx rw 'curl -s -m 5 -o /dev/null -w "%{http_code}" https://example.com 2>/dev/null; echo rc=$?')"
if echo "$OUT" | grep -q "rc=0"; then pass "rw: curl connectivity works"; \
  else fail "rw: curl connectivity works" "got: $OUT"; fi

run_sbx rw 'exit 42' >/dev/null; RC=$?
[ "$RC" = "42" ] && pass "rw: exit 42 propagates" \
  || fail "rw: exit 42 propagates" "rc=$RC"

# --- /proc is the host proc (RW runs on the host pidns) -------------------
OUT="$(run_sbx rw 'cat /proc/1/comm 2>/dev/null')"
HOSTCOMM="$(cat /proc/1/comm 2>/dev/null)"
if [ -n "$OUT" ] && [ "$OUT" = "$HOSTCOMM" ]; then
  pass "rw: /proc is host proc (pid 1 comm matches)"
else
  fail "rw: /proc is host proc" "inside='$OUT' host='$HOSTCOMM'"
fi

# --- background survival ---------------------------------------------------
# RW has no private pidns and no --die-with-parent, so a nohup'd child must
# outlive the payload command (pre-sandbox semantics). A pidns regression
# would SIGKILL the child at namespace teardown.
run_sbx rw "nohup sleep 30 >/dev/null 2>&1 & echo \$! > '$SCRATCH/p4_rw_bg.pid'; echo ok" >/dev/null
sleep 2
BGPID="$(tr -dc '0-9' < "$SCRATCH/p4_rw_bg.pid" 2>/dev/null)"
if [ -n "$BGPID" ] && [ -d "/proc/$BGPID" ] && \
   tr '\0' ' ' < "/proc/$BGPID/cmdline" 2>/dev/null | grep -q 'sleep 30'; then
  pass "rw: backgrounded process survives"
else
  fail "rw: backgrounded process survives" "pid='$BGPID' not alive"
fi
if [ -n "$BGPID" ] && [ -d "/proc/$BGPID" ]; then
  kill "$BGPID" 2>/dev/null
  sleep 1
  kill -9 "$BGPID" 2>/dev/null
fi
rm -f "$SCRATCH/p4_rw_bg.pid"

# ========================================================================
# FALLBACK PATHS
# ========================================================================
# bwrap-only: mount-based RO (--ro-bind / / + writable scratch), no Landlock
OUT="$(OPENCODE_SANDBOX_FALLBACK=bwrap-only "$HELPER" --probe | grep sandbox_path)"
echo "$OUT" | grep -q "bwrap-only" && pass "fallback: bwrap-only selected" \
  || fail "fallback: bwrap-only selected" "$OUT"

run_sbx ro 'echo x > "$HOME/.p4_bwo_write"' OPENCODE_SANDBOX_FALLBACK=bwrap-only >/dev/null
assert_absent "bwrap-only ro: home write blocked" "$HOME/.p4_bwo_write"
run_sbx ro "echo ok > '$SCRATCH/p4_bwo_scratch'" OPENCODE_SANDBOX_FALLBACK=bwrap-only >/dev/null
assert_present "bwrap-only ro: scratch writable" "$SCRATCH/p4_bwo_scratch"
rm -f "$SCRATCH/p4_bwo_scratch"
run_sbx ro 'exit 42' OPENCODE_SANDBOX_FALLBACK=bwrap-only >/dev/null; RC=$?
[ "$RC" = "42" ] && pass "bwrap-only ro: exit 42" \
  || fail "bwrap-only ro: exit 42" "rc=$RC"

# landlock-only: stage2 direct, AF_UNIX block mandatory, no bwrap
OUT="$(OPENCODE_SANDBOX_FALLBACK=landlock-only "$HELPER" --probe | grep sandbox_path)"
echo "$OUT" | grep -q "landlock-only" && pass "fallback: landlock-only selected" \
  || fail "fallback: landlock-only selected" "$OUT"

run_sbx ro 'echo x > "$HOME/.p4_llo_write"' OPENCODE_SANDBOX_FALLBACK=landlock-only >/dev/null
assert_absent "landlock-only ro: home write blocked" "$HOME/.p4_llo_write"
run_sbx ro "echo ok > '$SCRATCH/p4_llo_scratch'" OPENCODE_SANDBOX_FALLBACK=landlock-only >/dev/null
assert_present "landlock-only ro: scratch writable" "$SCRATCH/p4_llo_scratch"
rm -f "$SCRATCH/p4_llo_scratch"
OUT="$(run_sbx ro 'python3 -c "import socket; socket.socket(socket.AF_UNIX)" 2>&1 | tail -1' \
      OPENCODE_SANDBOX_FALLBACK=landlock-only)"
echo "$OUT" | grep -qi "not permitted" && pass "landlock-only ro: AF_UNIX blocked" \
  || fail "landlock-only ro: AF_UNIX blocked" "$OUT"
run_sbx ro 'exit 42' OPENCODE_SANDBOX_FALLBACK=landlock-only >/dev/null; RC=$?
[ "$RC" = "42" ] && pass "landlock-only ro: exit 42" \
  || fail "landlock-only ro: exit 42" "rc=$RC"

# landlock-only RW: no landlock, NNP+seccomp only, AF_UNIX open
run_sbx rw 'echo x > "$HOME/.p4_llo_rw"' OPENCODE_SANDBOX_FALLBACK=landlock-only >/dev/null
assert_present "landlock-only rw: home write allowed" "$HOME/.p4_llo_rw"
rm -f "$HOME/.p4_llo_rw"

# ========================================================================
# DENY LISTS / RW NETWORK / ALLOW SUDO / EXTRA ARGS  (new config knobs)
# ========================================================================
# Mount-based deny-list probes need a bwrap path; under landlock-only
# (e.g. when the probe shell itself is already sandboxed) there are no
# mounts to shadow, so those probes are reported SKIP, not FAIL.
HAVE_BWRAP_PATH=0
case "$("$HELPER" --probe | sed -n 's/^sandbox_path: //p')" in
  full|bwrap-only) HAVE_BWRAP_PATH=1 ;;
esac
skip() { RESULTS+=("SKIP  $1  -- $2"); }
bwrap_probe() { # name reason-if-skipped -> 0 run / 1 skipped
  if [ "$HAVE_BWRAP_PATH" = "1" ]; then return 0; fi
  skip "$1" "$2"; return 1
}

EXT="$SCRATCH/ext-c"
mkdir -p "$EXT/fix-dw" "$EXT/fix-dr" "$EXT/fix-both"
echo secret > "$EXT/fix-dr/hidden.txt"
echo both   > "$EXT/fix-both/x.txt"

if bwrap_probe "deny-write rw: write blocked, dir listable" "no bwrap path"; then
  OUT="$(run_sbx rw "echo x > '$EXT/fix-dw/t' 2>/dev/null; \
    ls '$EXT/fix-dw' >/dev/null 2>&1 && echo listable; \
    test -e '$EXT/fix-dw/t' && echo wrote || echo blocked" \
    OPENCODE_SANDBOX_DENY_WRITE="$EXT/fix-dw")"
  if echo "$OUT" | grep -q "listable" && ! echo "$OUT" | grep -q "wrote" \
     && [ ! -e "$EXT/fix-dw/t" ]; then
    pass "deny-write rw: write blocked, dir listable"
  else fail "deny-write rw" "$OUT"; fi
fi

if bwrap_probe "deny-write ro: write blocked, dir listable" "no bwrap path"; then
  OUT="$(run_sbx ro "echo x > '$EXT/fix-dw/t2' 2>/dev/null; \
    ls '$EXT/fix-dw' >/dev/null 2>&1 && echo listable; \
    test -e '$EXT/fix-dw/t2' && echo wrote || echo blocked" \
    OPENCODE_SANDBOX_DENY_WRITE="$EXT/fix-dw")"
  if echo "$OUT" | grep -q "listable" && ! echo "$OUT" | grep -q "wrote" \
     && [ ! -e "$EXT/fix-dw/t2" ]; then
    pass "deny-write ro: write blocked, dir listable"
  else fail "deny-write ro" "$OUT"; fi
fi

if bwrap_probe "deny-read rw: contents invisible" "no bwrap path"; then
  OUT="$(run_sbx rw "cat '$EXT/fix-dr/hidden.txt' 2>&1 | head -1; \
    echo entries=\$(ls -A '$EXT/fix-dr' 2>/dev/null | wc -l)" \
    OPENCODE_SANDBOX_DENY_READ="$EXT/fix-dr")"
  if echo "$OUT" | grep -qi "No such file" \
     && echo "$OUT" | grep -q "entries=0"; then
    pass "deny-read rw: contents invisible"
  else fail "deny-read rw" "$OUT"; fi
fi

if bwrap_probe "deny-read ro: contents invisible" "no bwrap path"; then
  OUT="$(run_sbx ro "cat '$EXT/fix-dr/hidden.txt' 2>&1 | head -1; \
    echo entries=\$(ls -A '$EXT/fix-dr' 2>/dev/null | wc -l)" \
    OPENCODE_SANDBOX_DENY_READ="$EXT/fix-dr")"
  if echo "$OUT" | grep -qi "No such file" \
     && echo "$OUT" | grep -q "entries=0"; then
    pass "deny-read ro: contents invisible"
  else fail "deny-read ro" "$OUT"; fi
fi

if bwrap_probe "deny-lists composed: empty AND unwritable" "no bwrap path"; then
  OUT="$(run_sbx rw "echo entries=\$(ls -A '$EXT/fix-both' 2>/dev/null | wc -l); \
    echo x > '$EXT/fix-both/y' 2>/dev/null; \
    test -e '$EXT/fix-both/y' && echo wrote || echo blocked" \
    OPENCODE_SANDBOX_DENY_READ="$EXT/fix-both" \
    OPENCODE_SANDBOX_DENY_WRITE="$EXT/fix-both")"
  if echo "$OUT" | grep -q "entries=0" \
     && ! echo "$OUT" | grep -q "wrote" \
     && [ ! -e "$EXT/fix-both/y" ]; then
    pass "deny-lists composed: empty AND unwritable"
  else fail "deny-lists composed" "$OUT"; fi
fi

# rwNetwork=0: TCP dead, but WSL interop (AF_UNIX /run/WSL) must survive.
OUT="$(run_sbx rw 'curl -s -m 3 -o /dev/null -w "%{http_code}" http://127.0.0.1:8791/ 2>/dev/null; echo rc=$?' \
      OPENCODE_SANDBOX_RW_NETWORK=0)"
if echo "$OUT" | grep -qE "rc=[1-9]"; then pass "rwNetwork=0: curl unreachable"; \
  else fail "rwNetwork=0: curl unreachable" "got: $OUT"; fi

OUT="$(run_sbx rw 'pwsh.exe -NoProfile -Command "echo interop-ok" 2>&1 | tr -d "\r"' \
      OPENCODE_SANDBOX_RW_NETWORK=0)"
if echo "$OUT" | grep -q "interop-ok"; then
  pass "rwNetwork=0: pwsh.exe interop still works"
else
  fail "rwNetwork=0: pwsh.exe interop" "got: $OUT"
fi

# allowSudo=1 (RW): stage1 routes host-direct — no bwrap at all — and
# stage2 skips NNP+seccomp, so sudo/setuid actually work (requires the
# invoking process to be free of ambient NNP). Deny lists, socket masks
# and rwNetwork are mount/userns features and are INERT on this path;
# the write-into-deny-dir probe documents that deliberately.
OUT="$(run_sbx rw 'sudo -n true && echo sudo-ok || echo sudo-fail; \
  grep "NoNewPrivs" /proc/self/status' \
      OPENCODE_SANDBOX_ALLOW_SUDO=1)"
if echo "$OUT" | grep -q "sudo-ok" && echo "$OUT" | grep -q "NoNewPrivs:[[:space:]]*0"; then
  pass "allowSudo=1 rw host-direct: sudo -n true succeeds, NNP off"
else
  fail "allowSudo=1 rw host-direct: sudo -n true" "$OUT"
fi

OUT="$(run_sbx rw "echo x > '$EXT/fix-dw/t3' 2>/dev/null; \
  test -e '$EXT/fix-dw/t3' && echo wrote || echo blocked" \
      OPENCODE_SANDBOX_ALLOW_SUDO=1 OPENCODE_SANDBOX_DENY_WRITE="$EXT/fix-dw")"
if echo "$OUT" | grep -q "wrote" && [ -e "$EXT/fix-dw/t3" ]; then
  pass "allowSudo=1 host-direct: deny lists inert (documented)"
else
  fail "allowSudo=1 host-direct: deny lists inert" "$OUT"
fi
rm -f "$EXT/fix-dw/t3"

# RW without the flag still refuses sudo via NNP (RO twin exists above).
OUT="$(run_sbx rw 'sudo -n true && echo sudo-ok || echo sudo-fail')"
if echo "$OUT" | grep -q "sudo-fail"; then
  pass "rw default: sudo -n refused (NNP)"
else
  fail "rw default: sudo -n refused" "$OUT"
fi

# EXTRA_ARGS: newline-joined bwrap argv elements, before the payload "--".
if bwrap_probe "extra-args: --setenv reaches payload" "no bwrap path"; then
  OUT="$(run_sbx rw 'echo "marker=$P4_MARKER"' \
        OPENCODE_SANDBOX_EXTRA_ARGS="$(printf -- '--setenv\nP4_MARKER\nhello')")"
  if echo "$OUT" | grep -q "marker=hello"; then
    pass "extra-args: --setenv reaches payload"
  else fail "extra-args: --setenv reaches payload" "$OUT"; fi
fi

if bwrap_probe "extra-args: bad flag fails closed" "no bwrap path"; then
  OUT="$(run_sbx rw 'echo SHOULD-NOT-PRINT' \
        OPENCODE_SANDBOX_EXTRA_ARGS='--not-a-real-flag')"
  if ! echo "$OUT" | grep -q "SHOULD-NOT-PRINT"; then
    pass "extra-args: bad flag fails closed"
  else fail "extra-args: bad flag fails closed" "$OUT"; fi
fi

rm -f "$EXT/fix-dr/hidden.txt" "$EXT/fix-both/x.txt" \
      "$EXT/fix-dw/t" "$EXT/fix-dw/t2" "$EXT/fix-both/y"
rmdir "$EXT/fix-dw" "$EXT/fix-dr" "$EXT/fix-both" "$EXT" 2>/dev/null

# ========================================================================
echo
echo "================ RESULTS ================"
printf '%s\n' "${RESULTS[@]}"
echo "========================================="
echo "pass=$PASS fail=$FAIL"
[ "$FAIL" = "0" ]
