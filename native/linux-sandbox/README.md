# opencode-sandbox (P4 OS sandbox helper)

Single static C binary implementing the kernel sandbox floor described in
`security-overhaul-research/13-p4-plan.md`. Linux only; x86_64.

## Architecture

One binary, two stages:

```
host:  opencode-sandbox -c <cmd>                       (stage 1)
         probes bwrap / userns / Landlock ABI once per process
         execs bwrap <floor args> -- <self> --stage2 ... -- bash -c <cmd>
bwrap: opencode-sandbox --stage2 --mode ro|rw ...      (stage 2)
         prctl(NO_NEW_PRIVS) -> seccomp-bpf floor
         RO only: Landlock FS+net+scope ruleset
         execvp(real_bash, ["bash","-c",cmd])
```

- **bwrap floor (RO and RW)**: new session, userns, `cap-drop ALL`,
  minimal `/dev`, root bind, privileged-socket masks (`/run/docker.sock`,
  podman, containerd — emitted only when the destination exists),
  `GIT_CONFIG safe.directory`, `--chdir $CWD`.
- **RO floor adds**: `die-with-parent`, private pid ns (`--unshare-pid`),
  fresh `/proc` (or host `--bind /proc /proc` when the probe shows pidns
  unsupported).
- **RW floor**: deliberately **no** pid ns and **no** `die-with-parent`;
  `/proc` is the host `/proc` (`--bind /proc /proc`). A private pidns
  would SIGKILL every backgrounded/detached child when the payload
  command exits — see *Background-process semantics* below.
- **RO adds**: `--unshare-net` (unless `OPENCODE_SANDBOX_RO_NETWORK=on`),
  `--tmpfs /run/WSL` (hides WSL interop sockets; unless
  `OPENCODE_SANDBOX_MASK_WSL_INTEROP=0`), `TMPDIR=$SCRATCH`, and the
  Landlock write-freeze ruleset: handled FS mask `0x7FF2` on ABI >= 3
  (WRITE_FILE|REMOVE_*|MAKE_*|REFER|TRUNCATE), TCP bind/connect handled
  with zero port rules on ABI >= 4, abstract-unix-socket + signal scopes
  on ABI >= 6. Writable hierarchies: `$SCRATCH` plus device nodes
  (`/dev/null` fatal if missing; `/dev/pts` directory rule included).
- **RW adds**: nothing else by default — host network and WSL interop
  stay usable; docker/podman/containerd masks still apply (the floor
  cannot be exceeded by a permission grant).
- **Deny lists (both profiles, emitted after the root bind so later
  mounts shadow it)**:
  `OPENCODE_SANDBOX_DENY_READ` mounts `--tmpfs` over each existing
  directory (the dir still exists but is empty inside; non-directory
  entries get a `/dev/null` bind instead — `--tmpfs` on a file would
  make bwrap fail). `OPENCODE_SANDBOX_DENY_WRITE` emits
  `--ro-bind <p> <p>` (readable, not writable). A path on **both** lists
  gets the tmpfs plus a `--remount-ro` of that same destination — empty
  AND read-only (`--ro-bind <p> <p>` cannot express this: bwrap resolves
  bind sources in the old root, so it would re-bind the original
  contents read-only). Both lists are a deny-floor below profile
  semantics: they apply in ro and rw, and on the bwrap-only fallback.
  On the landlock-only path there are no mounts, so the lists are
  inert. Non-absolute or non-existent entries are skipped at spawn time.
- **stage2 always** (except RW + `ALLOW_SUDO`, below): `NO_NEW_PRIVS`
  (neutralises passwordless sudo), then a seccomp deny-list
  (mount/umount2/unshare/setns/pivot_root/bpf/ptrace/
  process_vm_writev/open_by_handle_at/init/finit/delete_module/kexec*/
  reboot -> EPERM). RO strict mode also denies `socket(AF_UNIX)` /
  `socketpair(AF_UNIX)` (`OPENCODE_SANDBOX_RO_AF_UNIX_BLOCK`, default 1).
- **`OPENCODE_SANDBOX_ALLOW_SUDO=1` (RW only)**: the spawn is routed
  **host-direct** — stage1 execs stage2 without bwrap at all — and
  stage2 then skips BOTH `NO_NEW_PRIVS` and the seccomp floor (a seccomp
  install requires NNP or `CAP_SYS_ADMIN`). Host-direct is the only way
  sudo can work: bwrap sets `NO_NEW_PRIVS` unconditionally, before
  stage2 runs (verified on bubblewrap 0.11.1). This is a maximal
  weakening — **no** namespace isolation, `NO_NEW_PRIVS`, seccomp
  deny-list, socket masks, deny lists, or `rwNetwork` apply (all are
  mount/userns features); only the command itself runs, plus whatever
  ambient restrictions the invoking process already had (an ambient
  NNP cannot be unset, so sudo still refuses when the caller was
  already constrained).
  - RO ignores the flag entirely — a read-only session with working
    sudo is a contradiction; NNP + seccomp + Landlock always apply.

Mount order deviates from plan §2.1 literal listing: `--bind / /` (or the
`--ro-bind` pair) is emitted **before** `--proc`/`--dev`, otherwise the
host root bind shadows the fresh proc/devtmpfs mounts.

## Background-process semantics

- **RW**: backgrounded/detached children (`nohup X &`, `(server &)`,
  `watch … &`) **survive** after the wrapped command exits — pre-sandbox
  semantics are preserved. This is required for dev servers, watchers,
  and the WSL-interop restart chain (`nohup pwsh.exe … &`). Trade-off:
  orphans are possible; they are user-managed (`kill <pid>`).
- **RO**: bwrap's private pidns plus `die-with-parent` **kills all
  background children** when the command completes. This is acceptable —
  RO sessions never legitimately background anything (writes are denied
  anyway) and maximum isolation is correct there.

## Fallback paths (§3.4 decision table)

| bwrap | userns | Landlock ABI | Path |
|---|---|---|---|
| yes | yes | >= 3 | `full` (bwrap floor + Landlock RO) |
| yes | yes | < 3 / none | `bwrap-only` (RO: `--ro-bind / /` + writable scratch bind + stage2 NNP/seccomp/AF_UNIX-block, no Landlock) |
| bwrap unusable | — | >= 3 | `landlock-only` (stage2 on host; RO forces AF_UNIX block; no /proc hiding) |
| no | no | any | `unavailable` -> exit 125, refuse to run |

The `bwrap-only` RO path routes through stage2 with `--no-landlock`
rather than the plan's literal direct-bash exec: strictly stronger
(NNP + seccomp floor retained) at no extra cost.

Pin a path for testing with `OPENCODE_SANDBOX_FALLBACK=bwrap-only|landlock-only`.

## Build

```
make            # gcc -O2 -static -s -Wall -Wextra -> ../../bin/opencode-sandbox
```

## Probe

```
bin/opencode-sandbox --probe
```

Prints resolved bwrap path, userns availability (with pidns/proc-mount
degradation note), Landlock ABI number, and the sandbox path the
decision table selects.

## Environment contract

| Var | Default | Meaning |
|---|---|---|
| `OPENCODE_SANDBOX_MODE` | `rw` | `ro` or `rw` profile |
| `OPENCODE_SANDBOX_SCRATCH` | `/tmp/opencode` | sole writable hierarchy under RO; `mkdir -p`'d |
| `OPENCODE_REAL_BASH` | `/bin/bash` | shell exec'd inside the sandbox |
| `OPENCODE_SANDBOX_BWRAP` | `/usr/bin/bwrap` then `$PATH` | bwrap override |
| `OPENCODE_SANDBOX_HELPER` | `/proc/self/exe` | stage2 binary path inside bwrap |
| `OPENCODE_SANDBOX_RO_NETWORK` | `off` | `off` -> `--unshare-net` + Landlock TCP deny |
| `OPENCODE_SANDBOX_RO_AF_UNIX_BLOCK` | `1` | RO seccomp AF_UNIX deny |
| `OPENCODE_SANDBOX_MASK_WSL_INTEROP` | `1` | RO `--tmpfs /run/WSL` |
| `OPENCODE_SANDBOX_MASK_SOCKETS` | docker/podman/containerd socks | colon-separated mask list |
| `OPENCODE_SANDBOX_DENY_WRITE` | unset | colon-separated abs paths -> `--ro-bind` shadow (readable, read-only) |
| `OPENCODE_SANDBOX_DENY_READ` | unset | colon-separated abs paths -> `--tmpfs` shadow (dir exists, contents empty); both-lists path = empty AND read-only |
| `OPENCODE_SANDBOX_RW_NETWORK` | `1` | `0` -> `--unshare-net` on the RW floor too; AF_UNIX unaffected so WSL interop still works |
| `OPENCODE_SANDBOX_ALLOW_SUDO` | `0` | `1` -> RW runs host-direct (no bwrap) + stage2 skips NNP + seccomp; RO unaffected |
| `OPENCODE_SANDBOX_EXTRA_ARGS` | unset | raw bwrap argv elements joined by `\n`; appended verbatim just before the `--` payload separator (validated upstream: no `\n`/`\0`/`--`/empty elements, <=64KB; bwrap rejects bad flags = fail-closed). Trusted-config authority: `--setenv`/`--unsetenv` entries apply to stage2's environment and CAN override env-read stage2 configuration — e.g. `OPENCODE_SANDBOX_SCRATCH` widens the RO Landlock writable hierarchy (equivalent authority to `mode: full`). Do not set reserved `OPENCODE_SANDBOX_*`/`OPENCODE_REAL_BASH` overrides here; this is not a constrained security customization interface. argv-passed stage2 controls (`--mode`, `--real-bash`) and RO's argv-based allowSudo scoping cannot be forged this way |
| `OPENCODE_SANDBOX_FALLBACK` | unset | pin `bwrap-only` or `landlock-only` |

Exit status propagates unchanged through both exec chains
(`bash -c 'exit 42'` -> 42). Fatal setup errors exit 125.
