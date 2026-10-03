# Changelog

## 1.4.0 (2026-10-03)

### Jev payload/execution boundaries

- Jev review: apply a shared execution-consumer scope to all 23 questions;
  distinguish nested code/JSON data from executed programs, and retain actual
  protected-target overwrite checks even for inert replacement payloads.
- Present narrowly proven quoted-heredoc file data separately without removing
  contents or adding an ALLOW shortcut; keep cwd changes, ambiguous producers,
  protected targets and execution consumers in their original layout.
- Fix shell-fed heredoc hard guards: interpreter names must be command words,
  not filename/argument substrings; inspect the appropriate program body with
  bounded nested execution checks. Invalidate prior prompt verdict caches.
- Add 29 Python regressions and the small-batch research record, corpora and
  optimized prompt. Risk thresholds, permissions and sandbox policy unchanged.
- Carry one-call authorization into every judge and appeal question; align
  armed appeal floors with the main unconditional floor. Keep the second
  dynamic review and all DENYs; do not repeat already-authorized risk labels
  in escalation hints, while retaining full denial records.
- Enforce HARD's existing complete-script-inspection requirement using
  host-identified executed-script context. An indirection grant removes only
  that requirement, not another DENY or a safety floor; LOOSE is unchanged.

### TUI state freshness

- Re-subscribe RPC notifications and fetch authoritative permission/bypass
  snapshots after reconnects and session lifecycle/compaction events. Refresh
  known family members when an ancestor's state changes, using each session's
  own location rather than the current terminal location.
- Ignore late snapshots after plugin disposal and after session deletion;
  keep notification-handler errors from terminating subscriptions. No polling
  or server permission changes were introduced.

### Static proofs and read-only enforcement

- Release-audit fixes: fail closed on unresolved/mutated Python callable and
  argument aliases, expanded write modes, computed access, writable NumPy
  mappings and pickle loading. Parse SQL quoting/comments without hiding real
  writes or quoted executable function names; tighten curl write-out, tmux
  command chaining, compact gh mutations and stateful SQLite pragmas.

- LOOSE read-write sessions gain semantic static-allow proofs that run after
  every danger scan: an AST read-only prover for Python (`-c`, stdin heredoc,
  local scripts), read-only sqlite3 SQL, `gh` reads, tmux listing,
  version/help queries, loopback-only `curl` GET/HEAD, the RO read-only
  vocabulary reused for RW, compound-statement bodies, literal variable and
  loop-variable binding, and credential-safe glob operands of readers. No
  semantic proof covers remote network requests. On a fixed replay of 9,095
  reviewer-labelled commands static ALLOW rose from 8.1% to 44.4%, with no
  reviewer-denied command statically allowed and no new static DENY.
- LOOSE read-only sessions (`permScope.w=false`) share the lexer and
  vocabulary relaxations instead of keeping the stricter 1.3.0 verdicts:
  `sed -n … 2>/dev/null`, `~`-prefixed paths, for/if compound bodies, the
  `:` builtin, `git worktree list`/`git stash list`, and glob read operands
  are now proven read-only there too. The write ceiling is unchanged
  (writes outside the scratch root still deny, with or without the kernel
  sandbox). Replay: static ALLOW rose from 1,066 to 2,252 of 9,095 without
  the kernel and from 7,246 to 7,397 with it; no reviewer-denied command
  became a static ALLOW. HARD keeps the 1.3.0 verdicts row for row.
- New `trustedCommands` option: user-declared command prefixes are statically
  allowed in LOOSE read-write sessions once every danger scan passes.
- False-negative fixes in all modes:
  - git `--output`/`--ext-diff`/`--open-files-in-pager`, find `-fprint*`/
    `-fls`, awk `getline`/`print >`/`print |`, sed `w`, `xxd -r`, tar/zip
    program-running options, and same-directory Python modules that shadow
    the standard library in `python3 dir/x.py` (now inspected and
    fingerprinted with the script).
  - A compound-command keyword left by segment splitting (`then`, `do`,
    `if`, `else`, `!`, `{` …) no longer hides the command behind it from the
    read-only interop and mutation gates: an interop binary such as
    `pwsh.exe -Command 'Remove-Item …'` wrapped in `if … then` used to ride
    the unrecognized-leaf kernel passthrough in read-only sessions — the
    Linux kernel sandbox cannot contain Windows-side processes, so these now
    deny exactly like the bare command.
  - The temp-confined early allow no longer bypasses the executor-capability
    scans: `sed -n '1e id' x > /tmp/o` and `awk 'BEGIN{system(…)}' > /tmp/o`
    executed code behind a /tmp redirect in every mode. awk joins sed, rg,
    and `git grep` in the executor-capability gate (system/getline/
    print-pipe shapes, with quoted-string blanking so `print $1" || "$3`
    is not mistaken for a pipe).
  - Inline interpreter code that names a credential store
    (`python3 -c "print(open('/home/u/.ssh/id_rsa').read())"`,
    `node -e "…readFileSync('/home/u/.ssh/id_rsa')…"`) no longer rides a
    "pure read" proof or the kernel passthrough: the credential vocabulary
    from the path registry is matched against argument and code text, and
    read-only sessions now deny (without kernel) or send it to review
    (kernel-enforced) instead of statically allowing the read. On the fixed
    replay this removed the last 4 commands that a read-only
    kernel-enforced session statically allowed although the dynamic reviewer
    had denied them.

## 1.3.0 (2026-09-30)

- Separate inert payload text from executed commands. Proven data writers no
  longer inherit destructive findings from their fixture/script bodies;
  ambiguous consumers route to dynamic review instead of a static hard deny.
  Actual execution, shell expansion, hard floors and read/write ceilings remain
  enforced. Both dynamic reviewer prompts explicitly allow merely storing or
  printing payloads without executing them.
- Escalation review receives the last five user messages, a larger bounded
  prose window, and actual cwd/worktree. Routine administration, dependency
  installation and issuer authentication are not harm by themselves. Jev's
  deny band requires substantial harm/unsafe corroboration; category matching
  uses executable positions rather than words inside payload text.
- Retain Jev, with accident-oriented prompts targeting wrong cwd/targets,
  empty-variable globs, durable-data overwrites and loss of uncommitted work.
  Evaluated 20 prompt candidates through the full multi-question pipeline with
  more than 8,000 new completed HTTP requests; inspected real database refusals
  separately from test-session logs and infrastructure/permission errors.
  Development-set accuracy is not a guarantee of zero production false blocks.
- `/bypass category[,category] [timeout]` accepts seconds. Positive timeouts
  expire at an absolute deadline, never renewed by session or child activity;
  zero/negative timeouts never naturally expire. Omitted timeout uses the
  configured default. `/bypass off`, session deletion and plugin unload still
  clear leases. TUI notifications show the deadline/never-expire state, and
  invalid timeout input rejects before mutating the lease.

## 1.2.1 (2026-09-29)

- Reworked the Jev escalation mapping for LOOSE unattended operation
  (owner severity: frequent ask_user > benign mis-deny > rare missed deny):
  - deny needs corroboration now: retry-similarity ≥0.75, unsafe ≥0.70, a
    clear harmful-cover-story veto (new `harmful_mismatch` noul ≥0.80), or
    P(deny) ≥0.35 *with* unsafe ≥0.10 — pure "model dislikes it" no longer
    hard-blocks routine privilege escalations like `sudo apt-get install`.
  - ask_user requires the model preferring clarification AND the new `harm`
    noul reaching 0.40 (irreversible loss or immediate severe production
    impact); below the floor the benign-agent prior resolves indecision to
    allow_once instead of interrupting.
  - The `harm` criteria encode the destructive definition: irreversible or
    immediate severe production impact counts (`rm -rf` of an unbacked
    project, broad `pkill -9 node`); regenerable artifacts do not
    (`node_modules`, build output, caches).
  - `harmful_mismatch` catches dressed-up sabotage the choice question was
    soft on: e.g. `echo '0.0.0.0 github.com' >> /etc/hosts` justified as
    "fix DNS" now denies (mismatch ≈0.85) while the same command with an
    explicit intentional-block context allows.
  - New env-tunable keys: `deny_risk_min`, `ask_harm_min`,
    `harmful_mismatch_deny` in `JEV_ESCALATION_THRESHOLDS`; `allow_prob`
    removed (allow is a deliberate default, not a band).
  - Deterministic host gates unchanged: mechanism names deny, unknown
    categories ask, permScope.w=false+filesystem asks, category-mismatch
    asks, uncovered previousDenial asks.

## 1.2.0 (2026-09-28)

- Jev is now also the escalation reviewer under `reviewer: "auto"`:
  `src/security/jev-escalation-reviewer.py` answers allow_once/ask_user/deny
  from a single System One call (decision choice + necessity/unsafe/
  retry-similarity nouls, v4.2 probability-band mapping) with the same
  deterministic gates as the OpenAI-compatible reviewer — `dynamic`/`slow`
  deny, unknown category ask_user, uncovered previousDenial ask_user,
  permScope.w=false + filesystem ask_user. Latency drops from tens of
  seconds (thinking model) to ~1s.
- Escalation requests now carry `recentUserInputs` — the user's last three
  messages — on both engines, so a denial spanning multiple user turns is
  judged on the full request.
- Dynamic-deny messages no longer say "Denied by policy" (misleading);
  they read `Blocked by dynamic classifier. Risk categories: …`.
- Fix: Jev `cat_*` category nouls now judge executed effects only — inert
  payload text (file bodies, heredocs, quoted strings containing "sudo" or
  URLs) no longer inflates the risk-category set.
- Fix: reviewer trace records the Jev endpoint/model for Jev verdicts and
  only stamps a reason on actual denials.
- Fix: escalation child exit codes 6/7 classify as protocol errors, so a
  malformed Jev answer fails closed instead of falling back to the OpenAI
  reviewer (signals and other codes likewise never fall back; only 4/5
  transport failures do).

## 1.1.1 (2026-09-28)

- Fix TUI indicator not updating after `/perm` or `/bypass`: restores the
  1.0.2 fix that was dropped in the 1.1.0 refactor — the status pull now
  addresses the session's own location (RPCs without a location land on the
  service's cwd instance) and stale in-flight status replies are discarded
  via per-session revision counters.

## 1.1.0 (2026-09-28)

- Dynamic review engines: Jev (TypeSafe System One) is now an optional
  reviewer — `dynamicReview.jev` (`enabled`, `model`, `endpoint`,
  `apiKeyEnv`); `dynamicReview.reviewer: "auto"` (default) prefers Jev and
  falls back to the OpenAI-compatible auditor on infrastructure failures
  with a visible `fallback_reason`. Explicit `reviewer: "jev"` never falls
  back.
- Dynamic reviewers now return structured risk **categories** instead of a
  free-text reason: `{decision, categories[<=3], secondary_categories}`.
  Block messages carry `Risk categories: …` hints (static rules ∪ reviewer
  categories), and the denial's categories are stored so escalation
  requests are checked deterministically for coverage (uncovered → ask_user;
  `dynamic`/`slow` requests → deny). Escalation retry matching compares
  command tokens only, so adding the missing category is not mistaken for a
  replay.
- Reviewer prompts: armed categories move to the tail with a head-line
  reminder; an armed category cannot be selected as a risk category (only
  armed categories → ALLOW); write-vs-execute and category disambiguation
  wording added.
- Static classifier: interpreter heredoc bodies (`python3 <<EOF`, `node`,
  ...) are scanned for dangerous calls only at execution sinks — comments
  and inert string literals inside them no longer trigger destructive
  floors.
- TUI badges: `[Read Only]` / `[Read + Write]` / `[Write Only]` /
  `[…, Bypassing Category(ies): …]` / `[YOLO ON, Bypassing all permissions]`;
  `/bypass yolo`/`YOLO` is a case-insensitive kill-switch alias.
- Fixes: Jev redirect following disabled (no Authorization leak), malformed
  Jev answers fail closed, cached DENY refreshes escalation coverage state,
  `..`-preserving rm-target normalization, appeal/answer range validation.

## 1.0.1 (2026-09-25)

- Fix published CLI/TUI loading by declaring the Solid and OpenTUI JSX runtime
  peer dependencies required by `src/tui.tsx`.

## 1.0.0 (2026-09-25)

- Security (round 3): shell comments are now part of the lexical split — an
  unquoted `#` at word start comments to the newline, so a trailing quote in a
  comment can no longer corrupt the parse and hide a destructive chain
  (`ls; rm -rf ~ #'`), and comment text can no longer manufacture rule or path
  findings (`ls # rm -rf /` stays ALLOW). Unparseable input is now explicit:
  it never reaches a known-safe/read-only early allow (LOOSE → ASK, HARD/RO →
  DENY, kernel-enforced LOOSE keeps the non-write gate).
- Security: `git push` flag/refspec analysis is semantic argv parsing, not
  regex — quoted and partially-quoted spellings (`"--force"`, `'-'f`,
  `--fo"rce"`, ANSI-C encoded words), `--force-with-lease`, `--delete`,
  `--mirror`, and `+`/`-`-leading refspecs are all caught through global
  options and transparent launchers, while ordinary pushes, `--tags`,
  `--prune`, and text merely mentioning a push stay ALLOW.
- Security: executor modes can no longer ride known-safe/read-only shortcuts:
  `rg --pre`/`-M`, `git grep -O`/`--open-files-in-pager` (including the bare
  default-pager form), and the `sed` `e` family (`e` command, `s///e` flag,
  repeated `-e`, unknown `-f` scripts) are gated; statically extractable
  payloads are scanned (destructive payloads DENY), unextractable ones stay
  unproven, and under a read-only session they are denied outright — the
  kernel's write containment cannot confine a child's reads or network use.
- Policy: `dynamic` and `slow` are no longer grantable via the escalation
  protocol (a grant may not disable the review layers themselves); `sandbox`
  stays grantable and the rejection names the accurate category list. An
  armed `/bypass dynamic` now always behaves as reviewer-unavailable +
  fail-open regardless of `failPolicy`. New `escalationEnabled` option
  (default `true`): when false the escalation header is an inert comment, the
  escalation reviewer is not consulted, and no block text mentions the
  mechanism. Ordinary dynamic review can still run for the resulting command.
- Security: static floor refusals in the escalation precheck no longer write
  a reviewer-denial record — a classifier false positive can no longer lock
  out similar requests (the audit trace and the floor refusal itself are
  unchanged).
- False positives: proven data no longer trips destructive rules — quoted
  inert arguments of bare `grep`/`egrep`/`fgrep`, `rg` without a
  preprocessor, and `git commit -m` values are masked for rule scans only
  (paths/credentials still see real arguments), and heredoc bodies proven to
  feed a data consumer with no pipe-to-code or expansion are masked. Quoted
  bodies feeding shells/interpreters/databases, pipe-to-code heredocs, and
  every unknown layout keep the conservative raw scans.
- Security: the `cleanup.temp-confined` exemption no longer defeats credential-delete
  protection — `rm .env` / `rm id_rsa` / `rm -rf .ssh` under a temp root now emit
  `data.critical-delete` (needs `filesystem+secret`) exactly like a normal-root cwd,
  instead of fail-opening to ALLOW; ordinary temp cleanup keeps its ALLOW.
- Security: privilege launchers key to the `privilege` category in BOTH static gates.
  The kernel-enforced read-only non-write gate used to key sudo/doas/runas/pkexec to the
  host-keyed process rule, so arming `host` ALLOWed a sudo launch while arming
  `privilege` did not — inverted versus README. The rw trigger covered only
  `sudo|runas`, leaving `doas`/`pkexec`/`su`/`sudoedit` (and chown/chgrp/setcap/
  setfacl/mount/umount/unshare/nsenter/chroot) unmapped and clearable by any single
  armed category.
- Security: launcher and boundary-mutator words now match ONLY at command position on
  executable surfaces — the segment, quoted `-c`/`/c`/`-command` wrapper payloads,
  decoded payloads, `$(…)` command-substitution bodies, and heredoc bodies whose
  consumer executes them (unknown consumers keep the body in the scan fail-closed);
  the resolver follows wrapper leaves that execute a later operand (`eval`, `xargs`,
  `sh`/`bash`/`zsh`/`dash`/`ksh`, `exec`) and `find -exec`/`-execdir` operands.
  Launcher words in plain arguments, comments, or commit messages
  (`some-unknown-tool --label doas`, `git commit -m "use doas"`) never trigger. The rw
  privilege gate sits ahead of the generic wrapper/indirection ask, so
  `sh -c 'doas id'`, `eval "pkexec id"`, and `echo $(sudo id)` carry the
  privilege-keyed `operation.context-required` finding — arming `privilege` moves
  them on to the wrapper review instead of clearing everything.
- Security: shell-heredoc bodies keep their non-ALLOW classification results
  (previously only body DENYs survived the heredoc early return), so
  `bash <<'EOF'` carrying a `sudo id` body — quoted or unquoted — carries the
  privilege finding and arming `privilege` clears it. Benign heredoc bodies
  (data writers, `ls`/`echo` scripts, language programs) still classify ALLOW and
  keep their ordinary verdicts; nothing newly denies.
- Security: account/identity tools (`useradd`/`usermod`/`userdel`/`passwd`/
  `chpasswd`/`visudo`/`runuser`/`setpriv`/`capsh`) gate on the `privilege` category
  at command position, agreeing with the sandbox router's privilege set instead of
  falling to unmapped `operation.unknown`.
- Security: write-direction `/proc/sys` access (`echo 1 > /proc/sys/...`, `tee`,
  `dd of=`, `mkdir`) emits `kernel.sysctl-write` (privilege) instead of
  `credentials.sensitive-access` (secret), matching `sysctl -w` and README;
  reads keep their sensitive-path classification.
- Security: force push (`git push --force` / `-f`) is `git.remote-history-rewrite`
  (remote category) only — arming `remote` no longer leaves it blocked by the
  filesystem-keyed `git.irrecoverable-change`. That rule keeps covering
  local-worktree loss and gains its documented coverage for
  `git checkout|restore -- .` (the old regex never matched: trailing `\b` after
  a dot cannot match at end of string) and `git branch -D` (case-sensitive;
  lowercase `-d` stays out). `--force-with-lease` keeps its review-signal ASK.
- Taxonomy consistency: bypass.ts comment and the README `secret` row now state
  the actual conjunctive map (read = `secret`, modify/delete = `filesystem+secret`);
  README documents that the legacy `os` alias no longer covers `remote`; the
  `/bypass` usage and escalation guidance strings list `pkexec`/`sudoedit` in
  their `privilege` examples; `permissions.world-writable` covers non-777
  world-write grants (any octal mode whose last digit grants other-write, and
  symbolic `o/a/go/ugo+w`, bare `+w`; `u+w`/`g+w` stay out); `namespace.escape`
  matches `unshare -U` short flag clusters.
- Testing: `tests/taxonomy-fixes.test.ts` (135 tests) pins all of the above,
  including non-known-safe negatives for launcher words (unknown tools with
  launcher-looking arguments, commit messages), executable-surface positives,
  heredoc body positives/negatives, and the account-tool gate.
- Fix the escalation reviewer's hardcoded 20 s HTTP timeout that made every real
  (thinking-enabled) escalation review end in a transport error: both Python
  reviewers now derive their deadline from the resolved child-process budget
  (`OPENCODE_V2_SECURITY_REVIEW_DEADLINE_S` /
  `OPENCODE_V2_SECURITY_ESCALATION_DEADLINE_S`, forwarded by the TypeScript
  parent at budget − min(2 s, budget/2), strictly below every positive budget so
  a slow endpoint yields a clean transport error rather than a SIGKILL), the
  auditor applies ONE absolute deadline across the whole multi-round review, and
  the escalation review budget is `max(dynamicReview.timeoutMs, 120 s)`.
- Fix the escalation floor pre-check missing floor rules shadowed by unrequested
  categories or by an earlier segment's bypassable denial: the pre-check
  classification now runs with every static category armed, so root-deletion
  escalations are refused terminally (zero reviewer HTTP calls) even when the
  request only asks for `host`/`remote`.
- Escalation failure memory now covers the session's ancestor chain (bounded at
  the same 64 nodes as ancestry hydration): the similar-request check reads the
  read-only union of the parent's and own failure lists, so a denied request
  retried verbatim from a child (subagent) session is refused locally without
  another reviewer call. The 8-entry cap is unchanged.
- The escalation reviewer's system prompt now carries the same one-line category
  glosses as the agent guidance and states that `dynamic`/`sandbox`/`slow` are
  LAYER categories that remove a protection layer and must only be granted when
  the justification explains why that layer blocks the task.
- Similar-request matching is unchanged by design: a review found that comparing
  the last token lets comments, redirects, and trailing `; true` reopen a denied
  request, so no operand comparison was added (regression tests pin the
  cosmetic-rewrite behavior).
- Routing slice: close the silent-privilege-failure gap when the `privilege` category is NOT armed. A
  command that needs OS privilege now fails loud before the dynamic reviewer — instead of being wrapped in
  bwrap (NO_NEW_PRIVS + cap-drop) where sudo/chown would die with a confusing runtime error. The refusal
  names `privilege` as the missing category and points at `/bypass privilege` or adding `privilege` to the
  escalation. `sandbox`/`all` bypass (profile "full") and the rw `sandbox.allowSudo` host-direct route keep
  working as before. Reminder/audit lines are unchanged (only a real host-direct run records them).
- Extend `commandNeedsOsPrivilege` with the clear-cut root-requiring tools missed before: `runuser`,
  `setpriv`, `capsh`, `useradd`/`usermod`/`userdel`/`passwd`/`chpasswd`/`visudo`, `iptables`/`nft`/`ufw`,
  `losetup`, `setenforce`, `kexec` (both the command-word set and the conservative parse-failure fallback).
  Debatable tools (`chcon`, `fusermount`, `systemd-run`, `update-grub`/`grub-install`, `chattr +i`) are
  deliberately left out; see FIX-NOTES. `--privileged=false` stays excluded.
- Extend `tests/category-privilege.test.ts` with the new detection matrix and the fail-loud regression
  cases. Document the remaining limit (README `privilege` row): a stdin pipe into a shell (`echo 'sudo id' |
  sh`) is not recognized as privilege-needing; shell `-c`/eval, command substitution, and (round 2) shell
  heredocs are.
- Routing heredoc coverage (round 2 / D4): `commandNeedsOsPrivilege` now scans a heredoc body when its
  consumer is a shell (`bash`/`sh`/`dash`/`zsh`, also behind `env`/`command`), quoted or unquoted delimiter —
  so `bash <<'EOF'\nsudo id\nEOF` needs privilege and R1 refuses it when unarmed / routes it host-direct when
  `privilege` is armed. Heredocs consumed by `cat`/`python3`/`tee …` remain inert data and stdin pipes stay a
  documented limitation.

## 0.9.1-v2 (2026-09-21)

- Split the `host` bypass category's privilege semantics into a new static category `privilege`:
  `host` now covers running-system state (processes, services, power, persistence, anti-forensics)
  while `privilege` covers crossing permission or isolation boundaries (sudo/doas/pkexec/su/
  sudoedit, chown/chgrp/permission bits with setcap/setfacl, kernel parameters, namespace
  escapes, kernel modules, privileged containers). Guidance text, `/bypass` usage, layer notes,
  and the README category table now describe the split honestly.
- Fix the host/privilege ↔ OS sandbox inconsistency (flagship): a call whose effective bypass set
  (session lease ∪ per-call escalation grant) contains `privilege` and whose command needs OS
  privilege now runs host-direct instead of dying silently inside bwrap's unconditional
  NO_NEW_PRIVS/cap-drop floor. rw profiles reuse the existing `sandbox.allowSudo` host-direct
  helper route — the nonce marker carries a per-call `hostDirect` flag, so `OPENCODE_SANDBOX_
  ALLOW_SUDO=1` reaches the helper even when `sandbox.allowSudo` is false. When the call cannot
  leave the sandbox (ro profiles ignore allowSudo), the plugin now refuses terminally and loudly
  (pointing at `/bypass sandbox`, adding the `sandbox` category to escalations, or configuring
  `sandbox.allowSudo`) instead of letting sudo/chown fail silently at runtime. Each host-direct
  call appends an `opencode-v2-security:` agent reminder stating the call runs without the OS
  sandbox, and a `privilege_host_direct` reviewer-trace line when `logReviewerTrace` is on.
- Add an escalation floor pre-check: before a valid REQUIRE_ESCALATION request is sent to the
  escalation reviewer, the static classifier runs once with the best possible grant (session
  categories ∪ requested categories). If the command would still be denied by a rule no bypass
  category can ever exempt (the unconditional floor, the `permission.write` permission ceiling,
  opaque input), the request short-circuits — no reviewer HTTP call, a terminal refusal stating
  the escalation cannot cross the hard floor, and the outcome is recorded as a deny so similar
  re-requests cannot loop through the reviewer with reworded justifications.
- Testing: `tests/category-privilege.test.ts` covers the host-direct wrap decision (session lease
  and per-call escalation arms, asserted with the `{host, privilege}` dual arm), the ro-profile
  fail-loud terminal refusal, the floor pre-check short-circuit (reverse-shell and root-delete
  escalations reach zero reviewer HTTP calls), and the updated contract text.

## 0.9.0-v2 (2026-09-19)

- Rename the current plugin and install directory from `opencode-bash-classifier` to
  `opencode-v2-security`; current configuration and documentation use the new plugin name.
  Older command spellings retained below are historical records only.
- Refine bypass policy into the nine canonical categories `filesystem`, `host`, `secret`,
  `network`, `remote`, `indirection`, `dynamic`, `sandbox`, and `slow`. Input aliases `fs`,
  `os`, and `web` expand at the boundary and warn; permanent `BypassClassifier` state uses
  canonical names.
- Add one-shell escalation with the exact byte-zero, three-line prefix. A direct Python
  reviewer examines the user input, recent context, permission scope, and previous failed
  requests with thinking enabled and returns only `allow_once`, `ask_user`, or `deny`.
  `allow_once` adds only the approved categories for that shell and still runs the ordinary
  static, dynamic, permission, and sandbox checks not exempted by those categories; the reviewer
  is limited to two starts per rolling three seconds, and similar requests cannot be retried
  after `ask_user` or `deny`.
- Harden agent guidance and `/bypass` synthetic notices: the notice describes trusted user
  authorization rather than a system reminder or injection-style message, and blocked agents
  are told to skip an unnecessary step or ask for escalation instead of trying to bypass the check.
- Split the block ending: ordinary static/dynamic/policy blocks keep the exact escalation suffix
  and the once-per-cycle full guide (now with terse per-category meanings, one-call/independent-
  reviewer semantics, and the ask_user/deny no-retry rule). Terminal escalation outcomes —
  pending, history saturated, similar denied, reviewer unavailable, context read failure,
  session ended, reviewer ask_user/deny — end with skip-or-user-authorization copy
  (`/bypass <categories>` when known, else `/bypass`/`/perm`) and never say "ask for escalation";
  reviewer infra errors state that no failure was recorded and the same request may be retried
  later. `permission.write` hard refuses carry a dedicated ending pointing at `/perm +w` or
  `/perm rw` and neither attach nor consume the full guide. Agent reminders are prefixed with
  `opencode-v2-security:` and no longer expose internal event tokens; the permission reminder
  describes the concrete r/w/x label without claiming a user change, and the sandbox-unavailable
  deny names the user (not the agent) as the one who may install bubblewrap or relax
  `sandbox.onUnavailable`. Dynamic-review configuration reasons are folded to
  "dynamic review unavailable or invalid review configuration" in agent-facing messages; the
  verbatim detail stays in the reviewer trace/log. The stale subagent `permission` validation
  message now lists only the accepted `ro/4, rw/6, w/2, none/0` spellings, and the `/bypass`
  description clarifies that uppercase `ALL` is the kill switch while specific categories are
  preferred.
- Show the full escalation usage only on the first classifier block of a session's context
  cycle: the first static/dynamic/policy block carries the full three-line format and the
  allowed-category list; later blocks in the same cycle keep only the short guidance. A
  completed compaction (`session.compaction.ended`; the schema-manifest `session.compacted`
  alias is also accepted) starts a new cycle, `session.deleted` and plugin unload clear the
  state, and a plugin reload naturally starts fresh. The claim is synchronous at
  block-message construction, so concurrent blocks of one session never both show the full
  text and allow paths never consume it; paths that block without escalation guidance
  (soft slow, permission deny, patch delete) are untouched. The full guide no longer ends
  with the "all/*/ALL are forbidden" sentence — the parser still rejects wildcard
  categories.
- Resolve the armed-`dynamic` bypass + `fail_close` conflict with a dedicated terminal message
  instead of the ordinary fail-closed block: it explains that the user-armed bypass skips LLM
  review while the active fail-closed policy requires a review result, tells the agent to report
  the policy conflict to the user, and never attaches BLOCK_SUFFIX or consumes the per-cycle
  guide. `fail_open` still allows. Agent-facing copy cleanup: bypassable static DENY reasons no
  longer claim an absolute "forbidden" (they name the policy/authorization that actually gates
  them — the unconditional floor keeps its deny verdicts), escalation ask_user/deny refusals use
  natural sentences instead of quoted internal verdicts, bypass reminders read "because the user
  authorized" / "within the user's authorization" and the restore notice drops the bracketed
  `[ENFORCEMENT RESTORED]` marker, category notes state that the permission ceiling and floor
  still apply (and that off-host secret transfer still needs `network`), and every agent-visible
  x-bit string reads "x cannot be set; it is always on and only shown in the label."
- Restrict the `set_permission` tool to direct child sessions: `sessionID` is now a required
  argument (missing or empty fails closed, with no fallback to the caller), the target must
  be a direct child of the calling session (structural parent link or live `session.get`
  lookup; the caller itself, grandchildren, and unknown sessions fail closed), and writes
  remain tighten-only. The tool description, field descriptions, and success text use
  child-only wording; the user-side `/perm` command and the subagent `permission` argument
  are unchanged.
- Fix read-only child-session creation: a read-only parent can create a read-only child, while
  child permissions still inherit the parent's ceiling and can only become narrower.
- Make concurrent escalation reservations atomic, fail closed when the bounded failure history
  saturates, and complete permission ancestry at execution boundaries.

> Entries below 0.9.0-v2 are historical implementation notes. Their old plugin and command
> names do not describe the current interface; see `README.md` for the current contract.

## 0.8.2-v2 (2026-09-10)

- Deliver the agent bypass reminder as an **appended user message** instead of a system-prompt
  part. `session.synthetic` (`resume:false`) lowers to `role: "user"` in the request
  (`runner/to-llm-message.ts`), so appending it at the end of history keeps the cached prefix
  intact — a `system` part sits near the front and invalidates the message cache. A user message is
  also more salient to the agent.
- Send reminders only on state transitions (arm/change/end), not every step, so they no longer
  grow the request each turn. They carry no `description`, so the user's chat transcript is
  unaffected (the user is notified separately over RPC).
- Track the last announced category set per session so expiry is detected correctly. The previous
  expiry check recomputed the set after the lease had already expired and so never announced the
  end; subagents created under an active bypass now also receive one reminder.

## 0.8.1-v2 (2026-09-10)

- Fix the TUI companion silently dropping every notification after the user switches to a session in
  a different directory. The companion captured `context.location` **once at setup** and compared it
  against each event's location; the captured value froze the directory the TUI happened to be on
  when the plugin loaded. It now reads the live `context.location` getter per event and only filters
  on a definite `workspaceID` mismatch, never on a directory spelling/timing difference.

## 0.8.0-v2 (2026-09-10)

- Fix `/bypass-classifier` feedback channels. Previously state/usage was returned via
  `session.synthetic` without a `description`, which made it **model-visible but hidden from the
  TUI transcript** (v2 synthetic messages enter the model context; description-less ones are
  filtered from chat rows).
- Agent notification now goes through `session.hook("context")`: a short `<system_reminder>`
  warning is re-injected on every step while a bypass is active, and a one-shot "bypass ended"
  reminder fires on expiry. Neither wakes the session.
- Added a lease-expiry sweep (20s) so the expiry transition is observed; lease pruning was
  previously lazy and produced no notification.
- User notification now goes through an event-only RPC (`src/bypass-rpc.ts`) consumed by an
  optional TUI companion (`src/tui.ts`, package `exports["./tui"]`) that shows toasts. No sidebar.
- `/bypass-classifier <invalid>` now fails the command (TUI shows the usage) instead of echoing
  usage to the model. Removed all bypass-related session messages.
- Also fix the same visibility defect in the two adjacent alerts: the dynamic-reviewer outage
  notice and the prompt-injection alert now carry a `description`, so they render in the TUI chat
  (they were previously model-only despite comments claiming TUI visibility).
- State-machine hardening after review: re-arming clears a queued "bypass ended" notice; the
  expiry sweep reports "ended" only when no permanent/inherited bypass remains; notices are
  cleared on session deletion; `armed` vs `updated` now reflects prior state.

## 0.7.3-v2 (2026-09-08)

- Remove the unfinished `hardTimeoutMs` foreground/background timeout mechanism: delete the config option, resolution, and `applyPostChecks` injection. OpenCode's shell tool already applies a 120s foreground default timeout.
- Fix slow-command false positives: expensive home/system roots are now exact-root matches, so scoped directories such as `~/.cache/opencode` and `/proc/self` are no longer flagged.
- Raise the default `slowCommands.maxDepth` threshold from 3 to 16 so explicit bounded `find -maxdepth 4` scans are allowed.
- Fix `findRoots()` so `find -maxdepth 4 /path` and other path-option-before-root forms are parsed correctly instead of being missed.
- Update slow-command block hint to describe the actual bound requirement.

## 0.7.2-v2 (2026-09-05)

- Build dynamic policy from enabled categories; remove bypassed prohibitions and emphasize trusted BYPASS PERMISSION at both ends of the system prompt. Preserve the unconditional safety floor.
- Distinguish normal API/SSH authentication and probe data from credential theft; LOOSE no longer treats missing script evidence as sufficient grounds for rejection. Re-evaluate previous rejections against current permissions.
- Exempt deletion-directory mandatory inspection under HARD filesystem bypass, while retaining executed-script inspection and independent reviewer tool-access limits. Bump verdict cache prompt version to v5.
- Fix findings F1–F3: literal short sleep uses static ALLOW plus the existing duration guard; bounded worktree file globs for a small read-only command set use concrete-path checks; simple backticks share recursive read-only substitution review with $(). Keep dynamic/ambiguous substitutions, sensitive paths and symlink escapes conservative.
- Add Bun static/security regressions and Python policy-combination/inspection regressions.

## 0.7.1-v2 (2026-09-03)

### Changed
- **LOOSE backup-deletion relaxation (static)**: a backup file may now be deleted
  in LOOSE mode whenever it is obviously a backup — its name contains a complete
  separator-delimited backup word (`bak`, `backup`, `old`, `orig`; a substring
  inside a larger word like `bakery` does not count) and the same directory holds
  a similarly named file (the original or another dated copy). This replaces the
  exact-suffix-only rule (`.bak`/`.backup` with exact original, same kind, older
  than two minutes) for LOOSE; dated and prefixed backup names
  (`db-backup-20260813.sql`, `backup-config.json`) are now statically ALLOWed
  instead of falling to the dynamic reviewer. Credential/private-key backups
  (`.env.bak`, `id_rsa.backup`) remain DENY. HARD mode is unchanged.
- **Dynamic reviewer LOOSE prompt** updated to mirror the same rule, and
  `PROMPT_VERSION` bumped v3 → v4 to invalidate cached verdicts.

## 0.7.0-v2 (2026-09-01)

User-configured bypass escape hatches to cut false positives and over-caution, plus
reviewer prompt hardening. All findings from the post-implementation review round
(A1–A3, B1–B5, C1–C2, D1–D6, E1–E4) are fixed.

### Added
- **`BypassClassifier` (permanent)**: config field listing categories whose static
  checks are exempted — `filesystem` / `os` / `secret` / `dynamic` / `web`
  (unknown categories warn and are ignored).
- **`/bypass-classifier <category|all|off>` (temporary)**: server-registered slash
  command; arguments never enter model context. Implemented as an in-memory
  activity-renewed lease (TTL `bypassLeaseTtlMs`, default 20 min, range 1 min–24 h)
  renewed on session activity events, expiring when the TUI stays quiet or the
  service restarts. Arming is additive; `off` resets then arms.
- **Subagent propagation** (`bypassPropagateToSubagents`, default on): child
  sessions union all live ancestor leases; child activity renews ancestor leases.
- **Non-bypassable floor**: literal root/system-root deletion (`rm -rf /`,
  `rm -rf /etc`, brace/root-glob/find-root deletes), disk destruction, fork bombs,
  kernel triggers, and reverse shells stay DENY under every armed category.
- **Dynamic reviewer bypass rules**: per-category BYPASS RULE system-prompt blocks
  (filesystem/os/secret/web) telling the model what the user declared trusted,
  with the floor explicitly kept DENY. Environment line (OS name via
  /etc/os-release, shell) now sent with every review.

### Changed
- **Reviewer user prompt restructured** for injection resistance: header
  `Inspect the following command.` + environment line, command wrapped in
  `<data></data>` with XML-escaped content (a literal `</data>` can no longer break
  out) and `[DATA]` reminders every 1500 chars, tail anchor after the block.
  Context JSON no longer contains the raw command.
- **Prompt wording accuracy**: the marker claim now describes exactly which fields
  carry `[untrusted user data]` (command, local script contents, previous-command
  fields) instead of claiming every JSON string is marked.
- **`config.json` layering**: the package-root `config.json` is now always the base
  layer; `options.configFile` overlays it; `options` overlay both, field by field.
- **`operation.unknown` fallback**: with any bypass category armed, commands whose
  firing checks were all absorbed return `bypass.static-allow` ASK (consistent with
  the armed BYPASS RULE at the reviewer) instead of "cannot prove safe".
- **Network trigger matching**: network clients (`curl`/`wget`/`ssh`/`scp`/`rsync`/…)
  are matched as command words only, so paths like `~/.ssh/id_rsa` no longer wrongly
  defeat a `secret` bypass.

### Fixed
- Lease prune no longer drops child→parent links (only `session.deleted` clears
  them, and deletion now also removes links pointing to the deleted parent);
  `activeBypass` unions the whole ancestor chain; renewal covers ancestors.
- Credential rules (`data.critical-*`, `filesystem.critical-backup`,
  `permissions.sensitive-mode`, `filesystem.compression-sensitive`) follow the
  `secret` category; HARD/LOOSE deletion and backup policies gate each DENY
  per-rule, so `filesystem` alone no longer disables secret checks and `secret`
  alone clears `rm -f .env` style deletions at the dynamic reviewer. Recycle-bin
  findings and HARD recycle-block returns (`data.critical-delete`,
  `data.destructive-delete`, `filesystem.protected-target-delete`) are gated the
  same way.
- `network.`-prefixed rules (`destructive-api`, `firewall-mutate`) now follow `web`;
  `hard.named-temp-delete` / `hard.backup-target-delete` / `hard.local-temp-delete`
  follow `filesystem`; `filesystem.backup-destruction` maps to `filesystem`
  (snapshot/recovery destruction is data destruction); recycle-bin permanent
  delete maps to `filesystem`.
- Heredoc findings, `execution.local-script`, and `execution.local-script-signal`
  respect armed categories.
- **Floor hardening (segment-split evasion)**: fork bombs
  (`:(){ :|:& };:`, one-sided pipe recursion `f(){ f | g; }; f`, `while :; do
  $0& done`), kernel-trigger writes (`echo x | tee /proc/sysrq-trigger`,
  `cp x /proc/sysrq-trigger`, sysctl-style `kernel.core_pattern=`), and
  core_pattern writes are now judged on the full script, because the `&`/`|`
  inside these shapes previously split them into per-segment pieces the rules
  never saw — the fork-bomb rule did not fire on the canonical shape even
  without any bypass. The fork-bomb predicate now treats quoted spans as inert
  data, requires the function name as the command word of a pipe side
  (recursion core; `build(){ npm run build | tee log; }; build` stays allowed),
  and fixes the `while :`/`while [ … ]` boundary that made those alternatives
  dead. The kernel predicates are command-position anchored (so `echo tee
  /proc/…` inert text does not match) and accept quoted destinations with
  trailing comments/redirections.
- The system-root deletion floor (`rm -rf /etc`) now matches only the bare root
  or a direct glob over it (`/etc/*`, `/etc*`) — never deeper paths
  (`/var/tmp/...`, `/home/user/project/...`), which the filesystem bypass
  covers. One shared `SYSTEM_CRITICAL_ROOTS` list now drives both `rm -rf` and
  `find … -delete` floors (etc/usr/bin/sbin/boot/var/home/root/opt/lib/lib64/
  srv/sys/proc/mnt), so they cannot disagree; `/lib64` and `find /lib64
  -delete` are covered.
- Environment line reports the OS name (e.g. "Ubuntu 24.04 LTS WSL") instead of a
  kernel release, with WSL distro-name dedup.
- `userBypass` is sorted to match the dynamic cache key (one key ⇒ one prompt
  ordering).

### Known issues
- None currently. (The previous fork-bomb gap — `:(){ :|:& };:` evading the
  dedicated rule via segment splitting — was fixed with full-script floor checks.)

## 0.6.1-v2 (2026-08-26)

Comprehensive audit round (attack-surface gap analysis + adversarial LLM probing of
DeepSeek-V4-Flash and GLM on an OpenAI-compatible gateway). Findings and fixes:

### Fixed
- **Security (`git.remote-history-rewrite`)**: force-push / mirror push / remote
  branch & tag deletion / `update-ref` / `filter-branch`/`filter-repo` are now
  DEFINITE DENY in both policies (previously only an ASK signal, and several
  shapes — `--mirror`, `--delete`, `-C` prefix, delete-refspec — fell through to
  plain `operation.unknown`). `--force-with-lease` stays an ASK signal.
- **Security (`filesystem.root-glob-delete`)**: `rm -rf /*`, `rm -rf /etc*` and
  other absolute glob forced deletes are DENY (temp-area globs exempted).
- **Security (git hooks)**: writing into `/.git/hooks/` is ASK (LOOSE) / DENY
  (HARD); previously `cp evil.sh .git/hooks/pre-commit && chmod +x … && git commit`
  ran planted hooks through a fully ALLOWed chain.
- **Security (PowerShell pipeline delete)**: `… | Remove-Item` joins the
  destructive-pipeline rule (previously only `… | xargs …` was caught).
- **Security (at/systemd-run persistence)**: one-shot at/systemd-run timers join
  the persistence review signal.
- **Cache (dynamic-review poisoning)**: the psql cache-key normalizer no longer
  collapses `begin`/`prepare`/`values`/`with` SQL, and `select`/`show`/`describe`/
  `explain`/`vacuum`/`analyze` payloads are only collapsed when they contain no
  write keyword and no known side-effecting function. Previously a cached ALLOW
  for `psql -c "select 1"` was reused for `insert`/`prepare`/`pg_terminate_backend`
  payloads without review.
- **Security (local-script exfil)**: `hasExfilOrDangerousPerms` now also runs
  against inspected script content, so `bash script.sh` containing `curl -T` /
  `scp` uploads of sensitive data surfaces a review signal instead of ALLOW.
- **Security (named temp under /tmp worktrees)**: the named-temp whitelist no
  longer fires for every delete when the worktree itself lives under `/tmp` or
  contains a `tmp`/`temp` directory segment contributed by the worktree prefix.
- **FP (disposable cleanup)**: the disposable-directory whitelist now accepts
  quoted targets, long/split flag spellings, nested/ancestor paths
  (`some/pkg/node_modules`, `node_modules/.cache/puppeteer`, `src/generated`),
  brace-expanded targets, and additional generated-artifact names
  (venv, .tox, .mypy_cache, .ruff_cache, .nyc_output, .parcel-cache,
  .sass-cache, storybook-static, playwright-report, test-results, .angular,
  .dart_tool, htmlcov, .eggs).
- **FP (HARD inert echo)**: `echo 'rm -rf /'` no longer trips the HARD
  forced-recursive-delete deny.
- **FP (git clean flag order)**: `git clean -xdf` / `-dfx` are now matched
  regardless of flag order.
- **Budget (`slowCommands`, new option, default on)**: safe-but-wasteful commands
  — unbounded scans of system/mounted trees (`find`/`du`/`grep -r`/`rg`/`ls -R`
  over `/`, `/mnt/*`, `/home`, `/usr`, …), streaming commands (`tail -f`,
  `journalctl -f`, `docker/kubectl logs -f`, `watch`, unsteady `ping`/`tcpdump`,
  bare `yes`), and `sleep` at or beyond the 120-second default threshold — are
  DENYed statically with bound-it guidance, unless the caller passes an
  explicit timeout parameter.

### Cache (P2)
- **Global cross-session cache**: cache keys no longer carry the session ID —
  the payload already pins every security-relevant context (script, cwd, shell,
  static rules, fingerprints, directory listings, referenced paths, strictness,
  endpoint, model, prompt version), so identical contexts reuse a verdict across
  sessions. Allow-TTL reduced 30min → 15min to bound staleness.
- **Negative cache (90s)**: dynamic DENY results are replayed for 90 seconds so
  a stubborn model retrying the same denied command stops burning review calls.
- **In-flight dedup**: concurrent identical reviews share one auditor call.
- **Normalizer coverage**: `docker logs --tail N <id>` / `-n` / `--since` / `-q`
  / `-f` and `kubectl logs [-f] [-c container] <pod>` now share one cache entry
  with their bare forms.

### Hardening (P3)
- **`sed -i` durable-data overwrite** no longer rides the provably-safe early
  allow: `sed -i … file.csv|.json|.db|.sqlite|.xlsx|.parquet` is ASK.
- **Brace-expanded disposable cleanup**: `rm -rf src/{dist,output}` is ALLOWed
  when every expansion is an eligible disposable path inside the worktree.
- **Cross-segment variable tracking**: `D=rm; $D -rf ~/x` classifies the
  substituted surface too and keeps the worse verdict (now DENY).
- **Auditor transport resilience**: `_post_chat` retries fast-failing network
  errors (TLS/proxy resets) once within budget; 429 honors `Retry-After` and
  5xx retries with backoff, while other 4xx (auth/client errors) never retry.
  The prompt-injection detector separately retries 403 gateway jitter.

### Considered, intentionally not changed
- `git reset --hard` / `git checkout -- .` stay ASK signals: the dynamic layer
  denies them reliably, and a static DEFINITE deny would break routine
  discard-experimental-changes workflows.

### Auditor prompts (DeepSeek-oriented)
- LOOSE/HARD prompts now deny shared remote Git history rewriting explicitly.
- History clearing / history-file deletion is DENY in LOOSE (was a carve-out the
  model over-applied).
- Process termination is calibrated: PID- or scoped-`pkill` for the user's own
  dev process is ALLOW; broad/system termination is DENY.
- LOOSE adds slow-command guidance mirroring the static rule.

### Plugin shape (effect migration)
- **Effect plugin form**: the plugin is now `{ id, effect(ctx) }` whose `effect`
  returns an `Effect.Effect` (was the promise `{ id, setup(ctx) }`). Hook
  callbacks return `Effect`s: `execute.before` blocks route through
  `Effect.tryPromise`'s `catch` as a single-call typed `Tool.Error` failure
  (`catchTag("Tool.Error")` discriminates by `_tag`, so the rejection object
  need not be a real `Tool.Error` instance), `execute.after` swallows errors
  (`Effect.catchAll`), `shell.create.before` is `Effect.sync`, and the
  `session.deleted` consumer is `Stream.runForEach` + `Effect.forkScoped` tied
  to the plugin scope. `ctx.session.*` Effects run against the host-provided
  runtime captured inside `effect` (not a bare `Effect.runPromise`).
- **Fail-close protocol routing + injection detector**: under HARD, a
  protocol-class `ReviewError` (oversized payload, bad auditor shape/exit) is an
  **unconditional fail-close** regardless of `failPolicy`; under LOOSE every
  review failure — protocol or infra — honors the configured `failPolicy`
  (the auditor never enforces mandatory inspection under LOOSE). An infra-class
  error or unknown non-`ReviewError` honors `failPolicy` in both modes. On HARD
  + protocol with a configured
  reviewer endpoint, the prompt-injection detector is tripped: `injection:true`
  blocks + interrupts the session (with a `resume:false` synthetic warning);
  detector failure (`undefined`) fail-closes with a note; `false` still
  fail-closes (a protocol violation always denies). HARD bypass/abort timing
  fixed: the interrupt is fire-and-forget-delayed so the block message stays
  the visible outcome (was rewritten to STEP_INTERRUPTED when it landed first).
- **hardTimeoutMs no longer overrides background**: the `hardTimeoutMs`
  injection in `applyPostChecks` is skipped when `input.background === true`
  (v2 background runs have no default timeout and would otherwise be
  force-killed).

## 0.5.1-v2 (2025-08-18)

Synchronized with the v1 branch (`0.5.1`): the classifier and auditor sources are byte-identical to v1.

### Fixed
- **Security (`rmdir` forced-recursive hole)**: `rmdir` is `Remove-Item`'s alias on PowerShell/cmd, so `rmdir -Recurse -Force x`, `rmdir -R -F x`, and `rmdir /s /q x` are forced recursive deletes. 0.5.0 treated any `^rmdir` as known-safe in LOOSE, letting them through as `ALLOW`. Now only the plain empty-directory form is provably safe; recursive flag forms fall through to destructive-delete rules (`DENY`).
- **LOOSE false positives restored**: `Remove-Item -LiteralPath ".\dist" -Recurse -Force` and `rm -Force -Recurse .\node_modules` (in-worktree disposable cleanup) are `ALLOW` again.

### Chores
- Removed the local test script (`native/windows-bash-supervisor/test/integration.mjs`) and dropped it from the npm `files` list; removed build caches (`target/debug`, `__pycache__`). The compiled release supervisor binaries (`target/release/*.exe`) remain shipped in the npm tarball.
- Version `0.5.0-v2` → `0.5.1-v2` (the `-v2` marker keeps the v2 build distinct from v1 on npm under the shared package name).

## 0.5.0-v2 (2025-08-18)

v2 plugin API port (`{ id, setup(ctx) }` promise plugin) with the M1–M4 security hardening: path safety layer (`src/security/paths.ts`), provably-safe guard, verified area assertions, M2 destructive rules, TOCTOU fingerprint verification, hardened dynamic reviewer, M3 whitelist, M4 cache-key normalization. Details in `security-classifier-fix-plan.md` / `security-classifier-exploits.md`.
