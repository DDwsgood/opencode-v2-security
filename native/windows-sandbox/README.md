# Windows LPAC sandbox

> **Validated on real Windows for PowerShell 7 (`pwsh.exe`) and `cmd.exe`.**
> The native matrix passed file/read-only/network denial, atomic saves,
> concurrent grants, process-tree cancellation, and ACL/scratch restoration.
> Nine Windows host-integration checks also passed, including an explicitly
> authorized outbound connection and background permission revocation.
> Git Bash/MSYS/Cygwin and Windows PowerShell 5.1 are explicitly refused:
> the former needs incompatible global named objects; the latter stalled in
> legacy CLR/ALPC startup. Neither is silently run outside the sandbox.
> Host tests inject reviewer answers; live OpenCode + SystemOne end-to-end
> deployment has not been validated.

`opencode-windows-sandbox.exe` is a native Windows security boundary, not the
older Bash process supervisor. It launches supported programs in a unique
Less-Privileged AppContainer (LPAC), with an atomic, non-breakaway, kill-on-close
Job assignment. The plugin reviews the launch before calling it; this backend
does **not** claim Linux-style syscall observation or runtime approvals.

## Build and Windows integration

Use an installed Windows Rust MSVC toolchain and Windows SDK:

```powershell
cargo build --release --manifest-path native/windows-sandbox/Cargo.toml
cargo test --manifest-path native/windows-sandbox/Cargo.toml --bin opencode-windows-sandbox
./native/windows-sandbox/integration.ps1 -Helper ./native/windows-sandbox/target/release/opencode-windows-sandbox.exe
```

Copy the release executable to `bin/opencode-windows-sandbox.exe`. For WSL
development, copy this project into a dedicated Windows-local build directory
first; the integration script creates and removes its own random fixture tree.
Its standalone Rust payload is built with `rustc`, not shipped in the package.

The integration matrix exercises actual Windows access checks: workspace
writes, replacement/rename/deletion; external read/write denial; descendant denyRead/denyWrite; readonly
workspace with writable private scratch; IPv4/IPv6 Internet and loopback
network denial; environment scrubbing; cmd/PowerShell 7 command arguments,
output and exit status; explicit unsupported-shell refusal; concurrent grants;
descendant termination on normal exit, launcher death, and partial cancellation
frames; and ACL/scratch cleanup. A passing TypeScript
test or successful cross-compilation is not a substitute for this matrix.

The delivered x64 executable was built with a task-isolated Windows GNU Rust
toolchain. It imports only Windows-provided DLLs; no GNU runtime sidecars are
needed. For a GNU rebuild, install Rust's `llvm-tools` component, copy its
`llvm-ar.exe` to a build-local `llvm-dlltool.exe` (the same executable includes
that frontend), and set `RUSTFLAGS="-C dlltool=<absolute llvm-dlltool.exe path>"`.
This avoids the bundled GNU dlltool's dependency on a separate assembler.

Windows host checks are in `tests/windows-host-integration.test.ts`. Set
`OPENCODE_WINDOWS_RUN_ACCEPTANCE=1` to run the native-dependent cases, and
optionally `OPENCODE_WINDOWS_TEST_ENDPOINT=tcp://<authorized-host>:<port>` for
the positive network case. These variables configure tests, not the plugin.

## Host contract

`--probe` emits one JSON object:

```json
{"version":1,"backend":"windows-lpac","available":true}
```

An unavailable result contains `available:false` and a diagnostic `reason`.
An explicit `contractFailure:true` is a hard isolation-contract refusal, never
an availability failure that `failPolicy` may relax.
The probe creates a real LPAC process and checks its identity before running a
minimal system command. It is a platform prerequisite check, **not** a promise
that arbitrary later paths, shells, ACLs, or commands will work.

For a launch, the host sets:

* `OPENCODE_REAL_SHELL`: the absolute real executable, never this helper.
* `OPENCODE_WINDOWS_SANDBOX_POLICY`: a versioned JSON object with `version:1`,
  `profile` (`ro` or `workspace`), `cwd`, `scratch`, `readRoots`, `writeRoots`,
  `denyRead`, `denyWrite`, and boolean `network`.
* Optional **paired** `OPENCODE_WINDOWS_CONTROL_PIPE` and
  `OPENCODE_WINDOWS_CONTROL_TOKEN`. The pipe must start with
  `\\.\pipe\opencode-security-`; the token is 32–256 ASCII letters, digits,
  underscores or hyphens. This is for host revocation, not syscall review.

`src/windows-sandbox.ts` validates and encodes the policy. The helper validates
it independently and does not trust the TypeScript validation as a boundary.
`full`/Bypass must not invoke the helper. `rw` is encoded as the same root-limited
`workspace` policy, not host-wide write access.

The current host selects shell arguments *after* the `create.before` hook.
Consequently, generic `-c command` is translated based on the real executable:

* `pwsh.exe`: `-NoLogo -NoProfile -NonInteractive -Command`.
* `cmd.exe`: `/d /s /c`, with cmd-native command-string quoting.
* Legacy `powershell.exe` and MSYS/Cygwin shell names are refused, including
  explicit non-`-c` argument vectors.

Other explicit argument vectors are passed through. An unknown executable with
generic `-c` is refused; there is no speculative fallback to another shell.
Stdin is `NUL`; stdout/stderr and the process exit code are relayed. Setup,
cancellation and cleanup failures exit 125. A partly executed command is never
retried or replayed without isolation.

## Isolation and file authority

* Each call uses a fresh random AppContainer moniker and SID. The child token
  is checked for the requested AppContainer SID and absence of enabled
  `ALL APPLICATION PACKAGES` before the suspended child is resumed.
  It also carries a distinct per-call `S-1-9-...` restricting SID, checked before
  resume. `CreateRestrictedToken` removes privileges and adds a conventional
  access-check layer; `CreateProcessAsUserW` combines it with LPAC, not with a
  different user or SYSTEM identity. Package grants still bound LPAC access.
* `registryRead` and `lpacInstrumentation` are granted for runtime startup.
  The latter matches the existing ETW provider's baseline event-registration
  rights; logging is not disabled and host ETW ACLs are not changed.
  There is no COM/device
  capability, user credential forwarding, or SYSTEM payload. A SYSTEM launcher
  is explicitly refused. Windows' own LPAC-readable OS resources remain the
  platform baseline; this is not a complete private filesystem image.
* Network-off has **no network capabilities**. Network-on adds
  `internetClient` and `privateNetworkClientServer`. No firewall rules, loopback
  exemptions, services or drivers are installed. Windows can still deny loopback
  even with network-on; the helper never installs an exemption to weaken that.
* Existing policy paths are resolved through handles, including short-name
  aliases. UNC/device/ADS paths, ambiguous components and reparse points are
  rejected. Multiply-linked files are permitted only in read-only grants, never
  writable grants. No parent widening for nonexistent
  targets is performed. All policy roots must already exist.
* ACL changes add permissions only for this call's SID—never Everyone or
  `ALL APPLICATION PACKAGES`. Existing ACEs, ownership and integrity labels are
  preserved. The caller must already be able to read and change the relevant
  DACLs; no ownership takeover or silent elevation occurs.
* Every existing descendant is inspected and granted individually.
  `NtSetSecurityObject` updates only the checked object's DACL, without
  `SetSecurityInfo`'s descendant walk. Protected/unprotected state and existing
  ACE inheritance flags are retained. Windows may clear the informational
  `SE_DACL_AUTO_INHERITED` descriptor bit when a DACL is rewritten; exact SDDL
  equality is not promised on every runtime installation. Handles hold ACL
  rights, not data-write or maximum access, so
  executable loading and ordinary atomic saves do not conflict with supervision.
* denyRead denies all access; denyWrite denies mutation through the ordinary
  restricting SID, never by relying on package-SID DENY ACEs. A writable ancestor
  cannot override an explicit deny on a descendant. Writable objects receive
  DELETE for ordinary replacement, rename and deletion, but their parents never
  receive FILE_DELETE_CHILD. WRITE_DAC and WRITE_OWNER stay denied. Boundary
  roots and protected ancestors are pinned; temporary setup pins prevent path
  swaps during traversal and are released before the payload starts.
* New files/directories inherit the call's limited ACEs. Readonly clears every
  persistent write root. Each call receives a newly created private scratch
  child beneath `scratch`; this is allowed even when its parent workspace is
  readonly. Windows rewrites AppContainer TEMP below private LOCALAPPDATA, so
  the matching `Packages/<moniker>/AC/Temp` path is created inside that child.
  Existing user TEMP contents are not implicitly granted.
* The selected non-OS shell installation receives read access only unless
  it lies inside an independently approved write root. Windows/System32/WinSxS ACLs are
  never modified to run OS shells; their existing LPAC permissions apply.
  Persistent writes inside the Windows installation are refused.
* Write grants cannot overlap the helper's control-state directory. Read
  traversal skips it, and direct read grants inside it are refused. Native host
  file tools also protect this directory from writes. A tree is
  limited to 100,000 inspected objects. Inaccessible, absent or unsupported deny
  targets fail closed rather than being silently discarded.

## Environment, handles and lifecycle

The payload receives a newly constructed environment: Windows OS paths, a
minimal PATH/PATHEXT, private HOME/USERPROFILE/APPDATA/LOCALAPPDATA/TEMP/TMP and
telemetry/diagnostic-off settings. The inherited service environment is not
filtered by secret-name heuristics—it is discarded. Authentication must be
established explicitly inside the reviewed command or through explicitly
authorized files. Neither the real-shell variable nor any control prefix,
token, pipe or host credential is inherited.
Non-OS tools may need explicit absolute paths and approved read targets; this
is not a clone of the user's entire environment or a universally compatible VM.

The process attribute handle list contains only NUL stdin and dedicated output
pipe writers. Host handles, Job handles, token handles, ACL handles, journal
handles and cancellation handles never enter the payload. The Job is assigned
atomically at process creation, has no breakaway flags, and retains
kill-on-close on **normal completion as well as cancellation**. Cleanup waits
for the Job's active process count to reach zero before revoking file authority.

A thin launcher owns a private liveness pipe. A separate per-call cleanup
worker owns the Job and ACL handles; launcher termination closes the pipe and
cancels the worker's payload. The worker is started with breakaway from any
outer host Job; if that is not permitted, setup refuses. This is not a resident
service. Killing the worker itself still closes the payload Job, but requires
the durable recovery path for ACL/profile cleanup.

The optional host control connection sends newline-delimited JSON:

```text
{"version":1,"type":"ready","token":"<host token>"}
{"version":1,"type":"exit","token":"<host token>","exit":0}
```

There are no valid host-to-helper messages other than cancellation. Any input
byte—including a partial frame—EOF or read error therefore cancels immediately.
An exit frame is sent only after cleanup. The server must authenticate `ready`
and retain the pipe for background calls until completion/revocation. The
payload cannot access the host pipe under its ungranted LPAC identity.
The control watcher avoids a permanently blocking read on a duplicated
synchronous pipe handle, and consumes a queued cancellation signal so a sender
flushing its pipe cannot deadlock. Servers must keep reading exit frames while
waiting for the helper to exit. Windows signed 32-bit process exit status is
preserved by the host broker.

The protected per-user control directory is
`%LOCALAPPDATA%\opencode-windows-sandbox-state`. Before granting ACLs, the worker
flushes and atomically publishes a journal containing its unique identity,
process ID, granted roots and private scratch path—no commands or secrets.
Normal/error/cancellation cleanup removes both per-call SIDs' ACEs, including
inherited ACEs on newly created descendants, then removes private scratch and
the AppContainer profile. Updates are serialized by a named ACL mutex so
concurrent calls do not overwrite each other's grants.
Revocation explicitly deletes matching ALLOW and DENY ACEs: relying only on
`SetEntriesInAcl(REVOKE_ACCESS)` left DENY ACEs behind in the live diagnostic.

After abrupt worker termination or machine failure, the next probe/launch
recovers journals whose process is no longer alive. Unique SIDs are never reused.
There is **no claim of instantaneous ACL cleanup after power loss or killing
all cleanup processes**. A failed cleanup retains its journal and reports
failure. The helper does not roll back completed file-content writes.

### Earlier experimental ACL cleanup

Before the explicit DENY-revocation fix, failed experimental versions left
orphan DENY entries on the PowerShell/Git runtime trees. They were removed
with original descriptor backups retained. The one-off maintenance script
(not shipped in this plugin) initially allocated an x86-sized absolute security
descriptor on x64 and crashed; after correcting its size, a complete comparison
found no changes to non-component ACEs or ownership. The OS cleared some
`SE_DACL_AUTO_INHERITED` information bits; ACE inheritance flags and current
effective permissions were preserved. Future parent-inheritance updates were
not separately tested as part of that maintenance step.

## Focused denyRead diagnosis

The live diagnostic showed correct path matching and an installed explicit
`DENY FILE_ALL_ACCESS` for the package SID before its inherited allow ACE, on
both `secret` and `secret\secret.txt`. The actual LPAC payload still read the
file. Reordering that DACL would therefore not fix the failure.

The candidate now keeps LPAC grants on the package SID and uses a separate
ordinary restricting SID for denials. Both ACL identities are derived from the
same per-call identity and removed during normal cleanup and journal recovery.
Supplying the package SID itself to `CreateRestrictedToken` was rejected with
Win32 87; the ordinary SID plus the caller's enabled groups succeeded. The
caller user SID is deliberately not copied into the restricting list, so owner
rights do not become an implicit permission grant. The scratch-path, ETW
startup, ACL-revocation and control-pipe defects found afterward were also
resolved before the supported native and host-integration matrices passed.

## References

* [Microsoft: AppContainer isolation](https://learn.microsoft.com/en-us/windows/win32/secauthz/appcontainer-isolation)
* [Microsoft: launching AppContainer and LPAC](https://learn.microsoft.com/en-us/windows/win32/secauthz/implementing-an-appcontainer)
* [Microsoft: process attributes and atomic Job lists](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-updateprocthreadattribute)
* [Microsoft: SetSecurityInfo propagation rules](https://learn.microsoft.com/en-us/windows/win32/api/aclapi/nf-aclapi-setsecurityinfo)
