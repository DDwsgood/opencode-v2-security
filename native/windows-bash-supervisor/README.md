# Windows Bash supervisor

This component places the real MSYS2 Bash process in a Windows Job Object and
isolates its stdout/stderr behind private relay pipes. The plugin activates the
release build as OpenCode's configured Windows shell when it exists.

The supervisor preserves the original Bash argument vector (`-c`, `-lc`, and
other arguments are passed through unchanged). The real Bash and
its descendants never inherit OpenCode's stdout/stderr handles. Normal shell
exit gets a 300 ms bounded drain window; forced supervisor termination closes a
`JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE` handle and terminates the job tree.

## Build and test

```bash
cargo build --release --manifest-path native/windows-bash-supervisor/Cargo.toml
node native/windows-bash-supervisor/test/integration.mjs \
  native/windows-bash-supervisor/target/release/bash.exe
```

`OPENCODE_REAL_BASH` is mandatory: the plugin injects the configured real
shell through the `shell.env` hook as this variable. It is not an override of
a default, and there is intentionally no `C:\msys64\usr\bin\bash.exe`
fallback — the supervisor never silently targets the wrong shell. If
`OPENCODE_REAL_BASH` is missing, the supervisor exits with status **125**.

The integration test checks direct argument and `shell:` invocation,
exit-code/output passthrough, concurrent large stdout/stderr, reproduces an
inherited-pipe delay against direct Bash, verifies that the supervisor returns
without waiting for the background writer, confirms that normal detached
children survive, and force-kills the supervisor to verify Job Object tree
cleanup.

This is a one-shot process: one supervisor instance runs one Bash invocation.
Its stdin is intentionally `NUL`, matching OpenCode's non-interactive Bash
tool. There is an unavoidable small window between suspended process creation
and Job assignment; assignment failure explicitly terminates the suspended
process.

Invocations with no arguments or only interactive/login flags bypass the relay
and inherit the caller's PTY stdio, preserving OpenCode's integrated terminal.
