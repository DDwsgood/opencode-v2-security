#!/usr/bin/env python3
"""Native-behavior tests for opencode-boundary-watch.

Each scenario boots a fake broker (AF_UNIX NDJSON), runs the helper with a
harmless fixture script under /tmp/opencode/bw-test, and asserts on the
events seen / exit code / filesystem side effects.

No real credentials, no dangerous commands: all fixtures are synthetic.
"""

import errno
import json
import os
import re
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
BIN = os.path.normpath(os.path.join(HERE, "..", "..", "bin",
                                    "opencode-boundary-watch"))
BASE = "/tmp/opencode/bw-test"
TOKEN = "ab" * 32  # 64 hex chars
SH = "/bin/sh"


class Broker(threading.Thread):
    """One-shot NDJSON broker. policy(event, idx) -> 'allow'|'continue'|
    'deny'|'eof' (close without replying)|'allow_eof' (reply then close
    after a beat)|raw dict. close_after_accept drops the conn right away."""

    def __init__(self, sock_path, policy, close_after_accept=False,
                 eof_delay=0.4, idle_control=None):
        super().__init__(daemon=True)
        self.sock_path = sock_path
        self.policy = policy
        self.close_after_accept = close_after_accept
        self.eof_delay = eof_delay
        self.idle_control = idle_control
        self.events = []
        self.replies = []
        self.exits = []  # terminal {"type":"exit"} frames (no reply)
        self._srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        if os.path.exists(sock_path):
            os.unlink(sock_path)
        self._srv.bind(sock_path)
        self._srv.listen(1)
        self._srv.settimeout(60)

    def run(self):
        try:
            conn, _ = self._srv.accept()
            self._conn = conn
            conn.settimeout(60)
            if self.close_after_accept:
                time.sleep(self.eof_delay)
                conn.close()
                return
            if self.idle_control is not None:
                time.sleep(self.eof_delay)
                for fragment in self.idle_control:
                    conn.sendall(fragment)
                    time.sleep(0.05)
            buf = b""
            while True:
                try:
                    chunk = conn.recv(65536)
                except (socket.timeout, ConnectionResetError):
                    return
                if not chunk:
                    return
                buf += chunk
                while b"\n" in buf:
                    line, buf = buf.split(b"\n", 1)
                    if not line.strip():
                        continue
                    try:
                        ev = json.loads(line)
                    except json.JSONDecodeError:
                        return
                    if ev.get("type") == "exit":
                        # Terminal frame: not a boundary event, no reply.
                        self.exits.append(ev)
                        continue
                    self.events.append(ev)
                    action = self.policy(ev, len(self.events) - 1)
                    if action == "eof":
                        conn.close()
                        return
                    if action == "allow_eof":
                        reply = {"version": 1, "eventID": ev["eventID"],
                                 "action": "allow"}
                        self.replies.append(reply)
                        conn.sendall(json.dumps(reply).encode() + b"\n")
                        time.sleep(self.eof_delay)
                        conn.close()
                        return
                    if isinstance(action, dict):
                        reply = action
                    else:
                        reply = {"version": 1, "eventID": ev["eventID"],
                                 "action": action}
                    self.replies.append(reply)
                    try:
                        conn.sendall(json.dumps(reply).encode() + b"\n")
                    except OSError:
                        return
        except Exception:
            return
        finally:
            self._srv.close()

    def close(self):
        """Drop BOTH the listener and any live accepted connection — the
        helper must see a real EOF, not just an unbound path. shutdown()
        first: close() alone does NOT send FIN while another thread is
        blocked in recv() — the in-flight syscall keeps the socket alive
        until it returns (up to the 60s recv timeout)."""
        try:
            self._srv.close()
        except OSError:
            pass
        conn = getattr(self, "_conn", None)
        if conn is not None:
            try:
                conn.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            try:
                conn.close()
            except OSError:
                pass


def run_watch(script, policy, extra_args=None, timeout=30, shell=SH,
              root=None, sock_name="broker.sock", env=None, **broker_kw):
    """Run the helper under a fake broker. Returns (proc, broker)."""
    root = root or WORK
    sock_path = os.path.join(TMP, sock_name)
    broker = Broker(sock_path, policy, **broker_kw)
    broker.start()
    args = [BIN, "--broker", sock_path, "--token", TOKEN,
            "--root", root]
    args += extra_args or []
    args += ["--", shell, "-c", script]
    proc = subprocess.Popen(args, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE,
                            env=env or dict(os.environ, PYTHONDONTWRITEBYTECODE="1"))
    return proc, broker


def wait_proc(proc, timeout=40):
    try:
        out, err = proc.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        proc.kill()
        out, err = proc.communicate()
        raise AssertionError(f"helper timed out; stderr={err!r}")
    return proc.returncode, out.decode(), err.decode()


def make_fixture(name, content, mode=0o644):
    path = os.path.join(WORK, name)
    with open(path, "w") as f:
        f.write(content)
    os.chmod(path, mode)
    return path


def fresh_tree():
    subprocess.run(["rm", "-rf", WORK, OUT], check=False)
    os.makedirs(WORK, exist_ok=True)
    os.makedirs(OUT, exist_ok=True)


INT80_EXE = None


def build_int80_fixture():
    """A 64-bit binary that issues one i386 syscall via int $0x80."""
    global INT80_EXE
    if INT80_EXE and os.path.exists(INT80_EXE):
        return INT80_EXE
    src = os.path.join(TMP, "int80.c")
    exe = os.path.join(TMP, "int80")
    with open(src, "w") as f:
        f.write(r"""
static const char msg[] = "i386-write\n";
int main(void) {
    __asm__ volatile("int $0x80"
                     :: "a"(4), "b"(1), "c"(msg), "d"(sizeof(msg) - 1)
                     : "memory");
    return 0;
}
""")
    subprocess.run(["gcc", "-static", "-O2", "-o", exe, src], check=True)
    INT80_EXE = exe
    return exe


CUT_EXE = None


def build_cut_fixture():
    """Build the CLONE_UNTRACED test binary once."""
    global CUT_EXE
    if CUT_EXE and os.path.exists(CUT_EXE):
        return CUT_EXE
    src = os.path.join(TMP, "cut.c")
    exe = os.path.join(TMP, "cut")
    with open(src, "w") as f:
        f.write(r"""
#define _GNU_SOURCE
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>
static int fn(void *a) { (void)a; _exit(0); }
static char stack[1 << 20];
int main(void) {
    pid_t p = clone(fn, stack + sizeof(stack),
                    CLONE_UNTRACED | SIGCHLD, 0);
    if (p < 0) { printf("errno=%d %s\n", errno, strerror(errno)); return 2; }
    waitpid(p, 0, 0);
    puts("escaped");
    return 3;
}
""")
    subprocess.run(["gcc", "-O2", "-o", exe, src], check=True)
    CUT_EXE = exe
    return exe


FDHOLD_EXE = None


def build_fdhold_fixture():
    """fd-table coordination fixture, real threads (no GIL). Every mode
    relies on the same deterministic anchor: the rebind/alloc thread
    reaches its syscall while the consumer's post-gate drain sweep is
    collecting pending stops, so the entry stop lands in the deferred
    queue and is decided while the in-flight fd record is provably live.

    Modes:
      rebind  wr writes PAYLOAD to a pipe wfd (n-kind record); sibling
              dup2(file, wfd) must be held until the write exits.
      close   same consumer; sibling close(wfd) held likewise.
      alloc   fd 10 stays CLOSED; consumer write(10) EBADF (c-kind
              record); sibling open() must be held, then takes slot 10.
      range   consumers write(10)/write(11) EBADF; sibling
              close_range(10,11) must stay held until BOTH consumers'
              records clear (release retests the full recorded range).
    """
    global FDHOLD_EXE
    if FDHOLD_EXE and os.path.exists(FDHOLD_EXE):
        return FDHOLD_EXE
    src = os.path.join(TMP, "fdhold.c")
    exe = os.path.join(TMP, "fdhold")
    with open(src, "w") as f:
        f.write(r"""
#define _GNU_SOURCE
#include <fcntl.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <time.h>
static int wfd, target_fd;
static const char *outpath;
static double t0;
static volatile int armed;
static double now(void) {
    struct timespec a;
    clock_gettime(CLOCK_MONOTONIC, &a);
    return a.tv_sec + a.tv_nsec / 1e9 - t0;
}
/* Absolute-time wait, anchored at round_reset(): a sibling's own startup
 * stops may be deferred by the consumer's drain, which would silently
 * shift a relative busy() later — absolute anchoring keeps the syscall
 * inside the drain window regardless. Threads are created BEFORE the
 * round is armed so their startup stops never consume the window. */
static void at(double s) { while (!armed || now() < s) { } }
static void round_reset(void) {
    struct timespec a;
    clock_gettime(CLOCK_MONOTONIC, &a);
    t0 = a.tv_sec + a.tv_nsec / 1e9;
    armed = 1;
}
/* Each round is a coin flip the sibling side cannot control from user
 * space: either its entry stop is pending when the consumer's pause/drain
 * sweep runs (the stop is deferred and decided while the in-flight fd
 * record is provably live -> HELD), or it is processed first (semantically
 * fine — it simply ran before the gate). Rounds repeat so the test sees
 * the HELD branch at least once; the payload prints the OBSERVABLE
 * outcome of each round and the helper's BW_DEBUG HELD marker supplies
 * the mechanism evidence. */
static void *wr_pipe(void *a) {
    (void)a; while (!armed) { }
    (void)!write(wfd, "PAYLOAD", 7); return NULL;
}
static void *rb_dup2(void *a) {
    (void)a; at(0.30); dup2(target_fd, wfd); return NULL;
}
static void *cl_close(void *a) {
    (void)a; at(0.30); close(wfd); return NULL;
}
static void *wr_cA(void *a) {
    (void)a; while (!armed) { }
    (void)!write(10, "x", 1); return NULL;   /* EBADF: 'c' rec */
}
static void *wr_cB(void *a) {
    /* Late enough that wrA's post-gate drain sweeps this write's entry
     * stop into the deferred queue: its record is then live when cr's
     * held decision and the first release retest run. */
    (void)a; at(0.35); (void)!write(11, "x", 1); return NULL;
}
static void *op_open(void *a) {
    (void)a; at(0.30);
    int n = open(outpath, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    printf("fd=%d\n", n);
    return NULL;
}
static void *cr_rng(void *a) {
    (void)a; at(0.33);
    syscall(436, 10, 11, 0);   /* close_range */
    printf("ranged\n");
    return NULL;
}
static void drain_pipe(int r) {
    static char buf[4096];
    ssize_t tot = 0, rd;
    /* the wfd slot was rebound/closed: no writers left, drains to EOF */
    while ((rd = read(r, buf + tot, sizeof(buf) - tot)) > 0) tot += rd;
    printf("%s\n", (tot > 0 && memmem(buf, tot, "PAYLOAD", 7))
                   ? "PIPE" : "MISSING");
}
int main(int argc, char **argv) {
    if (argc < 3) return 2;
    outpath = argv[2];
    if (!strcmp(argv[1], "rebind") || !strcmp(argv[1], "close")) {
        int rebind = !strcmp(argv[1], "rebind");
        for (int i = 0; i < 8; i++) {
            int p[2];
            if (pipe(p)) return 2;
            wfd = p[1];
            target_fd = open(outpath,
                             O_WRONLY | O_CREAT | O_TRUNC, 0644);
            pthread_t a, b;
            armed = 0;
            pthread_create(&a, NULL, wr_pipe, NULL);
            pthread_create(&b, NULL, rebind ? rb_dup2 : cl_close, NULL);
            round_reset();
            pthread_join(a, NULL);
            pthread_join(b, NULL);
            drain_pipe(p[0]);
            close(p[0]);
        }
        printf("rounds-done\n");
        fflush(stdout);
        if (rebind)
            (void)!write(wfd, "AFTER", 5);  /* last slot -> file */
        else
            printf("%s\n", write(wfd, "y", 1) < 0 ? "BADFD" : "LEAK");
        fflush(stdout);
        return 0;
    }
    if (!strcmp(argv[1], "alloc")) {
        for (int i = 3; i < 10; i++) (void)!dup2(0, i);
        for (int i = 0; i < 8; i++) {
            pthread_t a, b;
            armed = 0;
            pthread_create(&a, NULL, wr_cA, NULL);
            pthread_create(&b, NULL, op_open, NULL);
            round_reset();
            pthread_join(a, NULL);
            pthread_join(b, NULL);
            close(10);        /* reset the slot for the next round */
        }
        (void)!write(10, "y", 1);          /* slot 10 -> the new file */
        printf("done\n");
        fflush(stdout);
        return 0;
    }
    if (!strcmp(argv[1], "range")) {
        for (int i = 3; i < 10; i++) (void)!dup2(0, i);
        for (int i = 0; i < 8; i++) {
            pthread_t a, b, c;
            /* cr first: a create issued later can itself be deferred by a
             * consumer's drain and push the sibling's birth past the
             * window. All three exist before armed fires, so every
             * at() deadline is measured from the same instant. */
            armed = 0;
            pthread_create(&c, NULL, cr_rng, NULL);
            pthread_create(&b, NULL, wr_cB, NULL);
            pthread_create(&a, NULL, wr_cA, NULL);
            round_reset();
            pthread_join(a, NULL);
            pthread_join(b, NULL);
            pthread_join(c, NULL);
        }
        printf("done\n");
        fflush(stdout);
        return 0;
    }
    return 2;
}
""")
    subprocess.run(["gcc", "-O2", "-pthread", "-o", exe, src], check=True)
    FDHOLD_EXE = exe
    return exe


SHARE_EXE = None


def build_shareclone_fixture():
    """clone(CLONE_FILES|SIGCHLD): a NEW tgid that still shares the fd
    table. The child rebinds a pipe fd while the parent thread's write on
    it is in flight; signals ride a second pipe (separate address space —
    no shared memory)."""
    global SHARE_EXE
    if SHARE_EXE and os.path.exists(SHARE_EXE):
        return SHARE_EXE
    src = os.path.join(TMP, "shareclone.c")
    exe = os.path.join(TMP, "shareclone")
    with open(src, "w") as f:
        f.write(r"""
#define _GNU_SOURCE
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <pthread.h>
#include <sys/wait.h>
#include <time.h>
static int pr, pw, target_fd;
static char cstack[1 << 20];
static void busy(double s) {
    struct timespec a, b;
    clock_gettime(CLOCK_MONOTONIC, &a);
    double e = a.tv_sec + a.tv_nsec / 1e9 + s;
    for (;;) { clock_gettime(CLOCK_MONOTONIC, &b);
               if (b.tv_sec + b.tv_nsec / 1e9 >= e) break; }
}
static int rebind_child(void *a) {
    (void)a;
    busy(0.15);
    /* The parent's write(pw) is in its stretched gate window now: this
     * rebind's entry stop is already queued, so it is HELD until the
     * write exits — the same fd NUMBER in a DIFFERENT tgid (shared fd
     * table) is what files_id tracks. */
    dup2(target_fd, pw);
    (void)!write(pw, "CHILD", 5);     /* via the shared slot -> the file */
    _exit(0);
}
static void *writer(void *a) {
    (void)a;
    (void)!write(pw, "PAYLOAD", 7);   /* gate observes pipe -> 'n' kind */
    return NULL;
}
int main(int argc, char **argv) {
    int p[2];
    pipe(p);
    pr = p[0]; pw = p[1];
    target_fd = open(argv[1], O_WRONLY | O_CREAT | O_TRUNC, 0644);
    pid_t c = clone(rebind_child, cstack + sizeof cstack,
                    CLONE_FILES | SIGCHLD, NULL);
    pthread_t th;
    pthread_create(&th, NULL, writer, NULL);
    pthread_join(th, NULL);           /* write exits -> dup2 released */
    waitpid(c, NULL, 0);
    static char rest[4096];
    ssize_t tot = 0, rd;
    /* dup2 rebound the w slot, so the pipe has no writers: drains to
     * EOF — and PAYLOAD must be in it (the write went to the object the
     * gate saw). */
    while ((rd = read(pr, rest + tot, sizeof(rest) - tot)) > 0) tot += rd;
    printf("%s\n", (tot > 0 && memmem(rest, tot, "PAYLOAD", 7))
                   ? "PIPE" : "MISSING");
    fflush(stdout);
    (void)!write(pw, "AFTER", 5);     /* slot now -> file: boundary event */
    close(pw);
    return 0;
}
""")
    subprocess.run(["gcc", "-O2", "-pthread", "-o", exe, src], check=True)
    SHARE_EXE = exe
    return exe


TMP = None
WORK = None
OUT = None


class BoundaryWatchTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        global TMP, WORK, OUT
        assert os.path.exists(BIN), f"missing helper binary: {BIN}"
        TMP = tempfile.mkdtemp(prefix="bw-", dir="/tmp/opencode")
        WORK = os.path.realpath(os.path.join(TMP, "work"))
        OUT = os.path.realpath(os.path.join(TMP, "outside"))
        fresh_tree()

    def setUp(self):
        fresh_tree()

    # 1. Read+write fully inside --root: zero events, exit 0.
    def test_01_in_root_rw_no_events(self):
        proc, br = run_watch("echo hi > $W/f.txt && cat $W/f.txt"
                             .replace("$W", WORK), lambda e, i: "deny")
        rc, out, err = wait_proc(proc)
        br.close()
        self.assertEqual(rc, 0, err)
        self.assertEqual(out.strip(), "hi")
        self.assertEqual(br.events, [])

    # 2. In-root write passes, out-of-root write => boundary event; broker
    #    deny => exit 126, the out file must NOT exist, the in file must.
    def test_02_out_write_denied(self):
        script = (f"echo a > {WORK}/a.txt && echo b > {OUT}/b.txt")
        proc, br = run_watch(script, lambda e, i: "deny")
        rc, out, err = wait_proc(proc)
        br.close()
        self.assertEqual(rc, 126, err)
        self.assertTrue(os.path.exists(f"{WORK}/a.txt"))
        self.assertFalse(os.path.exists(f"{OUT}/b.txt"))
        self.assertEqual(len(br.events), 1)
        ev = br.events[0]
        self.assertEqual(ev["kind"], "write")
        self.assertEqual(ev["token"], TOKEN)
        self.assertTrue(ev["targets"][0]["path"].startswith(OUT))

    # 3. Broker 'allow' detaches the whole tree: one event, the out-write
    #    then runs natively (file exists), exit 0.
    def test_03_allow_detaches_tree(self):
        script = (f"echo a > {WORK}/a.txt && echo b > {OUT}/b.txt && "
                  f"echo c > {OUT}/c.txt")
        proc, br = run_watch(script, lambda e, i: "allow")
        rc, out, err = wait_proc(proc)
        br.close()
        self.assertEqual(rc, 0, err)
        self.assertEqual(len(br.events), 1)  # only the first boundary
        self.assertTrue(os.path.exists(f"{OUT}/b.txt"))
        self.assertTrue(os.path.exists(f"{OUT}/c.txt"))

    # 4. Interpreter startup + log read: reads anywhere are not boundaries.
    def test_04_python_reads_no_events(self):
        log = make_fixture("app.log", "line1\n")
        proc, br = run_watch(
            f"python3 -c \"print(open('{log}').read().strip())\"",
            lambda e, i: "deny")
        rc, out, err = wait_proc(proc)
        br.close()
        self.assertEqual(rc, 0, err)
        self.assertEqual(out.strip(), "line1")
        self.assertEqual(br.events, [])

    # 5. Grandchild out-of-root write: tree is followed through fork/exec.
    def test_05_grandchild_out_write(self):
        script = f"{SH} -c 'echo g > {OUT}/g.txt'"
        proc, br = run_watch(script, lambda e, i: "deny")
        rc, out, err = wait_proc(proc)
        br.close()
        self.assertEqual(rc, 126, err)
        self.assertEqual(len(br.events), 1)
        self.assertFalse(os.path.exists(f"{OUT}/g.txt"))

    # 6a. Broker EOF mid-decision => tree killed, exit 126.
    def test_06a_broker_eof_kills(self):
        script = f"echo b > {OUT}/b.txt"
        proc, br = run_watch(script, lambda e, i: "eof")
        rc, out, err = wait_proc(proc)
        br.close()
        self.assertEqual(rc, 126, err)
        self.assertFalse(os.path.exists(f"{OUT}/b.txt"))

    # 6b. Tracer death: SIGKILL the watcher; PTRACE_O_EXITKILL must reap the
    #     payload tree (no silently-detached orphan).
    def test_06b_exitkill_on_tracer_death(self):
        script = "sleep 60"
        proc, br = run_watch(script, lambda e, i: "deny")
        time.sleep(1.0)  # let the payload exec+sleep
        # find the sleep pid
        sleeps = [p for p in os.listdir("/proc") if p.isdigit()]
        sleep_pids = []
        for p in sleeps:
            try:
                with open(f"/proc/{p}/comm") as f:
                    if f.read().strip() == "sleep":
                        with open(f"/proc/{p}/status") as s:
                            if "TracerPid:\t%d" % proc.pid in s.read():
                                sleep_pids.append(int(p))
            except OSError:
                pass
        self.assertTrue(sleep_pids, "payload sleep not found under tracer")
        os.kill(proc.pid, 9)
        proc.wait(timeout=10)
        time.sleep(0.5)
        for sp in sleep_pids:
            self.assertFalse(os.path.exists(f"/proc/{sp}"),
                             f"tracee {sp} survived tracer death")
        br.close()

    # 7. --readonly: even in-root writes are boundary events.
    def test_07_readonly_denies_write(self):
        proc, br = run_watch(f"echo x > {WORK}/r.txt",
                             lambda e, i: "deny",
                             extra_args=["--readonly"])
        rc, out, err = wait_proc(proc)
        br.close()
        self.assertEqual(rc, 126, err)
        self.assertEqual(len(br.events), 1)
        self.assertFalse(os.path.exists(f"{WORK}/r.txt"))

    # 8a. CLONE_UNTRACED clone attempt is an opaque full-approval event;
    #     'deny' kills before the clone runs. (It can only ever run detached,
    #     i.e. after an explicit whole-command 'allow'.)
    def test_08a_clone_untraced_event(self):
        exe = build_cut_fixture()
        proc, br = run_watch(exe, lambda e, i: "deny")
        rc, out, err = wait_proc(proc)
        br.close()
        self.assertEqual(rc, 126, err + out)
        self.assertEqual(len(br.events), 1)
        ev = br.events[0]
        self.assertEqual(ev["kind"], "opaque")
        self.assertTrue(ev["details"]["requiresFullApproval"])

    # 8a2. requiresFullApproval events refuse 'continue' helper-side:
    #      a broker that (incorrectly) answers continue must not short-circuit.
    def test_08a2_fullapproval_continue_denied(self):
        exe = build_cut_fixture()
        proc, br = run_watch(exe, lambda e, i: "continue")
        rc, out, err = wait_proc(proc)
        br.close()
        self.assertEqual(rc, 126, err + out)
        self.assertNotIn("escaped", out)

    # 8b. SCM_RIGHTS fd passing is an opaque sendfd boundary event.
    def test_08b_scm_rights_boundary(self):
        src = os.path.join(TMP, "scm.py")
        with open(src, "w") as f:
            f.write("""
import socket, array, os, sys
a, b = socket.socketpair()
fd = os.open("/dev/null", os.O_RDONLY)
a.sendmsg([b"x"], [(socket.SOL_SOCKET, socket.SCM_RIGHTS,
                    array.array("i", [fd]))])
print("sent")
""")
        proc, br = run_watch(f"python3 {src}", lambda e, i: "deny")
        rc, out, err = wait_proc(proc)
        br.close()
        self.assertEqual(rc, 126, err + out)
        self.assertEqual(len(br.events), 1)
        ev = br.events[0]
        self.assertEqual(ev["kind"], "opaque")
        self.assertEqual(ev["operation"], "sendfd")
        self.assertTrue(ev["details"]["requiresFullApproval"])

    # Credential-path guard: reading a .env / .ssh/id_* file is a read
    # boundary even though it lives inside the root.
    def test_09_credential_read_boundary(self):
        env = make_fixture(".env", "FAKE=test\n")
        proc, br = run_watch(f"cat {env}", lambda e, i: "deny")
        rc, out, err = wait_proc(proc)
        br.close()
        self.assertEqual(rc, 126, err)
        self.assertEqual(len(br.events), 1)
        self.assertEqual(br.events[0]["kind"], "read")

    # 10. Broker EOF while the payload is merely running (no boundary ever
    #     crossed): the tree must still be killed — lease revocation cancels
    #     in-flight commands.
    def test_10_broker_eof_while_idle_kills(self):
        proc, br = run_watch("sleep 30", lambda e, i: "deny",
                             close_after_accept=True, eof_delay=0.5)
        rc, out, err = wait_proc(proc)
        br.close()
        self.assertEqual(rc, 126, err)
        self.assertEqual(br.events, [])

    # 11. After 'allow' the tree detaches and runs natively, but supervision
    #     continues: a broker EOF mid-run kills the payload process group.
    def test_11_detached_broker_eof_kills_group(self):
        marker = os.path.join(OUT, "detached.txt")
        script = f"echo o > {OUT}/first.txt && sleep 30 && echo o > {marker}"
        proc, br = run_watch(script, lambda e, i: "allow_eof",
                             eof_delay=0.8)
        rc, out, err = wait_proc(proc)
        br.close()
        self.assertEqual(rc, 126, err)
        self.assertEqual(len(br.events), 1)
        self.assertTrue(os.path.exists(f"{OUT}/first.txt"))  # ran natively
        self.assertFalse(os.path.exists(marker))             # killed mid-run

    # 12. Detached 'allow' with broker staying up: command completes, its
    #     exit code is propagated, supervisor exits cleanly.
    def test_12_detached_completes(self):
        script = f"echo o > {OUT}/d.txt && exit 7"
        proc, br = run_watch(script, lambda e, i: "allow")
        rc, out, err = wait_proc(proc)
        br.close()
        self.assertEqual(rc, 7, err)
        self.assertTrue(os.path.exists(f"{OUT}/d.txt"))

    # Network: outbound connect is a boundary event.
    def test_13_connect_boundary(self):
        proc, br = run_watch(
            "python3 -c \"import socket;s=socket.socket();"
            "s.connect(('127.0.0.1',9))\"",
            lambda e, i: "deny")
        rc, out, err = wait_proc(proc)
        br.close()
        self.assertEqual(rc, 126, err)
        self.assertEqual(len(br.events), 1)
        self.assertEqual(br.events[0]["kind"], "network")

    # 14. NOFOLLOW-last: an in-root symlink that points OUTSIDE the root is
    #     itself an in-root entry — `rm` deletes the link without ever
    #     touching the referent, so this must produce NO boundary event.
    def test_14_unlink_outpointing_symlink_no_event(self):
        victim = os.path.join(OUT, "victim.txt")
        with open(victim, "w") as f:
            f.write("keep\n")
        link = os.path.join(WORK, "l.link")
        os.symlink(victim, link)
        proc, br = run_watch(f"rm {link}", lambda e, i: "deny")
        rc, out, err = wait_proc(proc)
        br.close()
        self.assertEqual(rc, 0, err)
        self.assertEqual(br.events, [])
        self.assertFalse(os.path.lexists(link))   # link removed
        self.assertTrue(os.path.exists(victim))   # referent untouched

    # 15. The mirror case: an entry named OUTSIDE the root is an out-of-root
    #     deletion even when it is a symlink pointing back inside. The event
    #     target must be the link path itself (nofollow), not the referent —
    #     resolving the leaf would silently pass this as an in-root op.
    def test_15_unlink_outside_link_boundary(self):
        target = make_fixture("inner.txt", "x\n")
        link = os.path.join(OUT, "l.link")
        os.symlink(target, link)
        proc, br = run_watch(f"rm {link}", lambda e, i: "deny")
        rc, out, err = wait_proc(proc)
        br.close()
        self.assertEqual(rc, 126, err)
        self.assertEqual(len(br.events), 1)
        ev = br.events[0]
        self.assertEqual(ev["operation"], "delete")
        self.assertEqual(ev["targets"][0]["path"], link)  # not the referent
        self.assertTrue(ev["targets"][0]["exists"])
        self.assertTrue(os.path.lexists(link))  # denied before unlink ran

    # 16. rename(2) carries BOTH endpoints in a single event: moving a file
    #     out of the root reports src AND dst.
    def test_16_rename_two_targets(self):
        src = os.path.join(WORK, "mv.txt")
        with open(src, "w") as f:
            f.write("x\n")
        dst = os.path.join(OUT, "mv.txt")
        proc, br = run_watch(f"mv {src} {dst}", lambda e, i: "deny")
        rc, out, err = wait_proc(proc)
        br.close()
        self.assertEqual(rc, 126, err)
        self.assertEqual(len(br.events), 1)
        ev = br.events[0]
        self.assertEqual(ev["operation"], "rename")
        paths = [t["path"] for t in ev["targets"]]
        self.assertIn(src, paths)
        self.assertIn(dst, paths)
        self.assertTrue(os.path.exists(src))    # vetoed before it ran
        self.assertFalse(os.path.exists(dst))

    # 17. hardlink: creating a link also modifies the source inode (nlink).
    #     A source outside the root is a write-boundary even though only a
    #     dest dentry gets created.
    def test_17_link_source_boundary(self):
        src = os.path.join(OUT, "s.txt")
        with open(src, "w") as f:
            f.write("x\n")
        dst = os.path.join(WORK, "l.txt")
        proc, br = run_watch(f"ln {src} {dst}", lambda e, i: "deny")
        rc, out, err = wait_proc(proc)
        br.close()
        self.assertEqual(rc, 126, err)
        self.assertEqual(len(br.events), 1)
        paths = [t["path"] for t in br.events[0]["targets"]]
        self.assertIn(src, paths)
        self.assertIn(dst, paths)
        self.assertFalse(os.path.exists(dst))

    # 18. Terminal frame: after the payload exits the broker receives
    #     {"type":"exit","exit":<real code>} exactly once (no reply).
    def test_18_exit_frame_reports_code(self):
        proc, br = run_watch("exit 42", lambda e, i: "deny")
        rc, out, err = wait_proc(proc)
        br.join(timeout=5)
        br.close()
        self.assertEqual(rc, 42, err)
        self.assertEqual(len(br.exits), 1)
        self.assertEqual(br.exits[0]["exit"], 42)
        self.assertEqual(br.exits[0]["token"], TOKEN)

    # 19. A deny-killed payload reports 128+SIGKILL (137) — a background
    #     caller must never see a fake exit 0 for a vetoed command.
    def test_19_denied_exit_frame_is_137(self):
        proc, br = run_watch(f"echo b > {OUT}/b.txt", lambda e, i: "deny")
        rc, out, err = wait_proc(proc)
        br.join(timeout=5)
        br.close()
        self.assertEqual(rc, 126, err)
        self.assertEqual(len(br.exits), 1)
        self.assertEqual(br.exits[0]["exit"], 137)

    # 20. Foreign ABI: int $0x80 under a 64-bit binary must not be gated
    #     against the x86_64 syscall table — it is an opaque exec-domain
    #     boundary (requiresFullApproval), not a silent miss.
    def test_20_foreign_abi_boundary(self):
        exe = build_int80_fixture()
        proc, br = run_watch(exe, lambda e, i: "deny")
        rc, out, err = wait_proc(proc)
        br.close()
        self.assertEqual(rc, 126, err + out)
        self.assertNotIn("i386-write", out)
        self.assertEqual(len(br.events), 1)
        ev = br.events[0]
        self.assertEqual(ev["kind"], "opaque")
        self.assertEqual(ev["operation"], "exec-domain")
        self.assertEqual(ev["syscall"], "foreign-abi")
        self.assertTrue(ev["details"]["requiresFullApproval"])
        self.assertEqual(ev["details"]["arch"], "0x40000003")

    # 21. Event context: details carry canonical cwd, executable and argv.
    def test_21_event_context_fields(self):
        proc, br = run_watch(f"echo b > {OUT}/b.txt", lambda e, i: "deny")
        rc, out, err = wait_proc(proc)
        br.close()
        self.assertEqual(rc, 126, err)
        self.assertEqual(len(br.events), 1)
        det = br.events[0]["details"]
        self.assertTrue(os.path.isabs(det["cwd"]))
        self.assertEqual(det["cwd"], os.path.realpath(os.getcwd()))
        self.assertTrue(det["executable"].startswith("/"))
        self.assertIn("/bin/sh", det["argv"][0])
        self.assertIn(f"echo b > {OUT}/b.txt", det["argv"])

    # 22. Exec events take argv from the execve vector itself, not the old
    #     image's /proc cmdline.
    def test_22_exec_event_argv(self):
        # "MZ" magic -> interop exec boundary, whatever the file is named.
        exe = os.path.join(OUT, "fake-pe")
        with open(exe, "wb") as f:
            f.write(b"MZ" + b"\0" * 62)
        os.chmod(exe, 0o755)
        proc, br = run_watch(f"{exe} hello-arg", lambda e, i: "deny")
        rc, out, err = wait_proc(proc)
        br.close()
        self.assertEqual(rc, 126, err)
        self.assertEqual(len(br.events), 1)
        self.assertEqual(br.events[0]["kind"], "interop")
        det = br.events[0]["details"]
        self.assertEqual(det["argv"][0], exe)
        self.assertEqual(det["argv"][1], "hello-arg")

    # 22b. An ELF image merely NAMED *.exe (bun.exe, opencode.exe) runs
    #      natively: no interop boundary.
    def test_22b_elf_named_exe_is_not_interop(self):
        exe = os.path.join(OUT, "tool.exe")
        subprocess.run(["cp", "/bin/true", exe], check=True)
        proc, br = run_watch(f"{exe}", lambda e, i: "deny")
        rc, out, err = wait_proc(proc)
        br.close()
        self.assertEqual(rc, 0, err)
        self.assertEqual(br.events, [])

    # 23. A setsid'd grandchild leaves the payload process GROUP but stays a
    #     tracee: a deny during the traced phase must still reap it via the
    #     per-tgid killpg fallback (killpg(root) alone would miss it).
    def test_23_setsid_escape_killed_on_deny(self):
        pidfile = f"{WORK}/sid.pid"
        script = (f"setsid sleep 30 & echo $! > {pidfile}; "
                  f"sleep 1; echo x > {OUT}/trip.txt")
        proc, br = run_watch(script, lambda e, i: "deny")
        rc, out, err = wait_proc(proc)
        br.close()
        self.assertEqual(rc, 126, err)
        with open(pidfile) as f:
            sidpid = int(f.read().strip())
        time.sleep(0.3)
        self.assertFalse(os.path.exists(f"/proc/{sidpid}"),
                         f"setsid'd child {sidpid} survived the deny")
        self.assertFalse(os.path.exists(f"{OUT}/trip.txt"))

    # 24. '..' must resolve against the real directory after following
    #     symlinks (kernel order), not be folded lexically: deleting
    #     "link/../victim" where link -> <outside>/sub really removes
    #     <outside>/victim — a boundary event, not an in-root pass.
    def test_24_dotdot_after_symlink_is_boundary(self):
        sub = os.path.join(OUT, "sub")
        os.makedirs(sub, exist_ok=True)
        victim = os.path.join(OUT, "victim.txt")
        with open(victim, "w") as f:
            f.write("keep")
        os.symlink(sub, os.path.join(WORK, "link"))
        proc, br = run_watch(f"rm {WORK}/link/../victim.txt",
                             lambda e, i: "deny")
        rc, out, err = wait_proc(proc)
        br.close()
        self.assertEqual(rc, 126, err)
        self.assertEqual(len(br.events), 1)
        self.assertEqual(br.events[0]["targets"][0]["path"], victim)
        self.assertTrue(os.path.exists(victim))
        # Entry-gate denial: the operation really was held before execution.
        self.assertIn("was not performed", err)

    # 25. linkat source is followed only under AT_SYMLINK_FOLLOW ('ln -L'):
    #     the default physical link of an in-root symlink raises no event.
    def test_25_linkat_follow_flag(self):
        real = os.path.join(OUT, "real.txt")
        with open(real, "w") as f:
            f.write("x")
        os.symlink(real, os.path.join(WORK, "src"))
        # ln -P: links the symlink inode itself — in-root, no event.
        proc, br = run_watch(f"ln -P {WORK}/src {WORK}/dst",
                             lambda e, i: "deny")
        rc, out, err = wait_proc(proc)
        br.close()
        self.assertEqual(rc, 0, err)
        self.assertEqual(len(br.events), 0)
        # ln -L: source follows to <outside> — a boundary event fires.
        proc, br = run_watch(f"ln -L {WORK}/src {WORK}/dst2",
                             lambda e, i: "deny")
        rc, out, err = wait_proc(proc)
        br.close()
        self.assertEqual(rc, 126, err)
        self.assertEqual(len(br.events), 1)
        self.assertEqual(br.events[0]["targets"][0]["path"], real)

    # 26. /dev is no longer a blanket pass: a write to a non-whitelisted
    #     node (here tmpfs /dev/shm) is a boundary event; /dev/null stays free.
    def test_26_dev_write_gated(self):
        proc, br = run_watch("echo x > /dev/null",
                             lambda e, i: "deny")
        rc, out, err = wait_proc(proc)
        br.close()
        self.assertEqual(rc, 0, err)
        self.assertEqual(len(br.events), 0)
        probe = "/dev/shm/bw-probe"
        proc, br = run_watch(f"echo x > {probe}", lambda e, i: "deny")
        rc, out, err = wait_proc(proc)
        br.close()
        self.assertEqual(rc, 126, err)
        self.assertEqual(len(br.events), 1)
        self.assertEqual(br.events[0]["targets"][0]["path"], probe)
        self.assertFalse(os.path.exists(probe))

    # 27. A WRITE to a sensitive other-pid /proc object is opaque, not a
    #     'read' event (the read class must never launder a write cap).
    def test_27_proc_write_is_opaque(self):
        proc, br = run_watch("echo x > /proc/1/mem", lambda e, i: "deny")
        rc, out, err = wait_proc(proc)
        br.close()
        self.assertEqual(rc, 126, err)
        self.assertEqual(len(br.events), 1)
        self.assertEqual(br.events[0]["kind"], "opaque")
        self.assertTrue(br.events[0]["details"]["requiresFullApproval"])

    # 28. Detached-phase cancel: after 'allow', the root exits but a
    #     detached setsid'd survivor remains. Broker close must still kill
    #     it — detached is supervised, not invisible. (The terminal frame
    #     only ships once the whole tree is reaped, so we key off the
    #     'allow' reply, not the exit frame.)
    def test_28_detached_setsid_cancel(self):
        pidfile = f"{WORK}/sid2.pid"
        script = (f"setsid sleep 30 & echo $! > {pidfile}; "
                  f"echo x > {OUT}/f.txt")
        proc, br = run_watch(script, lambda e, i: "allow")
        for _ in range(100):
            if br.replies:  # 'allow' landed; the tree is detached
                break
            time.sleep(0.05)
        self.assertTrue(br.replies, "no boundary reply before cancel")
        time.sleep(0.3)
        br.close()
        rc, out, err = wait_proc(proc)
        with open(pidfile) as f:
            sidpid = int(f.read().strip())
        time.sleep(0.3)
        self.assertFalse(os.path.exists(f"/proc/{sidpid}"),
                         f"detached setsid'd child {sidpid} survived cancel")

    # 29. --protect: writes inside a protected dir AND renames of its
    #     ancestors are boundary events even under an allowed root.
    def test_29_protect_inside_and_ancestor(self):
        prot = os.path.join(WORK, "prot")
        os.makedirs(os.path.join(prot, "inner"), exist_ok=True)
        proc, br = run_watch(
            f"echo x > {prot}/inner/new.txt",
            lambda e, i: "deny",
            extra_args=["--protect", os.path.join(prot, "inner")])
        rc, out, err = wait_proc(proc)
        br.close()
        self.assertEqual(rc, 126, err)
        self.assertEqual(len(br.events), 1)
        proc, br = run_watch(
            f"mv {prot} {WORK}/prot-moved",
            lambda e, i: "deny",
            extra_args=["--protect", os.path.join(prot, "inner")])
        rc, out, err = wait_proc(proc)
        br.close()
        self.assertEqual(rc, 126, err)
        self.assertEqual(len(br.events), 1)
        self.assertTrue(os.path.isdir(prot))

    # 30. fd 0-2 rebound onto a real file is a write boundary (the stdio
    #     exemption only covers pipes/ttys, never path targets).
    def test_30_stdio_rebound_is_boundary(self):
        proc, br = run_watch(
            f"exec 1>{OUT}/f.txt; echo hi",
            lambda e, i: "continue")
        rc, out, err = wait_proc(proc)
        br.close()
        self.assertEqual(rc, 0, err)
        # openat (path) + write(1) (fd rebound) both crossed the boundary.
        self.assertGreaterEqual(len(br.events), 2, br.events)
        with open(f"{OUT}/f.txt") as f:
            self.assertEqual(f.read().strip(), "hi")

    # 31. --defer restores only the declared mapping; a user's own
    #     OPENCODE_DEFER_* variable passes through untouched.
    def test_31_defer_explicit_restore(self):
        env = dict(os.environ, PYTHONDONTWRITEBYTECODE="1",
                   OPENCODE_DEFER_MARK="restored-value",
                   OPENCODE_DEFER_OWN="keep-me", MARK="")
        proc, br = run_watch(
            "echo \"M=$MARK\"; echo \"O=$OPENCODE_DEFER_OWN\"; "
            "echo \"S=${OPENCODE_DEFER_MARK:-gone}\"",
            lambda e, i: "deny",
            extra_args=["--defer", "OPENCODE_DEFER_MARK=MARK"],
            env=env)
        rc, out, err = wait_proc(proc)
        br.close()
        self.assertEqual(rc, 0, err)
        self.assertIn("M=restored-value", out)
        self.assertIn("O=keep-me", out)
        self.assertIn("S=gone", out)

    # 32. /dev/fd/N aliases resolve against the TRACEE's descriptor table:
    #     opening /dev/fd/3 where fd3 is a real file produces an event whose
    #     target is the real path — never the watcher's own /proc/self/fd/3.
    def test_32_dev_fd_alias_resolves_tracee_fd(self):
        real = os.path.join(OUT, "viafd.txt")
        with open(real, "w") as f:
            f.write("x")
        proc, br = run_watch(
            f"exec 3>{real}; echo hi > /dev/fd/3",
            lambda e, i: "continue")
        rc, out, err = wait_proc(proc)
        br.close()
        self.assertEqual(rc, 0, err)
        self.assertGreaterEqual(len(br.events), 2, br.events)
        for ev in br.events:
            self.assertEqual(ev["targets"][0]["path"], real,
                             f"alias resolved to wrong object: {ev['targets']}")
        with open(real) as f:
            self.assertIn("hi", f.read())

    # 33. Metadata ops on a whitelisted device are NOT I/O: chmod /dev/null
    #     is a boundary event even though data writes to it pass.
    def test_33_dev_metadata_gated(self):
        proc, br = run_watch("chmod 600 /dev/null", lambda e, i: "deny")
        rc, out, err = wait_proc(proc)
        br.close()
        self.assertEqual(rc, 126, err)
        self.assertEqual(len(br.events), 1)
        self.assertEqual(br.events[0]["operation"], "metadata")
        self.assertEqual(br.events[0]["targets"][0]["path"], "/dev/null")

    # 34. A cancel while the (detached) payload is still running must say
    #     "The command was stopped" — the boundary operation ran long ago;
    #     only an entry-gate denial may claim it was not performed.
    #     (The only exit-side event, recvfd/SCM_RIGHTS, cannot be exercised
    #     live: its sendmsg sibling is full-approval, which only 'allow'
    #     can pass — and 'allow' ends supervision. Wording coverage for the
    #     post-entry paths comes from this cancel instead.)
    def test_34_running_cancel_wording(self):
        proc, br = run_watch(f"echo x > {OUT}/f.txt; sleep 30",
                             lambda e, i: "allow")
        for _ in range(100):
            if br.replies:
                break
            time.sleep(0.05)
        self.assertTrue(br.replies, "no boundary reply")
        time.sleep(0.3)
        br.close()  # broker disconnect mid-run = cancel
        rc, out, err = wait_proc(proc, timeout=15)
        self.assertEqual(rc, 126, err)
        self.assertIn("Command blocked", err)
        self.assertIn("The command was stopped", err)
        self.assertNotIn("was not performed", err)

    # 35. Host SIGTERM on the watcher tears down the WHOLE tree — including
    #     a detached, setsid'd survivor that killpg can no longer reach.
    def test_35_host_sigterm_kills_detached_tree(self):
        pidfile = f"{WORK}/termpid.txt"
        script = (f"echo x > {OUT}/f.txt; "
                  f"setsid sleep 30 & echo $! > {pidfile}; sleep 30")
        proc, br = run_watch(script, lambda e, i: "allow")
        for _ in range(100):
            if br.replies:  # 'allow' landed; the tree is detached
                break
            time.sleep(0.05)
        self.assertTrue(br.replies, "no boundary reply before SIGTERM")
        time.sleep(0.3)
        proc.send_signal(15)  # SIGTERM — the host spawner's .kill()
        rc, out, err = wait_proc(proc, timeout=15)
        br.close()
        self.assertEqual(rc, 126, err)
        with open(pidfile) as f:
            sidpid = int(f.read().strip())
        time.sleep(0.3)
        self.assertFalse(os.path.exists(f"/proc/{sidpid}"),
                         f"detached setsid'd child {sidpid} survived SIGTERM")

    # 36. Root exit only RECORDS the result: the terminal exit frame arrives
    #     after the whole tree is gone — an orphaned detached child keeps
    #     the channel (and the watcher) alive until it finishes.
    def test_36_terminal_waits_for_whole_tree(self):
        script = f"echo x > {OUT}/f.txt; sleep 1.5 & echo MARK"
        proc, br = run_watch(script, lambda e, i: "allow")
        line = proc.stdout.readline()  # blocks until MARK (root about to exit)
        self.assertIn(b"MARK", line)
        time.sleep(0.5)
        self.assertEqual(br.exits, [],
                         "terminal frame sent before the tree finished")
        rc, out, err = wait_proc(proc, timeout=15)
        br.close()
        self.assertEqual(rc, 0, err)
        self.assertEqual(len(br.exits), 1)
        self.assertEqual(br.exits[0]["exit"], 0)

    # 37. A blocking write to a PIPE shared with a sibling thread must not
    #     deadlock the sibling freeze: the fd resolves to a non-path object,
    #     nothing mutable was consulted, the freeze lifts immediately.
    def test_37_pipe_write_no_freeze_deadlock(self):
        script = (
            "python3 -c 'import os,threading\n"
            "r,w=os.pipe()\n"
            "data=b\"x\"*200000\n"
            "def rd():\n"
            "    n=0\n"
            "    while True:\n"
            "        b=os.read(r,65536)\n"
            "        if not b: break\n"
            "        n+=len(b)\n"
            f"    open(\"{OUT}/pipen\",\"w\").write(str(n))\n"
            "t=threading.Thread(target=rd); t.start()\n"
            "os.write(w,data); os.close(w); t.join()\n"
            "print(\"done\")\n'")
        proc, br = run_watch(script, lambda e, i: "continue", timeout=25)
        rc, out, err = wait_proc(proc, timeout=25)
        br.close()
        self.assertEqual(rc, 0, err)
        self.assertIn("done", out)
        with open(f"{OUT}/pipen") as f:
            self.assertEqual(f.read().strip(), "200000")

    # 38. Two threads of one tgid gating boundary syscalls concurrently:
    #     the freezes are owner-scoped — both events serialize through the
    #     broker, neither syscall starves nor escapes.
    def test_38_dual_gated_threads(self):
        script = (
            "python3 -c 'import threading\n"
            "def w(n):\n"
            f"    open(\"{OUT}/th%d.txt\"%n,\"w\").write(\"x\")\n"
            "t1=threading.Thread(target=w,args=(1,))\n"
            "t2=threading.Thread(target=w,args=(2,))\n"
            "t1.start(); t2.start(); t1.join(); t2.join()\n"
            "print(\"done\")\n'")
        proc, br = run_watch(script, lambda e, i: "continue")
        rc, out, err = wait_proc(proc)
        br.close()
        self.assertEqual(rc, 0, err)
        self.assertIn("done", out)
        # 4 events: openat(create) + write(modify via fd→path) per thread —
        # all serialized through the broker, none dropped or starved.
        self.assertEqual(len(br.events), 4, br.events)
        creates = {ev["targets"][0]["path"] for ev in br.events
                   if ev["syscall"] == "openat"}
        self.assertEqual(creates, {f"{OUT}/th1.txt", f"{OUT}/th2.txt"})
        writes = {ev["targets"][0]["path"] for ev in br.events
                  if ev["syscall"] == "write"}
        self.assertEqual(writes, creates)
        for n in (1, 2):
            with open(f"{OUT}/th{n}.txt") as f:
                self.assertEqual(f.read(), "x")

    # 39. pause_siblings failing (injected) fails the command CLOSED —
    #     a sibling that cannot be confirmed stopped is not checked around.
    def test_39_pause_failure_fails_closed(self):
        env = dict(os.environ, PYTHONDONTWRITEBYTECODE="1",
                   BW_TEST_PAUSE_FAIL="1")
        proc, br = run_watch(f"echo x > {OUT}/f.txt",
                             lambda e, i: "deny", env=env)
        rc, out, err = wait_proc(proc)
        br.close()
        self.assertEqual(rc, 126, err)
        self.assertIn("could not be frozen", err)
        self.assertFalse(os.path.exists(f"{OUT}/f.txt"))

    # 40. A failed PR_SET_CHILD_SUBREAPER (injected) is a launch refusal:
    #     the cancel guarantee is load-bearing, so the payload must never
    #     start and no permit path may run — no events, no exit frame, no
    #     broker connection at all (the helper dies before connecting).
    def test_40_subreaper_failure_starts_nothing(self):
        env = dict(os.environ, PYTHONDONTWRITEBYTECODE="1",
                   BW_TEST_SUBREAPER_FAIL="1")
        proc, br = run_watch(f"touch {OUT}/subreaper-ran",
                             lambda e, i: "allow", env=env)
        rc, out, err = wait_proc(proc)
        self.assertEqual(rc, 125, err)
        self.assertIn("CHILD_SUBREAPER", err)
        time.sleep(0.3)
        br.close()
        self.assertEqual(br.events, [])
        self.assertEqual(br.exits, [])
        self.assertFalse(os.path.exists(f"{OUT}/subreaper-ran"))

    # 41. fd-rebind coordination: a sibling dup2 on an fd whose pipe
    #     binding an in-flight write consumed is HELD at its own entry
    #     stop until the write exits — the reviewed object is the object
    #     that runs. The fdhold C fixture uses real threads; the drain
    #     sweep collects the dup2's pending entry stop into the deferred
    #     queue, so it is decided while the write's in-flight record is
    #     provably live (ordering does not depend on waitpid order).
    def test_41_fd_rebind_held_until_consumer_exits(self):
        exe = build_fdhold_fixture()
        env = dict(os.environ, BW_DEBUG="1",
                   BW_TEST_POSTGATE_DELAY_MS="300",
                   BW_TEST_PREGATE_DELAY_MS="250")
        proc, br = run_watch(f"{exe} rebind {OUT}/rebound.txt",
                             lambda e, i: "continue", timeout=60, env=env)
        rc, out, err = wait_proc(proc, timeout=60)
        br.close()
        self.assertEqual(rc, 0, err)
        # At least one round held the dup2 (nr 33) at its own entry —
        # decided while the write's in-flight record was provably live.
        self.assertIn("HELD nr=33", err)
        # Held rounds put PAYLOAD in the pipe (the reviewed binding); an
        # early-processed round — legal, it ran before the gate — puts it
        # in the file, so PIPE/MISSING mix is expected. The constant is
        # that a held dup2 can never redirect the in-flight write.
        self.assertIn("PIPE", out)
        writes = [ev for ev in br.events if ev["syscall"] == "write"]
        self.assertTrue(writes, br.events)
        for ev in writes:
            self.assertEqual(ev["targets"][0]["path"],
                             f"{OUT}/rebound.txt")


    # 42. Same hold for close(): a sibling close of an in-flight fd waits
    #     at its entry stop until the consuming write exits.
    def test_42_fd_close_held_until_consumer_exits(self):
        exe = build_fdhold_fixture()
        env = dict(os.environ, BW_DEBUG="1",
                   BW_TEST_POSTGATE_DELAY_MS="300",
                   BW_TEST_PREGATE_DELAY_MS="250")
        proc, br = run_watch(f"{exe} close {OUT}/closed-target.txt",
                             lambda e, i: "continue", timeout=60, env=env)
        rc, out, err = wait_proc(proc, timeout=60)
        br.close()
        self.assertEqual(rc, 0, err)
        # At least one round held the close (nr 3) at its own entry while
        # the write record was live.
        self.assertIn("HELD nr=3", err)
        self.assertIn("PIPE", out)
        self.assertIn("BADFD", out)


    # 43. Cross-tgid table sharing: clone(CLONE_FILES|SIGCHLD) reports a
    #     FORK event, not CLONE — files_id must follow the creating
    #     syscall's recorded flags, so a DIFFERENT tgid's dup2 on the
    #     in-flight pipe fd is still held until the write exits.
    def test_43_clone_files_sigchld_rebind_held(self):
        exe = build_shareclone_fixture()
        env = dict(os.environ, BW_TEST_POSTGATE_DELAY_MS="300",
                   BW_TEST_PREGATE_DELAY_MS="250")
        proc, br = run_watch(f"{exe} {OUT}/cross-rebound.txt",
                             lambda e, i: "continue", timeout=30, env=env)
        rc, out, err = wait_proc(proc, timeout=30)
        br.close()
        self.assertEqual(rc, 0, err)
        # PAYLOAD reached the pipe (the binding the gate reviewed): the
        # cross-tgid dup2 could NOT have run before the write executed.
        self.assertIn("PIPE", out)
        self.assertNotIn("MISSING", out)
        # After release the rebind took effect: the child's write through
        # the shared slot went to the real file — and was gated there.
        writes = [ev for ev in br.events if ev["syscall"] == "write"]
        self.assertTrue(len(writes) >= 2, br.events)  # CHILD + AFTER
        for ev in writes:
            self.assertEqual(ev["targets"][0]["path"],
                             f"{OUT}/cross-rebound.txt")
        with open(f"{OUT}/cross-rebound.txt") as fh:
            self.assertEqual(fh.read(), "CHILDAFTER")

    # 44. Range rebinds keep the WHOLE request held: a close_range covering
    #     two in-flight fds must stay held after only ONE consumer exits —
    #     the release retests the full recorded range. The 'keep-held'
    #     debug line after consumer A's exit proves the range survived a
    #     single-consumer release pass; 'release-held' then comes only
    #     after the last record clears.
    def test_44_close_range_covers_all_inflight(self):
        exe = build_fdhold_fixture()
        env = dict(os.environ, BW_DEBUG="1",
                   BW_TEST_POSTGATE_DELAY_MS="300",
                   BW_TEST_PREGATE_DELAY_MS="250")
        proc, br = run_watch(f"{exe} range {OUT}/ranged.txt",
                             lambda e, i: "continue", timeout=60, env=env)
        rc, out, err = wait_proc(proc, timeout=60)
        br.close()
        self.assertEqual(rc, 0, err)
        # A round held close_range (nr 436) while records were live, then
        # a release pass kept it held (a second consumer's record was
        # still in flight) before the final release — proving the release
        # retests the WHOLE recorded range, not one fd. Track the held
        # tid's lifecycle: HELD -> keep-held (mid-hold release scan) ->
        # release-held.
        self.assertIn("HELD nr=436 kind=1", err)
        held_tids = [ln.split("HELD")[0].split("tid=")[1].split()[0]
                     for ln in err.splitlines() if "HELD nr=436" in ln]
        kept = False
        for tid in held_tids:
            lines = err.splitlines()
            i0 = next(i for i, ln in enumerate(lines)
                      if f"tid={tid} " in ln and "HELD nr=436" in ln)
            after = lines[i0:]
            k = next((i for i, ln in enumerate(after)
                      if f"keep-held tid={tid} " in ln), None)
            r = next((i for i, ln in enumerate(after)
                      if f"release-held tid={tid}" in ln), None)
            if k is not None and r is not None and k < r:
                kept = True
                break
        self.assertTrue(kept, "no held close_range survived a mid-hold "
                        "release scan; stderr tail:\n" + err[-4000:])


    # 45. clone3 with an unreadable argument block fails CLOSED — the flags
    #     decide fd-table sharing, and a guessed default would miss a real
    #     CLONE_FILES. No payload effect runs past the kill.
    def test_45_clone3_unreadable_args_fail_closed(self):
        env = dict(os.environ, PYTHONDONTWRITEBYTECODE="1",
                   BW_TEST_CLONE3_FAIL="1")
        script = (
            "python3 -c 'import ctypes\n"
            "ctypes.CDLL(\"libc.so.6\").syscall(435,0,88)\n"
            "'")
        proc, br = run_watch(script, lambda e, i: "continue", env=env)
        rc, out, err = wait_proc(proc)
        br.close()
        self.assertEqual(rc, 126, err)
        self.assertIn("clone3 argument block could not be read", err)
        self.assertEqual(br.events, [])

    # 46. Closed-slot observation coordination: the gate sees fd 10 closed
    #     (write -> EBADF pass), and a same-table sibling's fd-allocating
    #     syscall is held at ITS entry until the write exits — otherwise
    #     the allocator could fill slot 10 between check and execution and
    #     the write would land on a file the gate never saw. The write's
    #     EBADF is an ordinary kernel result; the released open() and the
    #     post-release write DO review (path inside --root).
    def test_46_closed_slot_allocator_held(self):
        exe = build_fdhold_fixture()
        env = dict(os.environ, BW_DEBUG="1",
                   BW_TEST_POSTGATE_DELAY_MS="300",
                   BW_TEST_PREGATE_DELAY_MS="250")
        proc, br = run_watch(f"{exe} alloc {OUT}/alloc.txt",
                             lambda e, i: "continue", timeout=60, env=env)
        rc, out, err = wait_proc(proc, timeout=60)
        br.close()
        self.assertEqual(rc, 0, err)
        # At least one round held the allocator at its own entry (kind 2)
        # until the consumer exited — direct tracer evidence.
        self.assertIn("HELD nr=257 kind=2", err)
        # Rounds where the allocator ran first give fd=10 anyway (the slot
        # is free); the distinguishing evidence is the HELD marker plus
        # the reviewed open() event for the file inside --root.
        self.assertIn("fd=10", out)
        ev_paths = {ev["targets"][0]["path"] for ev in br.events
                    if ev.get("targets")}
        self.assertIn(f"{OUT}/alloc.txt", ev_paths)

    # 47. NSS lookups (`ls -l` resolving owner names) never reach the
    #     broker: nscd is refused with ENOENT, which glibc treats as "no
    #     cache daemon".
    def test_47_nss_lookup_is_not_a_boundary(self):
        script = (f"ls -la {WORK} >/dev/null && python3 -c '\n"
                  "import errno, socket\n"
                  "s = socket.socket(socket.AF_UNIX)\n"
                  "try:\n"
                  "    s.connect(\"/var/run/nscd/socket\")\n"
                  "    print(\"connected\")\n"
                  "except OSError as e:\n"
                  "    print(\"errno\", e.errno)\n"
                  "'")
        proc, br = run_watch(script, lambda e, i: "deny")
        rc, out, err = wait_proc(proc)
        br.close()
        self.assertEqual(rc, 0, err)
        self.assertIn(f"errno {errno.ENOENT}", out)
        self.assertEqual(br.events, [])

    # 48. io_uring_setup is refused with ENOSYS without a broker round trip;
    #     the ring-less io_uring_enter stays an opaque boundary.
    def test_48_io_uring_setup_refused_enosys(self):
        script = ("python3 -c '\n"
                  "import ctypes\n"
                  "libc = ctypes.CDLL(None, use_errno=True)\n"
                  "params = ctypes.create_string_buffer(120)\n"
                  "rc = libc.syscall(425, 4, params)\n"
                  "print(rc, ctypes.get_errno())\n"
                  "'")
        proc, br = run_watch(script, lambda e, i: "deny")
        rc, out, err = wait_proc(proc)
        br.close()
        self.assertEqual(rc, 0, err)
        self.assertEqual(out.split(), ["-1", str(errno.ENOSYS)])
        self.assertEqual(br.events, [])

    # 49. Signal 0 only probes existence and passes; a real signal to a pid
    #     outside the tree is still an opaque boundary.
    def test_49_signal_zero_passes(self):
        proc, br = run_watch("kill -0 $PPID && kill -0 0 && echo probed",
                             lambda e, i: "deny")
        rc, out, err = wait_proc(proc)
        br.close()
        self.assertEqual(rc, 0, err)
        self.assertIn("probed", out)
        self.assertEqual(br.events, [])
        proc, br = run_watch("kill -CONT $PPID", lambda e, i: "deny")
        rc, out, err = wait_proc(proc)
        br.close()
        self.assertEqual(rc, 126, err)
        self.assertEqual(br.events[0]["operation"], "signal")

    # 50. Kernel-addressed netlink (getifaddrs/if_nameindex route dumps) is
    #     a query channel, not an opaque IPC boundary.
    def test_50_kernel_netlink_query_passes(self):
        proc, br = run_watch(
            "python3 -c 'import socket; print(len(socket.if_nameindex()) > 0)'",
            lambda e, i: "deny")
        rc, out, err = wait_proc(proc)
        br.close()
        self.assertEqual(rc, 0, err)
        self.assertIn("True", out)
        self.assertEqual(br.events, [])

    # 51. procps `ps` scanning other processes' environ is refused (EACCES)
    #     without review; any other reader of another process's environ is
    #     still a read boundary.
    @unittest.skipUnless(os.path.realpath("/usr/bin/ps") == "/usr/bin/ps",
                         "procps ps not installed at /usr/bin/ps")
    def test_51_ps_environ_scan_refused(self):
        proc, br = run_watch("ps aux > /dev/null && echo listed",
                             lambda e, i: "deny")
        rc, out, err = wait_proc(proc)
        br.close()
        self.assertEqual(rc, 0, err)
        self.assertIn("listed", out)
        self.assertEqual(br.events, [])
        proc, br = run_watch(f"cat /proc/{os.getpid()}/environ > /dev/null",
                             lambda e, i: "deny")
        rc, out, err = wait_proc(proc)
        br.close()
        self.assertEqual(rc, 126, err)
        self.assertEqual(br.events[0]["kind"], "read")
        # The watcher's own entries (broker token in cmdline) are refused.
        proc, br = run_watch("cat /proc/$PPID/cmdline", lambda e, i: "deny")
        rc, out, err = wait_proc(proc)
        br.close()
        self.assertEqual(rc, 1, err)
        self.assertIn("Permission denied", err)
        self.assertNotIn("--token", out)
        self.assertEqual(br.events, [])


    def test_52_fail_open_broker_failures_release_payload(self):
        for policy in [lambda ev, idx: "eof",
                       lambda ev, idx: {"version": 9, "action": "allow"}]:
            with self.subTest(policy=policy):
                fresh_tree()
                target = os.path.join(OUT, "fail-open.txt")
                proc, broker = run_watch(
                    f"printf fixture > {target}", policy,
                    extra_args=["--fail-open"])
                code, out, err = wait_proc(proc)
                broker.close()
                self.assertEqual(code, 0, err)
                self.assertTrue(os.path.exists(target))
                self.assertNotRegex(out + err, r"blocked|cannot|could not")

    def test_53_fail_open_setup_execs_payload_once(self):
        for failure in ["BW_TEST_SUBREAPER_FAIL", "BW_TEST_SEIZE_FAIL"]:
            with self.subTest(failure=failure):
                fresh_tree()
                target = os.path.join(WORK, "setup-pass.txt")
                proc, broker = run_watch(
                    f"printf fixture >> {target}", lambda ev, idx: "deny",
                    extra_args=["--fail-open"], env=dict(os.environ, **{failure: "1"}))
                code, out, err = wait_proc(proc)
                broker.close()
                self.assertEqual(code, 0, err)
                with open(target) as stream:
                    self.assertEqual(stream.read(), "fixture")
                self.assertNotRegex(out + err, r"blocked|cannot|could not")

    def test_54_fail_open_timeout_releases_payload(self):
        fresh_tree()
        target = os.path.join(OUT, "timeout-pass.txt")

        def slow_reply(ev, idx):
            time.sleep(6)
            return "allow"

        proc, broker = run_watch(
            f"printf fixture > {target}", slow_reply,
            extra_args=["--fail-open", "--approve-timeout-ms", "5000"])
        code, out, err = wait_proc(proc)
        broker.close()
        self.assertEqual(code, 0, err)
        self.assertTrue(os.path.exists(target))
        self.assertNotRegex(out + err, r"blocked|cannot|could not")

    def test_55_fail_open_keeps_denial_and_explicit_cancellation(self):
        for policy in [lambda ev, idx: "deny",
                       lambda ev, idx: {"version": 1, "type": "cancel"}]:
            with self.subTest(policy=policy):
                fresh_tree()
                target = os.path.join(OUT, "must-not-run.txt")
                proc, broker = run_watch(
                    f"printf fixture > {target}", policy,
                    extra_args=["--fail-open"])
                code, out, err = wait_proc(proc)
                broker.close()
                self.assertEqual(code, 126, err)
                self.assertFalse(os.path.exists(target))
                self.assertIn("Command blocked:", err)

    def test_56_fail_open_idle_eof_releases_whole_tree(self):
        fresh_tree()
        target = os.path.join(OUT, "idle-pass.txt")
        proc, broker = run_watch(
            f"sleep 1; printf fixture > {target}", lambda ev, idx: "deny",
            extra_args=["--fail-open"], close_after_accept=True, eof_delay=0.1)
        code, out, err = wait_proc(proc)
        broker.close()
        self.assertEqual(code, 0, err)
        self.assertTrue(os.path.exists(target))
        self.assertNotRegex(out + err, r"blocked|cannot|could not")

    def test_57_fragmented_idle_cancel_never_degrades_to_broker_eof(self):
        fresh_tree()
        target = os.path.join(WORK, "after-cancel.txt")
        proc, broker = run_watch(
            f"sleep 2; printf fixture > {target}", lambda ev, idx: "deny",
            extra_args=["--fail-open"], eof_delay=0.2,
            idle_control=[b'{"version":1,"type":"can', b'cel"}\n'])
        code, out, err = wait_proc(proc)
        broker.close()
        self.assertEqual(code, 126, err)
        self.assertFalse(os.path.exists(target))
        self.assertIn("cancelled", err)
        self.assertEqual(broker.events, [])

    def test_58_unfinished_idle_control_frame_uses_bounded_cancel(self):
        fresh_tree()
        target = os.path.join(WORK, "after-partial-cancel.txt")
        proc, broker = run_watch(
            f"sleep 2; printf fixture > {target}", lambda ev, idx: "deny",
            extra_args=["--fail-open"], eof_delay=0.2,
            idle_control=[b'{"version":1,"type":"cancel"}'])
        code, out, err = wait_proc(proc)
        broker.close()
        self.assertEqual(code, 126, err)
        self.assertFalse(os.path.exists(target))
        self.assertIn("cancelled", err)
        self.assertEqual(broker.events, [])

if __name__ == "__main__":
    unittest.main(verbosity=2)
