/*
 * opencode-boundary-watch — ptrace runtime boundary supervisor (v1)
 *
 * Linux x86_64 only. Companion to opencode-sandbox (mount/Landlock floor):
 * where that helper hard-denies crossings at spawn time, this helper runs the
 * payload with NO mount/NNP/Landlock restrictions and interposes at syscall
 * entry — every boundary-crossing syscall is paused BEFORE it executes and a
 * one-shot decision is requested from a broker over an AF_UNIX NDJSON channel.
 *
 * Protocol (stable):
 *
 *   opencode-boundary-watch --broker <absUnixSocket> --token <64hex>
 *       --root <canonicalpath> [--root ...]
 *       [--deny-read <path> ...] [--deny-write <path> ...] [--protect <path> ...]
 *       [--defer <storageVar>=<realName> ...] [--readonly]
 *       [--approve-timeout-ms N] -- <absoluteShell> -c <script>
 *
 *   helper -> broker (one JSON object per line, <= 64KiB):
 *     {"version":1,"type":"boundary","token":"...","eventID":N,"pid":TID,
 *      "syscall":"<name>","kind":"write|read|network|privilege|interop|opaque",
 *      "operation":"<open|modify|create|delete|rename|metadata|exec|connect|...>",
 *      "targets":[{"path":"<canonical>","exists":bool,"dev":"D","ino":"D",
 *                  "parentDev":"D","parentIno":"D"}],
 *      "details":{...small metadata...}}
 *   dev/ino values are decimal STRINGS (DrvFs inodes exceed JS 2^53).
 *   Events that grant an un-monitorable capability carry
 *   "details":{"requiresFullApproval":true}; for those, a broker 'continue'
 *   answer is treated as 'deny' (double protection — the broker must only send
 *   'allow' or 'deny' for them anyway).
 *
 *   broker -> helper: {"version":1,"eventID":N,"action":"allow|continue|deny"}
 *     allow    — the whole command is approved: detach the entire tree at the
 *                paused syscall entry so it runs natively (setuid elevation
 *                works). The supervisor stays alive, keeps the broker socket
 *                open, and reaps the root child; a broker disconnect during
 *                the detached phase kills the payload process group.
 *     continue — release ONLY this syscall; keep watching (L2-cache hits).
 *                Refused (as deny) for requiresFullApproval events.
 *     deny     — SIGKILL the whole tree. Same for a malformed reply, EOF, or
 *                the approval timeout: fail closed, never silently pass.
 *     The broker connection is supervised for the WHOLE run: EOF at any
 *     point (idle, mid-approval, detached) kills the payload tree/group.
 *
 *   --protect <path>: control-plane objects (this binary, the package's own
 *     code, the broker socket dir). A write inside a protected path OR to
 *     any ancestor of it (rename/unlink/chmod on a parent swaps the whole
 *     subtree) is a boundary event even when inside a write root.
 *   --defer <storage>=<name>: env-hook handoff. The untraced wrapper shell
 *     ran with <storage> variables instead of the real hook names; the
 *     traced child restores exactly the declared pairs before exec — other
 *     same-prefix variables pass through untouched.
 *   Detached != unsupervised: detached tracees stay in the table and are
 *     still SIGKILLed per-pid on cancel (setsid only escapes killpg, not
 *     the tracked list). The watcher is a child subreaper: orphaned
 *     grandchildren reparent to it and are likewise killable. The root's
 *     exit only RECORDS the exit code — the single terminal frame goes
 *     out when the whole tree is reaped (waitpid ECHILD). A broker close
 *     while supervising is always a cancel and reaches every descendant;
 *     SIGTERM/INT/HUP arm a flag checked in every wait loop and take the
 *     same teardown path (SIGKILL is uncatchable and remains a stated
 *     limitation: the payload survives us then).
 *   Block messages: "Command blocked: <reason>. <The boundary operation
 *   was not performed|The command was stopped>; earlier steps may already
 *   have run. Do not automatically rerun the whole command." The first
 *   phrase is used ONLY for entry-gate denials; exit-side denials (recvmsg
 *   cmsg), cancels, timeouts and review failures never claim the operation
 *   did not run.
 *
 *   helper -> broker (terminal, no reply expected):
 *     {"version":1,"type":"exit","token":"...","exit":<0..255>}
 *     Emitted exactly once after the payload's final exit, just before the
 *     channel closes: 128+SIGKILL for vetoed/killed payloads, the real code
 *     otherwise. Lets the broker retire a call that already returned the
 *     tool result (background=true) without polling.
 *
 *   Event "details" always include decision context:
 *     "cwd" (canonical), "executable" (/proc/<tgid>/exe, canonical),
 *     "argv" (the execve vector on exec events, /proc/<tgid>/cmdline else).
 *     An oversized/unreadable argv becomes "argvIncomplete":true +
 *     requiresFullApproval (a partial argv must never enter a cache that
 *     keys on the complete vector).
 *
 * Security notes (deliberate, documented):
 *  - The payload is a CHILD tree seized via PTRACE_SEIZE + PTRACE_O_EXITKILL
 *    so a watcher death SIGKILLs every tracee (no silent detach).
 *  - Payload cannot inherit the broker socket (child closes all fds > 2) and
 *    cannot learn the token (argv scrubbed; never in env; /proc/<watcher-pid>/
 *    access is forced through an opaque boundary event, never passed).
 *  - Entries that grant un-monitorable capability (io_uring*, Linux AIO,
 *    ptrace, process_vm_*, open_by_handle_at, perf_event_open, bpf,
 *    CLONE_UNTRACED clones) are opaque boundary events with
 *    requiresFullApproval — 'continue' is refused helper-side, 'allow'
 *    detaches at entry so the primitive runs with full native semantics.
 *  - TOCTOU: before resolving arguments for a decision, every sibling
 *    thread of the reporting tgid is PTRACE_INTERRUPT-paused AND held
 *    paused until the gated syscall reaches its exit stop (recv family
 *    excepted: the cmsg buffer is re-checked at the exit stop under a
 *    fresh freeze — a blocking recv must not starve the sibling that
 *    supplies the data). A sibling that cannot be confirmed stopped fails
 *    the command closed. Residual: the drain window while siblings stop —
 *    bounded, never silently widened.
 *  - Path resolution follows kernel traversal order: realpath() on the
 *    deepest existing ancestor (which resolves '..' AFTER following
 *    symlinks), never lexical '..' folding first — 'a/link/../f' where
 *    link is a symlink resolves to the same object the kernel would open.
 *    NOFOLLOW-last applies only to the final component.
 *  - /dev is not a blanket pass: only stdio plumbing and classic
 *    sinks/sources (/dev/null, /dev/pts/N, ...) skip classification;
 *    writes to any other node are boundary events. stdio fds 0-2 are
 *    resolved through /proc/pid/fd — a rebinding onto a real file gates.
 *  - Sensitive other-pid /proc objects classify WRITES as opaque (never a
 *    'read' event that would skip the write ceiling).
 *  - setuid/sgid exec while traced is suppressed by the kernel; the correct
 *    broker answer for a 'privilege' exec is 'allow' (detach -> native).
 *  - Syscall nrs not in the gate table but > LAST_KNOWN_NR are 'opaque'
 *    boundary events (new kernel primitives fail closed instead of slipping).
 *  - ABI: PTRACE_GET_SYSCALL_INFO.arch is verified per entry stop; a compat
 *    (i386/x32/int80) syscall is an opaque 'exec-domain' boundary rather than
 *    being mis-gated against the x86_64 table. Only x86_64 is supported.
 *  - NOFOLLOW-last ops (unlink/rmdir/rename/mkdir/mknod/symlink dest/
 *    linkat dest/lchown/l*xattr, plus O_NOFOLLOW and O_CREAT|O_EXCL opens)
 *    resolve as canonical(parent) + lexical basename — deleting an in-root
 *    symlink that merely points outside is NOT an out-of-root deletion.
 *    link()/rename() report BOTH endpoints as targets (a hardlink bumps the
 *    source inode's nlink — the source is a real effect).
 */

#define _GNU_SOURCE
#if !defined(__x86_64__) || !defined(__linux__)
#error "opencode-boundary-watch supports Linux x86_64 only"
#endif

#include <arpa/inet.h>
#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <poll.h>
#include <sched.h>
#include <signal.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/prctl.h>
#include <sys/ptrace.h>
#include <sys/signalfd.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/un.h>
#include <sys/user.h>
#include <sys/vfs.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
#include <linux/audit.h>
#include <linux/elf.h>
#include <linux/ptrace.h>
#include <linux/sched.h>

#ifndef PTRACE_GET_SYSCALL_INFO
#define PTRACE_GET_SYSCALL_INFO 0x420e
#endif
#ifndef AUDIT_ARCH_X86_64
#define AUDIT_ARCH_X86_64 0xC000003EU
#endif
#ifndef __X32_SYSCALL_BIT
#define __X32_SYSCALL_BIT 0x40000000
#endif

#ifndef CLONE_NEWTIME
#define CLONE_NEWTIME 0x00000080
#endif
#ifndef CLONE_UNTRACED
#define CLONE_UNTRACED 0x00800000
#endif
#ifndef O_PATH
#define O_PATH 010000000
#endif
#ifndef O_TMPFILE
#define O_TMPFILE (020000000 | 0200000)
#endif
#ifndef AT_EMPTY_PATH
#define AT_EMPTY_PATH 0x1000
#endif
#ifndef AT_FDCWD
#define AT_FDCWD -100
#endif
#ifndef PTRACE_EVENT_STOP
#define PTRACE_EVENT_STOP 128
#endif
#ifndef PR_SET_PTRACER
#define PR_SET_PTRACER 0x59616d61
#endif
#ifndef PR_SET_CHILD_SUBREAPER
#define PR_SET_CHILD_SUBREAPER 36
#endif

/* ------------------------------------------------------------------ */
/* Configuration                                                       */
/* ------------------------------------------------------------------ */

#define MAX_ROOTS 64
#define MAX_TIDS 8192
#define MAX_JSON (64 * 1024)
#define APPROVE_TIMEOUT_MS 35000 /* default; --approve-timeout-ms overrides */
#define LAST_KNOWN_NR 470

static long g_approve_timeout_ms = APPROVE_TIMEOUT_MS;

/* Gate return code (internal): PASS = resume silently; other values are
 * broker decision codes or the detach-mode signal RC_DETACHED. */
#define GATE_PASS (-100)
#define RC_DETACHED 3

static char *g_roots[MAX_ROOTS];
static int g_nroots;
static char *g_deny_read[MAX_ROOTS];
static int g_ndeny_read;
static char *g_deny_write[MAX_ROOTS];
static int g_ndeny_write;
/* Control-plane paths (watcher binary, package code, broker dir): a write
 * inside them OR to any ancestor (rename/unlink/rmdir/chmod of a parent
 * swaps the whole subtree) is a boundary event. --protect <path>. */
static char *g_protect[MAX_ROOTS];
static int g_nprotect;
/* Environment hook deferral: explicit <storage>:<real> pairs built by the
 * broker side. Only the listed storage names are restored/unset — the
 * payload's own OPENCODE_DEFER_* variables pass through untouched. */
static char *g_defer_store[256];
static char *g_defer_real[256];
static int g_ndefer;
static int g_readonly;
/* Set whenever a gate consumed mutable tracee state — a path string, a
 * sockaddr/msghdr buffer, or an fd that resolved to a real path (whose
 * shared-fd binding a sibling could swap). handle_stop keeps the sibling
 * freeze until the gated syscall's exit stop only when this is set; a gate
 * that needed none (e.g. a write to a pipe) releases it at once so an
 * in-process rendezvous cannot deadlock. */
static int g_gate_used_mutable;
/* Fd NUMBERS whose current binding the in-flight gate consulted (fd →
 * real path, fd → pipe/socket, or "fd already closed" — all mutable
 * facts). A thread sharing the same fd table (CLONE_FILES) could rebind
 * such a number between the check and the syscall's actual execution, so
 * the gate result alone would not describe the object that really runs.
 * After the gate these move into the tracee's inflight_fds; a same-table
 * close/dup2/dup3/close_range on one is then held at ITS entry stop until
 * the consuming syscall exits — reviewed object == executed object. */
static long g_gate_fds[8];
static char g_gate_fd_kind[8];
static int g_ngate_fds;
static int g_gate_saw_racy_fd; /* any 'n'/'c' fd recorded this gate */
static void note_fd(long fd, char kind)
{
    fd = (long)(int)fd;
    if (fd < 0) return;
    for (int i = 0; i < g_ngate_fds; i++)
        if (g_gate_fds[i] == fd) return;
    if (g_ngate_fds < 8) {
        g_gate_fds[g_ngate_fds] = fd;
        g_gate_fd_kind[g_ngate_fds] = kind;
        g_ngate_fds++;
        if (kind != 'f') g_gate_saw_racy_fd = 1;
    }
}
/* Test-only: stretch the decision→execution window so fixtures can race a
 * rebind deterministically. Applies only when a NON-FILE or CLOSED
 * binding was observed — normal file-path gates keep full speed.
 * Delaying longer only holds siblings longer; it cannot widen a check. */
static long g_postgate_delay_ms;
static const char *g_broker_path;
static char g_token[65];
static pid_t g_self_pid;
static pid_t g_root_pid;
static int g_fail_open;
static char *const *g_payload_argv;
static int g_broker_fd = -1;
static void setup_fail_open(void);
/* Set by the host's normal signals (TERM/INT/HUP). Checked in every wait
 * loop so a cancel tears down the WHOLE payload tree — traced, detached,
 * and orphaned — instead of letting detached survivors outlive us. */
static volatile sig_atomic_t g_term_signal;
static void on_term_signal(int sig) { g_term_signal = sig; }

static void die(const char *fmt, ...)
{
    if (g_fail_open && g_payload_argv && !g_term_signal)
        setup_fail_open();
    if (g_root_pid > 0) kill(g_root_pid, SIGKILL);
    va_list ap;
    va_start(ap, fmt);
    fprintf(stderr, "opencode-boundary-watch: ");
    vfprintf(stderr, fmt, ap);
    fprintf(stderr, "\n");
    va_end(ap);
    exit(125);
}

/* ------------------------------------------------------------------ */
/* Small utilities                                                     */
/* ------------------------------------------------------------------ */

static int write_all(int fd, const void *buf, size_t len)
{
    const char *p = buf;
    while (len) {
        /* send+MSG_NOSIGNAL: a dead broker must never SIGPIPE us — the
         * fail-closed path (kill_tree) itself writes a terminal frame. */
        ssize_t n = send(fd, p, len, MSG_NOSIGNAL);
        if (n < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        p += n;
        len -= (size_t)n;
    }
    return 0;
}

/* Canonicalize: realpath the deepest existing ancestor, re-append the
 * missing suffix. Returns 1 when a canonical path was produced, 0 when the
 * path could not be resolved at all (caller treats as boundary). */
static int canon_path(const char *abs, char *out)
{
    char cur[PATH_MAX];
    char suffix[PATH_MAX] = "";
    snprintf(cur, sizeof(cur), "%s", abs);
    for (int depth = 0; depth < 64; depth++) {
        if (realpath(cur, out)) {
            if (suffix[0]) {
                if (strlen(out) + strlen(suffix) + 2 >= PATH_MAX) return 0;
                strcat(out, "/");
                strcat(out, suffix);
            }
            return 1;
        }
        if (errno != ENOENT && errno != ENOTDIR) return 0;
        char *slash = strrchr(cur, '/');
        if (!slash || slash == cur) return 0;
        char leaf[PATH_MAX];
        snprintf(leaf, sizeof(leaf), "%s", slash + 1);
        if (suffix[0]) {
            char tmp[PATH_MAX * 2];
            snprintf(tmp, sizeof(tmp), "%s/%s", leaf, suffix);
            if (strlen(tmp) >= sizeof(suffix)) return 0;
            snprintf(suffix, sizeof(suffix), "%s", tmp);
        } else {
            snprintf(suffix, sizeof(suffix), "%s", leaf);
        }
        *slash = 0;
    }
    return 0;
}

static int is_within(const char *root, const char *p)
{
    size_t n = strlen(root);
    return strcmp(root, p) == 0 || (strncmp(root, p, n) == 0 && p[n] == '/');
}

/* /dev/fd/N, /dev/std{in,out,err} alias the CALLER's descriptors: inside the
 * tracee they name the tracee's own fds, but realpath() here would bind them
 * to the WATCHER's /proc/self — classifying our tty where the tracee opened
 * its secret file. Parse the leading alias; rest receives the trailing
 * subpath ("" or "/sub"). Returns 1 when abs starts with an fd alias. */
static int dev_fd_alias(const char *abs, long *fd, const char **rest)
{
    if (strncmp(abs, "/dev/fd/", 8) == 0) {
        char *end;
        long v = strtol(abs + 8, &end, 10);
        if (end != abs + 8 && (*end == 0 || *end == '/')) {
            *fd = v;
            *rest = end;
            return 1;
        }
        return 0;
    }
    static const struct { const char *name; long fd; } stds[] = {
        { "/dev/stdin", 0 }, { "/dev/stdout", 1 }, { "/dev/stderr", 2 }
    };
    for (size_t i = 0; i < sizeof(stds) / sizeof(stds[0]); i++) {
        size_t l = strlen(stds[i].name);
        if (strncmp(abs, stds[i].name, l) == 0 &&
            (abs[l] == 0 || abs[l] == '/')) {
            *fd = stds[i].fd;
            *rest = abs + l;
            return 1;
        }
    }
    return 0;
}

/* ------------------------------------------------------------------ */
/* Tracee table                                                        */
/* ------------------------------------------------------------------ */

typedef struct {
    pid_t tid;
    pid_t tgid;
    int in_syscall;      /* next expected stop is a syscall-exit */
    int first_stop;      /* freshly auto-attached; resume without injection */
    int dead;
    int detached;        /* released by 'allow' but still supervised */
    int hold_sibs;       /* siblings stay frozen until this syscall exits */
    int pending_recv;    /* recvmsg-family nr awaiting exit-side cmsg check */
    uintptr_t recv_msghdr;
    int recv_vlen;
    pid_t paused_for;    /* owner tid whose freeze holds this thread, 0=free */
    int paused_confirmed;/* interrupt-stop for paused_for observed */
    pid_t files_id;      /* fd-table identity: shared across CLONE_FILES */
    unsigned long long clone_flags; /* clone/clone3 flags from its entry */
    int clone_flags_valid; /* clone_flags belongs to the in-flight syscall */
    long inflight_fds[8];/* fd bindings this in-flight syscall's gate read */
    char inflight_kind[8];/* parallel: 'f' path / 'n' non-file / 'c' closed */
    int inflight_nfds;
    int held_kind;       /* 0=free 1=rebind target range 2=fd allocator */
    long held_lo, held_hi; /* full target range for held_kind==1 */
    int exit_requeued;   /* exit stop already deferred once (test-only) */
    int inject_errno;    /* entry was skipped: its exit stop returns -errno */
} Tracee;

static Tracee g_tids[MAX_TIDS];
static int g_ntids;

static Tracee *tid_find(pid_t tid)
{
    for (int i = 0; i < g_ntids; i++)
        if (g_tids[i].tid == tid) return &g_tids[i];
    return NULL;
}

static pid_t tid_tgid(pid_t tid)
{
    char p[64];
    snprintf(p, sizeof(p), "/proc/%d/status", (int)tid);
    FILE *f = fopen(p, "r");
    if (!f) return tid;
    char line[256];
    pid_t tgid = tid;
    while (fgets(line, sizeof(line), f)) {
        if (strncmp(line, "Tgid:", 5) == 0) {
            tgid = (pid_t)atoi(line + 5);
            break;
        }
    }
    fclose(f);
    return tgid;
}

static Tracee *tid_register(pid_t tid)
{
    Tracee *t = tid_find(tid);
    if (t) return t;
    if (g_ntids >= MAX_TIDS) return NULL;
    t = &g_tids[g_ntids++];
    memset(t, 0, sizeof(*t));
    t->tid = tid;
    t->tgid = tid_tgid(tid);
    t->files_id = tid; /* own fd table until a CLONE_FILES link is seen */
    t->first_stop = 1;
    return t;
}

static int tgid_in_tree(pid_t pid)
{
    for (int i = 0; i < g_ntids; i++)
        if (!g_tids[i].dead && (g_tids[i].tgid == pid || g_tids[i].tid == pid))
            return 1;
    return 0;
}

/* ------------------------------------------------------------------ */
/* Tracee memory/register access                                       */
/* ------------------------------------------------------------------ */

static int get_regs(pid_t tid, struct user_regs_struct *r)
{
    struct iovec io = { r, sizeof(*r) };
    return ptrace(PTRACE_GETREGSET, tid, (void *)NT_PRSTATUS, &io);
}

static int set_regs(pid_t tid, struct user_regs_struct *r)
{
    struct iovec io = { r, sizeof(*r) };
    return ptrace(PTRACE_SETREGSET, tid, (void *)NT_PRSTATUS, &io);
}

static ssize_t tmem_read(pid_t tid, uintptr_t addr, void *buf, size_t len)
{
    struct iovec l = { buf, len };
    struct iovec r = { (void *)addr, len };
    return process_vm_readv(tid, &l, 1, &r, 1, 0);
}

/* Read a NUL-terminated string, bounded. Returns length or -1. */
static ssize_t tmem_str(pid_t tid, uintptr_t addr, char *out, size_t cap)
{
    size_t off = 0;
    while (off < cap) {
        char chunk[256];
        size_t want = cap - off > sizeof(chunk) ? sizeof(chunk) : cap - off;
        ssize_t n = tmem_read(tid, addr + off, chunk, want);
        if (n <= 0) break;
        for (ssize_t i = 0; i < n; i++) {
            if (chunk[i] == 0) {
                memcpy(out + off, chunk, (size_t)i);
                out[off + (size_t)i] = 0;
                return (ssize_t)(off + (size_t)i);
            }
        }
        memcpy(out + off, chunk, (size_t)n);
        off += (size_t)n;
    }
    if (cap) out[cap - 1] = 0;
    return off > 0 ? (ssize_t)off : -1;
}

static char *fd_target(pid_t tid, long fd, char *out, size_t cap)
{
    fd = (long)(int)fd; /* fd args are int: reg high bits may be garbage */
    if (fd < 0) return NULL;
    char link[128];
    snprintf(link, sizeof(link), "/proc/%d/fd/%ld", (int)tid, (long)fd);
    ssize_t n = readlink(link, out, cap - 1);
    /* Every caller reads this binding to decide whether the syscall is a
     * boundary — record the number even when the readlink fails: "closed
     * right now" is itself a mutable fact (a same-table allocator could
     * resurrect the slot before the syscall runs, so closed observations
     * coordinate fd-allocating syscalls too). */
    if (n < 0) { note_fd(fd, 'c'); return NULL; }
    out[n] = 0;
    size_t l = strlen(out);
    const char *del = " (deleted)";
    if (l > strlen(del) && strcmp(out + l - strlen(del), del) == 0)
        out[l - strlen(del)] = 0;
    note_fd(fd, out[0] == '/' ? 'f' : 'n');
    return out;
}

static char *cwd_of(pid_t tid, char *out, size_t cap)
{
    char link[64];
    snprintf(link, sizeof(link), "/proc/%d/cwd", (int)tid);
    ssize_t n = readlink(link, out, cap - 1);
    if (n < 0) return NULL;
    out[n] = 0;
    return out;
}

/* ------------------------------------------------------------------ */
/* Deferred stops + sibling pause (TOCTOU mitigation)                  */
/* ------------------------------------------------------------------ */

typedef struct { pid_t tid; int status; } Deferred;
static Deferred g_deferred[MAX_TIDS];
static int g_ndeferred;

static void defer_stop(pid_t tid, int status)
{
    if (g_ndeferred >= MAX_TIDS) return;
    g_deferred[g_ndeferred].tid = tid;
    g_deferred[g_ndeferred].status = status;
    g_ndeferred++;
}

/* Pop the first deferred stop whose tid is NOT currently frozen for
 * someone's gate. A still-owned tid must stay parked: replaying its stop
 * would restart it under the active freeze. Entries for paused tids wait
 * in place. Defined below (uses tid_find). */
static int defer_pop_ready(Deferred *out);
static int deferred_has(pid_t tid);

/* Pause every other live thread in tgid before a decision reads tracee
 * memory. Stops of other tids seen meanwhile are deferred and replayed by
 * the main loop after the decision lands.
 * Returns 0 when every sibling is confirmed stopped; -1 when at least one
 * could not be frozen — the caller must fail closed rather than check
 * tracee memory that a still-running thread can mutate. */
static int pause_siblings(pid_t tgid, pid_t keep)
{
    /* Test-only fail-injection: a payload can only ever DoS ITSELF with
     * this (denial direction), never widen a check. */
    if (getenv("BW_TEST_PAUSE_FAIL")) return -1;
    char dir[64];
    snprintf(dir, sizeof(dir), "/proc/%d/task", (int)tgid);
    DIR *d = opendir(dir);
    if (!d) return -1; /* cannot enumerate the writers: unverifiable */
    struct dirent *e;
    int wants = 0, failed = 0;
    while ((e = readdir(d))) {
        pid_t tid = (pid_t)atoi(e->d_name);
        if (tid <= 0 || tid == keep) continue;
        Tracee *t = tid_find(tid);
        if (!t) {
            /* A tid we have never seen is a just-cloned tracee whose
             * CLONE event is still queued — born stopped and unable to
             * run until its attach stop is consumed — or an unverifiable
             * writer. INTERRUPT converges the cases: a running tracee
             * stops and confirms below, a born-stopped one's pending
             * EVENT_STOP confirms it, ESRCH means the tid is gone (no
             * writer remains), and anything else fails closed. */
            if (ptrace(PTRACE_INTERRUPT, tid, 0, 0) != 0) {
                if (errno != ESRCH) {
                    if (getenv("BW_DEBUG"))
                        fprintf(stderr, "[bw] pause tgid=%d: tid=%d "
                                "untracked interrupt: %s\n",
                                (int)tgid, (int)tid, strerror(errno));
                    failed = 1;
                    break;
                }
                continue;
            }
            if (!(t = tid_register(tid))) { failed = 1; break; }
            t->paused_for = keep;
            t->paused_confirmed = 0;
            wants++;
            continue;
        }
        /* A tid we stopped at an fd-rebind hold, or whose real stop was
         * already consumed into the deferred queue, is verifiably frozen
         * (the replay cannot run before our gate finishes) — INTERRUPT
         * on either would confirm nothing and time out spuriously. */
        if (t->dead || t->paused_for || t->held_kind ||
            deferred_has(tid)) continue;
        if (ptrace(PTRACE_INTERRUPT, tid, 0, 0) == 0) {
            t->paused_for = keep;
            t->paused_confirmed = 0;
            wants++;
        } else if (errno != ESRCH) {
            if (getenv("BW_DEBUG"))
                fprintf(stderr, "[bw] pause tgid=%d: tid=%d interrupt: %s\n",
                        (int)tgid, (int)tid, strerror(errno));
            failed = 1; /* alive but not interruptible: unverifiable */
            break;
        }
        /* ESRCH: the tid vanished — no writer left to freeze. */
    }
    closedir(d);
    if (failed) return -1;
    if (getenv("BW_DEBUG") && wants)
        fprintf(stderr, "[bw] pause tgid=%d keep=%d wants=%d\n",
                (int)tgid, (int)keep, wants);
    for (int spins = 0; wants > 0 && spins < wants * 8 + 64; spins++) {
        if (g_term_signal) return -1;
        int st;
        pid_t p = waitpid(-1, &st, __WALL | WNOHANG);
        if (p <= 0) { usleep(500); continue; }
        Tracee *t = tid_find(p);
        /* A paused tid that exited instead of stopping is no longer a
         * writer: it cannot mutate the memory we are about to read. */
        if (t && t->paused_for && (WIFEXITED(st) || WIFSIGNALED(st))) {
            t->dead = 1;
            if (t->paused_for == keep && !t->paused_confirmed) {
                t->paused_confirmed = 1;
                wants--;
            }
            continue;
        }
        if (t && t->paused_for == keep && !t->paused_confirmed &&
            WIFSTOPPED(st)) {
            /* Frozen — either our interrupt-stop landed, or the tid was
             * already parked at a real stop when the interrupt arrived
             * (PTRACE_INTERRUPT returns success but delivers no event to
             * a stopped tracee). Either way it cannot run: confirm it,
             * and defer any REAL stop so the deferred replay — not an
             * early PTRACE_SYSCALL — delivers it after the freeze lifts. */
            t->paused_confirmed = 1;
            wants--;
            if (((st >> 16) & 0xffff) == PTRACE_EVENT_STOP)
                /* If this was the tid's attach stop, it is consumed now:
                 * leaving first_stop set would let the deferred/next
                 * entry stop resume it ungated. */
                t->first_stop = 0;
            else
                defer_stop(p, st);
            continue;
        }
        defer_stop(p, st);
    }
    if (wants && getenv("BW_DEBUG"))
        fprintf(stderr, "[bw] pause tgid=%d keep=%d TIMEOUT wants=%d\n",
                (int)tgid, (int)keep, wants);
    return wants ? -1 : 0;
}

static double bw_now(void);
/* Test-only sweep: move every pending tracee stop into the deferred
 * queue. Returns the number captured. Exits included — the replay path
 * marks dead/clears records/captures exit status, so deferring is only
 * ever more conservative, never a lost event. */
static int sweep_pending_to_deferred(void)
{
    int n = 0;
    for (;;) {
        int st;
        pid_t q = waitpid(-1, &st, __WALL | WNOHANG);
        if (q <= 0) break;
        if (getenv("BW_DEBUG"))
            fprintf(stderr, "[bw %.3f] defer tid=%d st=%x\n",
                    bw_now(), (int)q, st);
        defer_stop(q, st); /* replayed after the current processing */
        n++;
    }
    return n;
}

static int live_sibling_count(pid_t tgid, pid_t keep)
{
    int n = 0;
    for (int i = 0; i < g_ntids; i++) {
        Tracee *s = &g_tids[i];
        if (s->tgid != tgid || s->tid == keep || s->dead || s->detached)
            continue;
        n++;
    }
    return n;
}

/* Test-only: poll pending sibling stops into the deferred queue for the
 * whole configured window — a deferred stop replays (and is re-gated)
 * only after this decision lands and while the in-flight fd records are
 * still live, which lets fixtures exercise post-decision ordering
 * deterministically instead of racing waitpid's sibling iteration order.
 * A tid whose stop is deferred cannot run anyway, so draining changes
 * only WHEN it is observed, never what it observes; the window only
 * delays this tid longer and cannot widen a check. The same knob also
 * arms the exit-side sweep in handle_stop: an exiting consumer with live
 * in-flight records re-queues its own exit stop behind pending sibling
 * stops once, so a late-arriving rebind/allocator entry is still decided
 * before the records clear. */
static long g_pregate_delay_ms;
static void pregate_drain(void)
{
    double end = bw_now() + (double)g_pregate_delay_ms / 1000.0;
    if (getenv("BW_DEBUG"))
        fprintf(stderr, "[bw %.3f] drain-open (%.0fms)\n",
                bw_now(), end * 1000.0);
    for (;;) {
        int st;
        pid_t q = waitpid(-1, &st, __WALL | WNOHANG);
        if (q > 0) {
            /* Everything is deferred — exits included: the replay path
             * marks dead/clears records/captures exit status, so
             * deferring is only ever more conservative, never lost. */
            if (getenv("BW_DEBUG"))
                fprintf(stderr, "[bw %.3f] defer tid=%d st=%x\n",
                        bw_now(), (int)q, st);
            defer_stop(q, st); /* replayed after the gate completes */
            continue;
        }
        /* Poll for the whole window: later arrivals are just as eligible
         * for deferral, and sibling startup itself may be delayed by
         * earlier deferrals. */
        if (bw_now() >= end) break;
        usleep(1000);
    }
    if (getenv("BW_DEBUG"))
        fprintf(stderr, "[bw %.3f] drain-close\n", bw_now());
}

static int defer_pop_ready(Deferred *out)
{
    for (int i = 0; i < g_ndeferred; i++) {
        Tracee *t = tid_find(g_deferred[i].tid);
        if (t && (t->paused_for || t->held_kind)) continue;
        *out = g_deferred[i];
        memmove(&g_deferred[i], &g_deferred[i + 1],
                (size_t)(g_ndeferred - i - 1) * sizeof(*out));
        g_ndeferred--;
        return 1;
    }
    return 0;
}

/* Does tid have a consumed-but-not-yet-replayed stop? Such a tid must NOT
 * be restarted directly — the deferred replay delivers that stop through
 * handle_stop, which is what resumes it. */
static int deferred_has(pid_t tid)
{
    for (int i = 0; i < g_ndeferred; i++)
        if (g_deferred[i].tid == tid) return 1;
    return 0;
}

/* Release only the threads frozen for <owner>: two threads of the same
 * tgid can each hold an overlapping freeze for separate gated syscalls,
 * and one syscall completing must not drop the other's freeze early. */
static void resume_paused_siblings(pid_t tgid, pid_t owner)
{
    for (int i = 0; i < g_ntids; i++) {
        Tracee *t = &g_tids[i];
        if (t->tgid == tgid && t->paused_for == owner) {
            t->paused_for = 0;
            t->paused_confirmed = 0;
            if (!deferred_has(t->tid))
                ptrace(PTRACE_SYSCALL, t->tid, 0, 0);
            /* else: the pending deferred stop will restart it on replay */
        }
    }
}

/* ------------------------------------------------------------------ */
/* In-flight fd binding protection                                     */
/* ------------------------------------------------------------------ */

/* Syscalls that install a NEW fd into the lowest eligible free slot can
 * resurrect a slot whose closed state an in-flight syscall's gate just
 * relied on (fd observed closed -> PASS, then a same-table open/dup lands
 * a real file in it before execution). Held only while such a closed
 * observation is actually in flight — and only within the same shared fd
 * table, so ordinary allocation is unaffected. dup2/dup3 are NOT here:
 * they rebind a named slot and are covered by the rebind path. */
static int nr_allocates_fd(long nr, const struct user_regs_struct *r)
{
    switch (nr) {
    case 2: case 85: case 257: case 437:               /* open/creat/openat/openat2 */
    case 32:                                            /* dup */
    case 22: case 293:                                  /* pipe/pipe2 */
    case 41: case 43: case 288:                         /* socket/accept/accept4 */
    case 53:                                            /* socketpair */
    case 282: case 289:                                 /* signalfd/signalfd4 */
    case 283:                                           /* timerfd_create */
    case 284: case 290:                                 /* eventfd/eventfd2 */
    case 213: case 291:                                 /* epoll_create/create1 */
    case 253: case 294:                                 /* inotify_init/init1 */
    case 300: case 304:                                 /* fanotify_init/open_by_handle_at */
    case 323:                                           /* userfaultfd */
    case 319:                                           /* memfd_create */
    case 434: case 438:                                 /* pidfd_open/getfd */
    case 47: case 299:                                  /* recvmsg/recvmmsg (SCM_RIGHTS install) */
    case 240:                                           /* mq_open */
    case 428: case 430: case 432: case 433:             /* open_tree/fsopen/fsmount/fspick */
    case 444: case 447:                                 /* landlock_ruleset/memfd_secret */
        return 1;
    case 72:                                            /* fcntl */
        return r->rsi == 0 /*F_DUPFD*/ || r->rsi == 1030 /*F_DUPFD_CLOEXEC*/;
    default:
        return 0;
    }
}

/* Classify the entry stop: 0 pass, 1 = it rebinds an fd NUMBER that is
 * in flight (close / dup2,dup3 newfd / close_range range), 2 = it may
 * allocate a fd while a CLOSED-slot observation is in flight. The full
 * target range is kept so release can retest the whole request. */
static int fd_hold_class(long nr, const struct user_regs_struct *r,
                         long *lo, long *hi)
{
    switch (nr) {
    case 3:   *lo = *hi = (long)(int)r->rdi; return 1;      /* close */
    case 33: case 292: *lo = *hi = (long)(int)r->rsi; return 1; /* dup2/3 */
    case 436:                                                /* close_range */
        *lo = (long)(unsigned int)r->rdi;
        *hi = (long)(unsigned int)r->rsi;
        return 1;
    default:
        return nr_allocates_fd(nr, r) ? 2 : 0;
    }
}

static int fd_hold_conflict(const Tracee *self, int kind, long lo, long hi)
{
    if (kind == 1 && (lo < 0 || hi < lo)) return 0;
    for (int i = 0; i < g_ntids; i++) {
        const Tracee *o = &g_tids[i];
        if (o == self || o->dead || o->detached) continue;
        if (o->files_id != self->files_id) {
            if (getenv("BW_DEBUG") && o->inflight_nfds)
                fprintf(stderr, "[bw] holdtest tid=%d files=%d nfds=%d "
                        "!= self %d\n", (int)o->tid, (int)o->files_id,
                        o->inflight_nfds, (int)self->files_id);
            continue;
        }
        for (int j = 0; j < o->inflight_nfds; j++) {
            if (kind == 1) {
                if (o->inflight_fds[j] >= lo && o->inflight_fds[j] <= hi)
                    return 1;
            } else if (o->inflight_kind[j] == 'c') {
                return 1; /* any live closed observation stalls allocators */
            }
        }
    }
    return 0;
}

/* A released held tid still sits AT ITS ENTRY STOP: re-drive the full
 * entry gate for it instead of a bare restart, or a held boundary syscall
 * (e.g. an openat that conflicted with a closed-slot observation) would
 * execute unchecked. Filled in after the gate helpers exist. */
static int entry_gate(Tracee *t, int *exit_code);
static int g_detached;

/* An in-flight binding record cleared — retest every held syscall: the
 * held request may resume only when NO in-flight entry conflicts with
 * its full recorded range/allocation kind anymore. */
static void release_fd_holds(void)
{
    if (getenv("BW_DEBUG"))
        fprintf(stderr, "[bw %.3f] release-scan\n", bw_now());
    for (int i = 0; i < g_ntids; i++) {
        Tracee *t = &g_tids[i];
        if (!t->held_kind || t->dead || t->detached) continue;
        if (fd_hold_conflict(t, t->held_kind, t->held_lo, t->held_hi)) {
            if (getenv("BW_DEBUG"))
                fprintf(stderr, "[bw] keep-held tid=%d kind=%d "
                        "lo=%ld hi=%ld\n", (int)t->tid, t->held_kind,
                        t->held_lo, t->held_hi);
            continue;
        }
        if (getenv("BW_DEBUG"))
            fprintf(stderr, "[bw] release-held tid=%d\n", (int)t->tid);
        t->held_kind = 0;
        /* A tid with a deferred stop pending cannot run anyway — its real
         * stop replays later and reaches the gate path on its own. */
        if (!deferred_has(t->tid)) {
            int scratch = 0;
            if (entry_gate(t, &scratch) == RC_DETACHED)
                g_detached = 1;
        }
    }
}

static void clear_inflight(Tracee *t)
{
    if (t->inflight_nfds) {
        t->inflight_nfds = 0;
        release_fd_holds();
    }
}

/* ------------------------------------------------------------------ */
/* Boundary classification                                             */
/* ------------------------------------------------------------------ */

static const char *path_base(const char *p)
{
    const char *s = strrchr(p, '/');
    return s ? s + 1 : p;
}

static int path_in_roots(const char *p)
{
    for (int i = 0; i < g_nroots; i++)
        if (is_within(g_roots[i], p)) return 1;
    return 0;
}

static int path_in_list(char **list, int n, const char *p)
{
    for (int i = 0; i < n; i++)
        if (is_within(list[i], p)) return 1;
    return 0;
}

/* Credential-class read targets: .env names, key-file suffixes, ~/.ssh
 * private keys. Logs/history/config/known_hosts are deliberately NOT here. */
static int credential_path(const char *p)
{
    const char *b = path_base(p);
    size_t bl = strlen(b);
    if (strcmp(b, ".env") == 0) return 1;
    if (bl > 4 && strcmp(b + bl - 4, ".env") == 0) return 1;
    static const char *exts[] = { ".pem", ".key", ".p12", ".pfx", ".p8" };
    for (size_t i = 0; i < sizeof(exts) / sizeof(exts[0]); i++) {
        size_t el = strlen(exts[i]);
        if (bl > el && strcasecmp(b + bl - el, exts[i]) == 0) return 1;
    }
    if (strncmp(b, "id_", 3) == 0 && bl > 4 && strstr(b, ".pub") == NULL) {
        char dir[PATH_MAX];
        snprintf(dir, sizeof(dir), "%s", p);
        char *s = strrchr(dir, '/');
        if (s) {
            *s = 0;
            if (strcmp(path_base(dir), ".ssh") == 0) return 1;
        }
    }
    return 0;
}

/* /proc/<pid>/... access checks. pid_out receives the parsed pid or 0.
 * Returns: 2 = watcher self-introspection (token/broker fd live there),
 *          1 = boundary event (otherpid sensitive objects),
 *          0 = fine. */
static int proc_check(const char *path, pid_t *pid_out)
{
    *pid_out = 0;
    if (strncmp(path, "/proc/", 6) != 0) return 0;
    const char *s = path + 6;
    if (!(*s >= '0' && *s <= '9')) return 0;
    char *end;
    long pid = strtol(s, &end, 10);
    if (end == s) { *pid_out = (pid_t)pid; return 0; }
    *pid_out = (pid_t)pid;
    if (*end != '/') return 0;
    if (pid == g_self_pid) return 2;
    if (tgid_in_tree((pid_t)pid)) return 0;
    static const char *sens[] = {
        "/mem", "/environ", "/fd", "/fdinfo", "/map_files"
    };
    for (size_t i = 0; i < sizeof(sens) / sizeof(sens[0]); i++)
        if (strncmp(end, sens[i], strlen(sens[i])) == 0) return 1;
    return 0;
}

/* ------------------------------------------------------------------ */
/* Broker channel                                                      */
/* ------------------------------------------------------------------ */

static unsigned long g_event_id;
static char g_deny_reason[240]; /* broker 'reason' carried to the kill text */
static int g_at_exit_stop;      /* decision made at a syscall-EXIT check */

static void json_escape(const char *in, char *out, size_t cap)
{
    size_t o = 0;
    for (const unsigned char *p = (const unsigned char *)in; *p && o + 8 < cap; p++) {
        if (*p == '"' || *p == '\\') { out[o++] = '\\'; out[o++] = (char)*p; }
        else if (*p == '\n') { out[o++] = '\\'; out[o++] = 'n'; }
        else if (*p == '\r') { out[o++] = '\\'; out[o++] = 'r'; }
        else if (*p == '\t') { out[o++] = '\\'; out[o++] = 't'; }
        else if (*p < 0x20) { o += (size_t)snprintf(out + o, cap - o, "\\u%04x", *p); }
        else out[o++] = (char)*p;
    }
    out[o] = 0;
}

typedef struct {
    const char *path;
    int nofollow; /* path resolved NOFOLLOW-last: stat the link itself */
} Target;

/* ------------------------------------------------------------------ */
/* Cache-relevant context: cwd / executable / argv                     */
/* ------------------------------------------------------------------ */

/* Read the tracee's argv: from the execve argument vector when argv_ptr is
 * nonzero (exec events), else /proc/<tgid>/cmdline. Emits a JSON array of
 * strings. Returns bytes written (without the trailing NUL), or -1 when
 * argv could not be captured completely (caller sets argvIncomplete). */
static ssize_t argv_json(Tracee *t, uintptr_t argv_ptr, char *out, size_t cap)
{
    size_t off = 0;
    int narg = 0;
    out[off++] = '[';
    if (argv_ptr) {
        for (int i = 0; i < 256; i++) {
            uintptr_t ap;
            if (tmem_read(t->tid, argv_ptr + i * 8, &ap, 8) != 8) break;
            if (!ap) break;
            char arg[4096];
            if (tmem_str(t->tid, ap, arg, sizeof(arg)) < 0) break;
            char esc[8192];
            json_escape(arg, esc, sizeof(esc));
            if (off + strlen(esc) + 4 >= cap) return -1;
            off += snprintf(out + off, cap - off, "%s\"%s\"",
                            narg++ ? "," : "", esc);
        }
    } else {
        char p[64];
        snprintf(p, sizeof(p), "/proc/%d/cmdline", (int)t->tgid);
        FILE *f = fopen(p, "rb");
        if (!f) return -1;
        char buf[8192], *cur = buf;
        size_t total = fread(buf, 1, sizeof(buf) - 1, f);
        int more = !feof(f);
        fclose(f);
        buf[total] = 0;
        while (cur < buf + total) {
            size_t l = strlen(cur);
            char esc[16384];
            json_escape(cur, esc, sizeof(esc));
            if (off + strlen(esc) + 4 >= cap) return -1;
            off += snprintf(out + off, cap - off, "%s\"%s\"",
                            narg++ ? "," : "", esc);
            cur += l + 1;
        }
        if (more) return -1; /* cmdline truncated by our read cap */
    }
    if (off + 2 >= cap) return -1;
    out[off++] = ']';
    out[off] = 0;
    return (ssize_t)off;
}

/* Gather the decision-relevant tracee context as a JSON fragment:
 *   "cwd":"<canonical>","executable":"<canonical>","argv":[...]
 * On argv capture failure emits "argvIncomplete":true and returns 1 so the
 * caller can force requiresFullApproval (a partial argv must never reach a
 * cache keyed on complete argv). */
static int cred_context(Tracee *t, uintptr_t argv_ptr,
                        char *out, size_t cap)
{
    char cwd[PATH_MAX], esc[PATH_MAX * 2];
    int off = 0;
    if (cwd_of(t->tid, cwd, sizeof(cwd))) {
        char canon[PATH_MAX];
        const char *c = canon_path(cwd, canon) ? canon : cwd;
        json_escape(c, esc, sizeof(esc));
        off += snprintf(out + off, cap - off, "\"cwd\":\"%s\"", esc);
    } else {
        off += snprintf(out + off, cap - off, "\"cwd\":null");
    }
    char link[64], raw[PATH_MAX];
    snprintf(link, sizeof(link), "/proc/%d/exe", (int)t->tgid);
    ssize_t n = readlink(link, raw, sizeof(raw) - 1);
    if (n > 0) {
        raw[n] = 0;
        size_t l = strlen(raw);
        const char *del = " (deleted)";
        if (l > strlen(del) && strcmp(raw + l - strlen(del), del) == 0)
            raw[l - strlen(del)] = 0;
        char canon[PATH_MAX];
        const char *c = canon_path(raw, canon) ? canon : raw;
        json_escape(c, esc, sizeof(esc));
        off += snprintf(out + off, cap - off, ",\"executable\":\"%s\"", esc);
    } else {
        off += snprintf(out + off, cap - off, ",\"executable\":null");
    }
    static char aj[48 * 1024];
    if (argv_ptr) g_gate_used_mutable = 1; /* argv read from tracee memory */
    ssize_t an = argv_json(t, argv_ptr, aj, sizeof(aj));
    if (an < 0) {
        off += snprintf(out + off, cap - off, ",\"argvIncomplete\":true");
        return off > 0 ? 1 : -1;
    }
    off += snprintf(out + off, cap - off, ",\"argv\":%s", aj);
    return 0;
}

/* Emit one boundary event and return the broker action:
 *   0 = 'continue', 1 = 'allow', -1 = explicit 'deny' reply,
 *  -2 = review did not complete (timeout / EOF / malformed / oversized /
 *      'continue' on a full-approval event — an infra failure, not a
 *      verdict).
 * argv_ptr is the tracee's execve argv for exec events, 0 otherwise (the
 * current /proc/<tgid>/cmdline is used then). */
static int is_cancel_frame(const char *line)
{
    char compact[512];
    size_t off = 0;
    int quoted = 0, escaped = 0;
    for (const char *p = line; *p; p++) {
        if (!quoted && isspace((unsigned char)*p)) continue;
        if (off + 1 >= sizeof(compact)) return 0;
        compact[off++] = *p;
        if (escaped) escaped = 0;
        else if (quoted && *p == '\\') escaped = 1;
        else if (*p == '"') quoted = !quoted;
    }
    compact[off] = 0;
    return strcmp(compact, "{\"version\":1,\"type\":\"cancel\"}") == 0 ||
           strcmp(compact, "{\"type\":\"cancel\",\"version\":1}") == 0;
}

static int broker_decide_argv(Tracee *t, const char *syscall, const char *kind,
                              const char *op, Target *targets, int ntargets,
                              const char *details, int full_approval,
                              uintptr_t argv_ptr)
{
    static char body[MAX_JSON];
    int off = snprintf(body, sizeof(body),
        "{\"version\":1,\"type\":\"boundary\",\"token\":\"%s\",\"eventID\":%lu,"
        "\"pid\":%ld,\"syscall\":\"%s\",\"kind\":\"%s\",\"operation\":\"%s\",\"targets\":[",
        g_token, ++g_event_id, (long)t->tgid, syscall, kind, op);
    for (int i = 0; i < ntargets && off > 0 && off < (int)sizeof(body) - 4096; i++) {
        char esc[PATH_MAX * 2];
        json_escape(targets[i].path ? targets[i].path : "?", esc, sizeof(esc));
        struct stat st;
        /* lstat for link-operating ops: the reported identity must be the
         * entry being renamed/unlinked/created, not its referent. */
        int exists = targets[i].path &&
            (targets[i].nofollow ? lstat(targets[i].path, &st)
                                 : stat(targets[i].path, &st)) == 0;
        int inspection_errno = exists ? 0 : errno;
        off += snprintf(body + off, sizeof(body) - (size_t)off, "%s{\"path\":\"%s\",\"exists\":%s",
                        i ? "," : "", esc, exists ? "true" : "false");
        if (!exists && inspection_errno != ENOENT && inspection_errno != ENOTDIR)
            off += snprintf(body + off, sizeof(body) - (size_t)off,
                            ",\"inspectionError\":\"%s\"", strerrorname_np(inspection_errno) ?: "EUNKNOWN");
        if (off > 0 && exists) {
            off += snprintf(body + off, sizeof(body) - (size_t)off,
                            ",\"dev\":\"%llu\",\"ino\":\"%llu\",\"mode\":\"%u\"",
                            (unsigned long long)st.st_dev,
                            (unsigned long long)st.st_ino,
                            (unsigned)(st.st_mode & 07777));
        }
        if (off > 0) {
            /* Parent identity is emitted for missing objects too: the
             * broker binds create grants to the containing directory. */
            char parent[PATH_MAX];
            snprintf(parent, sizeof(parent), "%s", targets[i].path);
            char *sl = strrchr(parent, '/');
            if (sl && sl != parent) *sl = 0; else strcpy(parent, "/");
            struct stat pst;
            if (stat(parent, &pst) == 0)
                off += snprintf(body + off, sizeof(body) - (size_t)off,
                                ",\"parentDev\":\"%llu\",\"parentIno\":\"%llu\"",
                                (unsigned long long)pst.st_dev, (unsigned long long)pst.st_ino);
        }
        if (off > 0) off += snprintf(body + off, sizeof(body) - (size_t)off, "}");
    }
    static char ctx[56 * 1024];
    int cincomplete = cred_context(t, argv_ptr, ctx, sizeof(ctx));
    if (cincomplete) full_approval = 1;
    if (off < 0) return -2;
    off += snprintf(body + off, sizeof(body) - (size_t)off,
                    "],\"details\":{\"requiresFullApproval\":%s%s%s%s,%s}}\n",
                    full_approval ? "true" : "false",
                    details && *details ? "," : "",
                    details && *details ? details : "",
                    /* Test-only: emit a pre-protocol event with atExit
                     * absent, so the broker's unknown-phase path is
                     * exercised. Real helpers always send the field. */
                    getenv("BW_TEST_OMIT_ATEXIT") ? ""
                        : g_at_exit_stop ? ",\"atExit\":true"
                                         : ",\"atExit\":false",
                    ctx);
    if (off <= 0 || off >= (int)sizeof(body) ||
        write_all(g_broker_fd, body, (size_t)off) < 0)
        return -2;

    /* Read one NDJSON reply within the approval deadline. */
    static char line[MAX_JSON];
    size_t llen = 0;
    struct timespec t0, t1;
    clock_gettime(CLOCK_MONOTONIC, &t0);
    for (;;) {
        clock_gettime(CLOCK_MONOTONIC, &t1);
        long long elapsed = (t1.tv_sec - t0.tv_sec) * 1000LL +
                            (t1.tv_nsec - t0.tv_nsec) / 1000000LL;
        long rem = g_approve_timeout_ms - (long)elapsed;
        if (rem <= 0 || g_term_signal) return -2;
        struct pollfd pfd = { g_broker_fd, POLLIN, 0 };
        int pr = poll(&pfd, 1, rem > 1000 ? 1000 : (int)rem);
        if (pr < 0) { if (errno == EINTR) continue; return -2; }
        if (pr == 0) continue;
        if (!(pfd.revents & POLLIN)) return -2; /* EOF/HUP/ERR: fail closed */
        char c;
        ssize_t n = read(g_broker_fd, &c, 1);
        if (n <= 0) return -2;
        if (c == '\n') {
            if (llen == 0) continue;
            line[llen] = 0;
            break;
        }
        if (llen + 1 >= sizeof(line)) return -2;
        line[llen++] = c;
    }
    if (!strstr(line, "\"version\":1") && !strstr(line, "\"version\": 1"))
        return -2;
    if (is_cancel_frame(line)) return -3;
    const char *eid = strstr(line, "\"eventID\"");
    if (!eid || !(eid = strchr(eid, ':'))) return -2;
    if (strtoul(eid + 1, NULL, 10) != g_event_id) return -2;
    const char *act = strstr(line, "\"action\"");
    if (!act || !(act = strchr(act, ':'))) return -2;
    act++;
    while (*act == ' ' || *act == '\t') act++;
    char action[16] = "";
    if (*act == '"') {
        const char *e = strchr(act + 1, '"');
        if (!e || (size_t)(e - act - 1) >= sizeof(action)) return -2;
        memcpy(action, act + 1, (size_t)(e - act - 1));
    }
    if (strcmp(action, "allow") == 0) return 1;
    if (strcmp(action, "deny") == 0) {
        /* Carry the broker's reason into the block message when present —
         * bounded and flattened (no quotes/newlines/controls through). */
        const char *rs = strstr(line, "\"reason\"");
        if (rs && (rs = strchr(rs, ':')) && *++rs) {
            while (*rs == ' ' || *rs == '\t') rs++;
            if (*rs == '"') {
                const char *e = strchr(rs + 1, '"');
                size_t n = e ? (size_t)(e - rs - 1) : 0;
                if (n > 0 && n < sizeof(g_deny_reason) - 4) {
                    size_t o = 0;
                    for (size_t i = 0; i < n; i++) {
                        unsigned char c = (unsigned char)rs[1 + i];
                        g_deny_reason[o++] = (c >= 0x20 && c != '"' && c != '\\')
                                             ? (char)c : ' ';
                    }
                    g_deny_reason[o] = 0;
                }
            }
        }
        return -1;
    }
    if (strcmp(action, "continue") == 0) return full_approval ? -2 : 0;
    return -2; /* anything else: malformed, fail closed */
}

static int broker_decide(Tracee *t, const char *syscall, const char *kind,
                         const char *op, Target *targets, int ntargets,
                         const char *details, int full_approval)
{
    return broker_decide_argv(t, syscall, kind, op, targets, ntargets,
                              details, full_approval, 0);
}

/* Terminal frame: emitted exactly once after the payload's final exit and
 * before the channel closes, so the broker can retire the call without
 * polling. 'exit' is the real 0..255 code; 128+sig for killed payloads. */
static void broker_send_exit(int code)
{
    if (g_broker_fd < 0) return;
    char b[160];
    int n = snprintf(b, sizeof(b),
        "{\"version\":1,\"type\":\"exit\",\"token\":\"%s\",\"exit\":%d}\n",
        g_token, code & 0xff);
    if (n > 0) write_all(g_broker_fd, b, (size_t)n);
}

/* Only a fixed code is reported: setup errors may contain sensitive paths.
 * The payload has not executed yet, so discard the stopped bootstrap child
 * and exec the original payload once, restoring its deferred environment. */
static void setup_fail_open(void)
{
    if (g_root_pid > 0) {
        kill(g_root_pid, SIGKILL);
        int st;
        while (waitpid(g_root_pid, &st, __WALL) > 0) {
            if (WIFEXITED(st) || WIFSIGNALED(st)) break;
            ptrace(PTRACE_CONT, g_root_pid, 0, 0);
        }
    }
    if (g_broker_fd < 0 && g_broker_path) {
        struct sockaddr_un sa;
        memset(&sa, 0, sizeof(sa));
        sa.sun_family = AF_UNIX;
        if (strlen(g_broker_path) < sizeof(sa.sun_path)) {
            snprintf(sa.sun_path, sizeof(sa.sun_path), "%s", g_broker_path);
            g_broker_fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
            if (g_broker_fd >= 0)
                connect(g_broker_fd, (struct sockaddr *)&sa, sizeof(sa));
        }
    }
    char frame[180];
    int n = snprintf(frame, sizeof(frame),
        "{\"version\":1,\"type\":\"fail_open\",\"token\":\"%s\",\"code\":\"observer_setup\"}\n", g_token);
    if (g_broker_fd >= 0) write_all(g_broker_fd, frame, (size_t)n);
    for (int i = 0; i < g_ndefer; i++) {
        const char *value = getenv(g_defer_store[i]);
        if (value) setenv(g_defer_real[i], value, 1);
        unsetenv(g_defer_store[i]);
    }
    sigset_t mask;
    sigemptyset(&mask);
    sigprocmask(SIG_SETMASK, &mask, NULL);
    signal(SIGTERM, SIG_DFL);
    signal(SIGINT, SIG_DFL);
    signal(SIGHUP, SIG_DFL);
    execv(g_payload_argv[0], g_payload_argv);
    _exit(127); /* The payload's own exec failure, not a plugin refusal. */
}

/* ------------------------------------------------------------------ */
/* Tree actions                                                        */
/* ------------------------------------------------------------------ */

/* SIGKILL every payload descendant — traced, already-detached and orphaned
 * grandchildren alike — then reap until no children remain. Tracees hit a
 * PTRACE_EVENT_EXIT stop before dying, so every stopped tid must be
 * restarted for the kill to complete; a plain reap loop deadlocks. */
static void kill_everything(void)
{
    /* Payload runs in its own process group (spawn does setpgid): nuke the
     * group first, then per-tgid SIGKILL — catches traced tracees whose
     * group changed (setsid/setpgid) and detached survivors alike. */
    if (g_root_pid > 0) kill(-g_root_pid, SIGKILL); /* pgid 0 == our own! */
    for (int i = 0; i < g_ntids; i++)
        if (!g_tids[i].dead) kill(g_tids[i].tgid, SIGKILL);
    /* The watcher is a child subreaper: grandchildren orphaned by the kills
     * above reparent here instead of escaping to init. Loop: release any
     * stopped tracee so it can die, reap what is dead, then kill every pid
     * that calls us parent — until nothing is left. */
    for (int rounds = 0; rounds < 400; rounds++) {
        int progressed = 0, st;
        pid_t p;
        while ((p = waitpid(-1, &st, __WALL | WNOHANG)) > 0) {
            progressed = 1;
            if (WIFSTOPPED(st))
                ptrace(PTRACE_SYSCALL, p, 0, 0); /* release exit-stops */
        }
        if (p < 0 && errno == EINTR) continue;
        if (p < 0 && !progressed) break; /* ECHILD: nothing remains */
        /* Scan for children that reparented to us and are still alive. */
        DIR *pd = opendir("/proc");
        if (pd) {
            struct dirent *e;
            while ((e = readdir(pd))) {
                if (e->d_name[0] < '0' || e->d_name[0] > '9') continue;
                pid_t cp = (pid_t)atoi(e->d_name);
                if (cp <= 0) continue;
                char sf[64], line[256];
                snprintf(sf, sizeof(sf), "/proc/%d/stat", (int)cp);
                FILE *f = fopen(sf, "r");
                if (!f) continue;
                if (fgets(line, sizeof(line), f)) {
                    char *rp = strrchr(line, ')'); /* ppid is field 4 */
                    if (rp && atoi(rp + 4) == (int)g_self_pid) {
                        kill(cp, SIGKILL);
                        progressed = 1;
                    }
                }
                fclose(f);
            }
            closedir(pd);
        }
        if (!progressed) usleep(2000);
    }
}

/* Deny/cancel teardown: kill the whole tree, report the truthful exit code
 * to the broker (only a genuine exit 0 may update the background cache —
 * on a broker-EOF path the channel is dead and the write simply fails),
 * then exit with the canonical blocked message.
 *
 * op_blocked distinguishes the two honest wordings: only an ENTRY-gate
 * denial may claim the boundary operation was not performed; a kill during
 * or after the operation must not. */
static void kill_tree(const char *msg, int op_blocked)
{
    kill_everything();
    broker_send_exit(128 + SIGKILL);
    fprintf(stderr, "Command blocked: %s. %s; earlier steps may already "
            "have run. Do not automatically rerun the whole command.\n",
            msg, op_blocked ? "The boundary operation was not performed"
                            : "The command was stopped");
    exit(126);
}

/* 'allow': detach every live tracee. Detached != dead: entries stay in the
 * table so a later cancel (broker EOF) still kills them — per-pid SIGKILL
 * reaches them even after setsid escapes the payload's process group, and
 * the main loop keeps running until no children remain.
 *
 * PTRACE_DETACH only succeeds on a stopped tracee: RUNNING siblings must be
 * PTRACE_INTERRUPT-ed first, their interrupt-stop awaited, then detached.
 * SIGCONT is injected on every detach — the spawn-time raise(SIGSTOP) leaves
 * a lingering job-control group-stop that silently re-engages once a tid is
 * no longer ptraced (observed: payload stranded in 'T' forever). */
static int g_root_reaped_exit = -1; /* exit code if root was reaped here */
static void detach_all(void)
{
    int pending = 0;
    for (int i = 0; i < g_ntids; i++) {
        Tracee *t = &g_tids[i];
        if (t->dead || t->detached) continue;
        if (ptrace(PTRACE_DETACH, t->tid, 0, (void *)(long)SIGCONT) == 0) {
            t->detached = 1; /* supervised, no longer traced */
            continue;
        }
        /* Not stopped (running or just died): interrupt and retry once the
         * stop lands below. */
        if (ptrace(PTRACE_INTERRUPT, t->tid, 0, 0) == 0)
            pending++;
        else
            t->dead = 1; /* ESRCH: already gone */
    }
    int spins = 0;
    while (pending > 0 && spins++ < MAX_TIDS * 4 + 64) {
        if (g_term_signal)
            kill_tree("the supervisor was terminated (cancelled)", 0);
        int st;
        pid_t p = waitpid(-1, &st, __WALL | WNOHANG);
        if (p <= 0) { usleep(200); continue; }
        Tracee *t = tid_find(p);
        if (!t || t->dead) {
            /* Stops of tids we never tracked can't happen here (all live
             * tids got INTERRUPT or were detached), but if the waitpid
             * report belongs to an already-detached tid it is an exit —
             * remember a root exit so the caller can finish correctly. */
            if (p == g_root_pid && (WIFEXITED(st) || WIFSIGNALED(st)))
                g_root_reaped_exit = WIFEXITED(st) ? WEXITSTATUS(st)
                                                 : 128 + WTERMSIG(st);
            continue;
        }
        if (WIFEXITED(st) || WIFSIGNALED(st)) {
            t->dead = 1;
            pending--;
            if (p == g_root_pid)
                g_root_reaped_exit = WIFEXITED(st) ? WEXITSTATUS(st)
                                                 : 128 + WTERMSIG(st);
            continue;
        }
        /* Whatever stop arrived (interrupt-stop, syscall-stop, signal-stop
         * or an event), detach with SIGCONT: for non-stop signals forward
         * the signal so nothing is swallowed. */
        int sig = WSTOPSIG(st);
        int ev = (st >> 16) & 0xffff;
        long data = ev ? SIGCONT : (sig == SIGTRAP ? SIGCONT : sig);
        ptrace(PTRACE_DETACH, p, 0, (void *)data);
        t->detached = 1; /* still supervised: killable on cancel */
        pending--;
    }
}

static struct timespec g_t0;
static double bw_now(void)
{
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return (t.tv_sec - g_t0.tv_sec) + (t.tv_nsec - g_t0.tv_nsec) / 1e9;
}

/* ------------------------------------------------------------------ */
/* Path resolution                                                     */
/* ------------------------------------------------------------------ */

static int resolve_at(pid_t tid, long dirfd, uintptr_t pathptr, char *out)
{
    dirfd = (long)(int)dirfd; /* fd args are int: reg high bits may be 0 */
    if (!pathptr) return 0;
    char rel[PATH_MAX];
    ssize_t rl = tmem_str(tid, pathptr, rel, sizeof(rel));
    if (getenv("BW_DEBUG"))
        fprintf(stderr, "[bw] resolve tid=%d dirfd=%ld ptr=%llx -> rl=%zd '%s'\n",
                (int)tid, dirfd, (unsigned long long)pathptr, rl, rl >= 0 ? rel : "!");
    if (rl < 0) return 0;
    g_gate_used_mutable = 1;
    char abs[PATH_MAX * 2];
    if (rel[0] == '/') {
        snprintf(abs, sizeof(abs), "%s", rel);
    } else {
        char base[PATH_MAX];
        if (dirfd == AT_FDCWD) {
            if (!cwd_of(tid, base, sizeof(base))) return 0;
        } else {
            if (!fd_target(tid, dirfd, base, sizeof(base)) || base[0] != '/')
                return 0;
        }
        snprintf(abs, sizeof(abs), "%s/%s", base, rel);
    }
    /* /dev/fd/N and /dev/std* name the TRACEE's descriptors — resolve the
     * alias to the real object before anything else, or realpath binds it
     * to the watcher's own fds. */
    {
        long afd;
        const char *arest;
        if (dev_fd_alias(abs, &afd, &arest)) {
            char tgt[PATH_MAX];
            if (!fd_target(tid, afd, tgt, sizeof(tgt)) || tgt[0] != '/')
                return 0; /* pipe/socket/anon fd: no filesystem boundary */
            char real[PATH_MAX * 2];
            snprintf(real, sizeof(real), "%s%s", tgt, arest);
            snprintf(abs, sizeof(abs), "%s", real);
        }
    }
    /* No lexical '..' folding BEFORE resolution: the kernel resolves '..' in
     * the real directory reached after following symlinks, so
     * 'a/link/../f' and 'a/f' can be different objects. canon_path realpaths
     * the deepest existing ancestor in traversal order — the same order the
     * kernel uses. */
    /* /proc self-referring entries must resolve against the TRACEE, not
     * against this watcher: /proc/self, /proc/thread-self and the procfs
     * magic symlinks /proc/mounts (self/mounts) and /proc/net (self/net).
     * realpath() here would bind them to OUR pid and every benign procfs
     * read would look like watcher introspection. */
    char sub[PATH_MAX];
    const char *n = abs;
    pid_t subpid = 0;
    size_t pl = 0;
    static const char *self_aliases[] = {
        "/proc/self", "/proc/thread-self", "/proc/mounts", "/proc/net"
    };
    for (size_t ai = 0; ai < sizeof(self_aliases) / sizeof(self_aliases[0]); ai++) {
        size_t al = strlen(self_aliases[ai]);
        if (strncmp(abs, self_aliases[ai], al) == 0 &&
            (abs[al] == '/' || abs[al] == 0)) {
            pl = al;
            subpid = strcmp(self_aliases[ai], "/proc/thread-self") == 0
                     ? tid : tid_tgid(tid);
            break;
        }
    }
    if (subpid) {
        snprintf(sub, sizeof(sub), "/proc/%d%s", (int)subpid, abs + pl);
        n = sub;
    }
    if (canon_path(n, out)) return 1;
    snprintf(out, PATH_MAX, "%.*s", PATH_MAX - 1, n);
    return 1;
}

/* NOFOLLOW-last resolution: canonicalize the parent directory, keep the
 * basename lexical. unlink/rename/rmdir/lchown/lsetxattr etc. operate on
 * the link itself — following a final symlink would misjudge deleting an
 * in-root symlink (whose referent is outside) as an outside deletion. */
static int resolve_at_nofollow(pid_t tid, long dirfd, uintptr_t pathptr,
                               char *out)
{
    dirfd = (long)(int)dirfd;
    if (!pathptr) return 0;
    char rel[PATH_MAX];
    if (tmem_str(tid, pathptr, rel, sizeof(rel)) < 0) return 0;
    g_gate_used_mutable = 1;
    char abs[PATH_MAX * 2];
    if (rel[0] == '/') {
        snprintf(abs, sizeof(abs), "%s", rel);
    } else {
        char base[PATH_MAX];
        if (dirfd == AT_FDCWD) {
            if (!cwd_of(tid, base, sizeof(base))) return 0;
        } else {
            if (!fd_target(tid, dirfd, base, sizeof(base)) || base[0] != '/')
                return 0;
        }
        snprintf(abs, sizeof(abs), "%s/%s", base, rel);
    }
    /* /dev fd aliases (see resolve_at): rewrite against the tracee's fd
     * before splitting parent/leaf. */
    {
        long afd;
        const char *arest;
        if (dev_fd_alias(abs, &afd, &arest)) {
            char tgt[PATH_MAX];
            if (!fd_target(tid, afd, tgt, sizeof(tgt)) || tgt[0] != '/')
                return 0;
            char real[PATH_MAX * 2];
            snprintf(real, sizeof(real), "%s%s", tgt, arest);
            snprintf(abs, sizeof(abs), "%s", real);
        }
    }
    /* Same kernel-order rule as resolve_at: the parent part is canonicalized
     * by realpath (which resolves '..' after following symlinks); only the
     * FINAL component stays lexical. A leaf of '.' or '..' is not a
     * symlinkable name — resolve the whole path normally. */
    char parent[PATH_MAX];
    snprintf(parent, sizeof(parent), "%.*s", PATH_MAX - 1, abs);
    char *sl = strrchr(parent, '/');
    if (!sl) return 0;
    const char *leaf = sl + 1;
    if (strcmp(leaf, ".") == 0 || strcmp(leaf, "..") == 0)
        return canon_path(abs, out) ? 1
                                    : (snprintf(out, PATH_MAX, "%.*s",
                                                PATH_MAX - 1, abs), 1);
    char pcanon[PATH_MAX];
    if (sl == parent) strcpy(parent, "/"); else *sl = 0;
    if (canon_path(parent, pcanon)) {
        size_t o = strlen(pcanon);
        memcpy(out, pcanon, o);
        if (o > 1 && o < PATH_MAX - 1) out[o++] = '/';
        size_t room = PATH_MAX - o - 1;
        size_t ll = strlen(leaf);
        if (ll > room) ll = room;
        memcpy(out + o, leaf, ll);
        out[o + ll] = 0;
    } else {
        snprintf(out, PATH_MAX, "%.*s", PATH_MAX - 1, abs);
    }
    return 1;
}

/* Resolve fd target to a filesystem path; non-file targets return NULL. */
static const char *fd_path_or_null(Tracee *t, long fd, char *buf)
{
    char raw[PATH_MAX];
    if (!fd_target(t->tid, fd, raw, sizeof(raw))) return NULL;
    if (raw[0] != '/') return NULL; /* socket:, pipe:, anon_inode: */
    /* The fd resolves to a real path AND lives in a table shared with
     * siblings — they could dup2-rebind it before the syscall executes:
     * the binding is mutable input. */
    g_gate_used_mutable = 1;
    char canon[PATH_MAX];
    snprintf(buf, PATH_MAX, "%s", canon_path(raw, canon) ? canon : raw);
    return buf;
}

/* ------------------------------------------------------------------ */
/* Syscall-name table (event field)                                    */
/* ------------------------------------------------------------------ */

static const char *sc_name(long nr)
{
    static char buf[32];
    switch (nr) {
    case 1: return "write"; case 2: return "open"; case 9: return "mmap";
    case 10: return "mprotect"; case 18: return "pwrite64"; case 20: return "writev";
    case 26: return "msync"; case 29: return "shmget"; case 30: return "shmat";
    case 31: return "shmctl"; case 40: return "sendfile"; case 42: return "connect";
    case 44: return "sendto"; case 46: return "sendmsg"; case 47: return "recvmsg";
    case 43: return "accept"; case 288: return "accept4"; case 50: return "listen";
    case 49: return "bind"; case 56: return "clone"; case 59: return "execve";
    case 62: return "kill"; case 64: return "semget"; case 65: return "semop";
    case 66: return "semctl"; case 68: return "msgget"; case 69: return "msgsnd";
    case 70: return "msgrcv"; case 71: return "msgctl"; case 76: return "truncate";
    case 77: return "ftruncate"; case 82: return "rename"; case 83: return "mkdir";
    case 84: return "rmdir"; case 85: return "creat"; case 86: return "link";
    case 87: return "unlink"; case 88: return "symlink"; case 90: return "chmod";
    case 91: return "fchmod"; case 92: return "chown"; case 93: return "fchown";
    case 101: return "ptrace"; case 103: return "syslog"; case 132: return "utime";
    case 133: return "mknod"; case 153: return "vhangup"; case 155: return "pivot_root";
    case 159: return "adjtimex"; case 161: return "chroot"; case 163: return "acct";
    case 164: return "settimeofday"; case 165: return "mount"; case 166: return "umount2";
    case 167: return "swapon"; case 168: return "swapoff"; case 169: return "reboot";
    case 170: return "sethostname"; case 171: return "setdomainname"; case 172: return "iopl";
    case 173: return "ioperm"; case 175: return "init_module"; case 176: return "delete_module";
    case 179: return "quotactl"; case 188: return "setxattr"; case 189: return "lsetxattr";
    case 190: return "fsetxattr"; case 197: return "removexattr"; case 198: return "lremovexattr";
    case 199: return "fremovexattr"; case 200: return "tkill"; case 206: return "io_setup";
    case 207: return "io_destroy"; case 208: return "io_getevents"; case 209: return "io_submit";
    case 210: return "io_cancel"; case 227: return "clock_settime"; case 234: return "tgkill";
    case 235: return "utimes"; case 240: return "mq_open"; case 241: return "mq_unlink";
    case 242: return "mq_timedsend"; case 243: return "mq_timedreceive"; case 244: return "mq_notify";
    case 245: return "mq_getsetattr"; case 246: return "kexec_load"; case 248: return "add_key";
    case 249: return "request_key"; case 250: return "keyctl"; case 257: return "openat";
    case 258: return "mkdirat"; case 259: return "mknodat"; case 260: return "fchownat";
    case 261: return "futimesat"; case 263: return "unlinkat"; case 264: return "renameat";
    case 265: return "linkat"; case 266: return "symlinkat"; case 268: return "fchmodat";
    case 272: return "unshare"; case 275: return "splice"; case 276: return "tee";
    case 278: return "vmsplice"; case 280: return "utimensat"; case 285: return "fallocate";
    case 295: return "preadv"; case 296: return "pwritev"; case 297: return "rt_tgsigqueueinfo";
    case 298: return "perf_event_open"; case 299: return "recvmmsg"; case 304: return "open_by_handle_at";
    case 305: return "clock_adjtime"; case 307: return "sendmmsg"; case 308: return "setns";
    case 310: return "process_vm_readv"; case 311: return "process_vm_writev";
    case 313: return "finit_module"; case 316: return "renameat2"; case 320: return "kexec_file_load";
    case 321: return "bpf"; case 322: return "execveat"; case 326: return "copy_file_range";
    case 327: return "preadv2"; case 328: return "pwritev2"; case 329: return "pkey_mprotect";
    case 333: return "io_pgetevents"; case 424: return "pidfd_send_signal";
    case 425: return "io_uring_setup"; case 426: return "io_uring_enter";
    case 427: return "io_uring_register"; case 428: return "open_tree";
    case 429: return "move_mount"; case 430: return "fsopen"; case 431: return "fsconfig";
    case 432: return "fsmount"; case 433: return "fspick"; case 435: return "clone3";
    case 437: return "openat2"; case 438: return "pidfd_getfd"; case 440: return "process_madvise";
    case 442: return "mount_setattr"; case 443: return "quotactl_fd"; case 448: return "process_mrelease";
    case 452: return "fchmodat2"; case 463: return "setxattrat"; case 466: return "removexattrat";
    default: snprintf(buf, sizeof(buf), "nr_%ld", nr); return buf;
    }
}



/* ------------------------------------------------------------------ */
/* Broker decision application                                         */
/* ------------------------------------------------------------------ */

/* apply_decision: returns 0 when the tid should be resumed ('continue'),
 * RC_DETACHED when the whole tree was detached ('allow'). deny / timeout /
 * EOF paths never return (kill_tree exits).
 * g_at_exit_stop marks decisions made on a syscall-EXIT stop (recvmsg cmsg
 * inspection): there the audited operation already ran, so the denial text
 * may not claim it was blocked before execution. */
static int apply_decision(Tracee *t, int decision, int *exit_code)
{
    (void)t; (void)exit_code;
    if (g_term_signal || decision == -3)
        kill_tree("the command was cancelled", 0);
    if (decision == -2 && g_fail_open) {
        char frame[200];
        int n = snprintf(frame, sizeof(frame),
            "{\"version\":1,\"type\":\"fail_open\",\"token\":\"%s\",\"code\":\"observer_review\"}\n", g_token);
        if (g_broker_fd >= 0) write_all(g_broker_fd, frame, (size_t)n);
        decision = 1;
    }
    if (decision == 1) {
        detach_all();
        g_detached = 1;
        return RC_DETACHED;
    }
    if (decision == -1)
        kill_tree(g_deny_reason[0] ? g_deny_reason
                                   : "boundary operation denied",
                  !g_at_exit_stop);
    if (decision == -2)
        kill_tree("the boundary review did not complete",
                  !g_at_exit_stop);
    return 0;
}

static int observer_failure(const char *code, const char *reason, int at_entry)
{
    if (!g_fail_open) kill_tree(reason, at_entry);
    if (g_term_signal) kill_tree("the command was cancelled", 0);
    char frame[200];
    int n = snprintf(frame, sizeof(frame),
        "{\"version\":1,\"type\":\"fail_open\",\"token\":\"%s\",\"code\":\"%s\"}\n", g_token, code);
    if (g_broker_fd >= 0) write_all(g_broker_fd, frame, (size_t)n);
    detach_all();
    g_detached = 1;
    return RC_DETACHED;
}

/* ------------------------------------------------------------------ */
/* Path/syscall boundary checks                                        */
/* ------------------------------------------------------------------ */

/* Devices the payload may do I/O on without a boundary event: stdio
 * plumbing and the classic sinks/sources only. Metadata ops (chmod, chown,
 * xattr, utimes) on a device node are NOT I/O and never skip the boundary.
 * /dev/fd/N and /dev/std* are deliberately absent: they are fd aliases and
 * are resolved to the real object before classification. */
static int dev_allowed(const char *path)
{
    static const char *ok[] = {
        "/dev/null", "/dev/zero", "/dev/full", "/dev/random", "/dev/urandom",
        "/dev/tty", "/dev/ptmx"
    };
    for (size_t i = 0; i < sizeof(ok) / sizeof(ok[0]); i++)
        if (strcmp(path, ok[i]) == 0) return 1;
    if (strncmp(path, "/dev/pts/", 9) == 0) return 1;
    return 0;
}

/* Classify one canonical path against the deny/read-only/root policy.
 * metadata_ops (chmod/chown/xattr/utime) never get the device I/O pass.
 * Returns GATE_PASS, or the boundary class: 0 write, 1 read, 2 opaque. */
static int classify_path(const char *path, int is_write, int metadata_op)
{
    pid_t pp;
    int pc = proc_check(path, &pp);
    if (pc == 2) return 2;
    /* A sensitive other-pid /proc object is a read boundary when read, but
     * WRITING one is an opaque capability: class 'read' would let a w-cap
     * check elsewhere mistake it for harmless reads and skip the write
     * ceiling entirely. */
    if (pc == 1) return is_write ? 2 : 1;
    if (strncmp(path, "/dev/", 5) == 0 && !metadata_op &&
        dev_allowed(path)) return GATE_PASS;
    if (is_write) {
        /* --protect control plane: writes inside a protected path, or to
         * any of its ancestors (rename/unlink/chmod on a parent swaps the
         * whole subtree), are boundary events even inside a write root. */
        for (int i = 0; i < g_nprotect; i++)
            if (is_within(g_protect[i], path) || is_within(path, g_protect[i]))
                return 0;
        if (path_in_list(g_deny_write, g_ndeny_write, path) ||
            g_readonly || !path_in_roots(path))
            return 0;
        return GATE_PASS;
    }
    if (path_in_list(g_deny_read, g_ndeny_read, path) || credential_path(path))
        return 1;
    return GATE_PASS;
}

/* Emit one boundary event for 1-2 classified targets and apply the reply.
 * is_write selects the policy class to test (a linkat source inode's
 * metadata is modified too, so link/rename classify BOTH paths as writes).
 * The event kind is the strongest classification among the targets;
 * watcher-self paths force opaque + requiresFullApproval. */
static int decide_paths(Tracee *t, const char *sc, const char *op,
                        Target *tgs, int n, int is_write, const char *details)
{
    int cls = GATE_PASS;
    int metadata_op = op && strcmp(op, "metadata") == 0;
    for (int i = 0; i < n; i++) {
        int c = classify_path(tgs[i].path, is_write, metadata_op);
        if (c == 2) cls = 2;
        else if (c != GATE_PASS && cls == GATE_PASS) cls = c;
    }
    if (cls == GATE_PASS) return GATE_PASS;
    const char *kind = cls == 2 ? "opaque" : cls == 1 ? "read" : "write";
    return broker_decide(t, sc, kind, op, tgs, n, details, cls == 2);
}

static int check_path(Tracee *t, const char *sc, const char *kind,
                      const char *op, const char *path, const char *details)
{
    Target tg = { .path = path };
    return decide_paths(t, sc, op, &tg, 1, kind[0] == 'w', details);
}

/* sockaddr family: AF_INET/INET6 -> 'network', everything else 'opaque'. */
static int gate_sockaddr(Tracee *t, const char *sc, const char *op,
                         uintptr_t addr, unsigned long long len)
{
    if (addr == 0 || len < 2) return GATE_PASS;
    unsigned char sa[128];
    size_t want = len > sizeof(sa) ? sizeof(sa) : (size_t)len;
    if (tmem_read(t->tid, addr, sa, want) <= 0) return GATE_PASS;
    g_gate_used_mutable = 1; /* sockaddr lives in tracee memory */
    uint16_t fam;
    memcpy(&fam, sa, 2);
    char details[256];
    /* Netlink addressed to the kernel (nl_pid 0: an auto-bound local port,
     * or a request to the kernel) is a query channel such as getifaddrs()
     * route dumps. Every netlink state change needs CAP_NET_ADMIN or similar,
     * which an unprivileged tracee cannot gain: traced setuid/fcaps execs do
     * not elevate and namespace creation is a privilege boundary. */
    if (fam == AF_NETLINK && want >= 12 && geteuid() != 0) {
        uint32_t nl_pid;
        memcpy(&nl_pid, sa + 4, 4);
        if (nl_pid == 0) return GATE_PASS;
    }
    if (fam == AF_UNIX && want > 2) {
        char sun[112];
        size_t n = want - 2 > sizeof(sun) - 1 ? sizeof(sun) - 1 : want - 2;
        memcpy(sun, sa + 2, n);
        sun[n] = 0;
        char esc[128];
        json_escape(sun[0] ? sun : "<abstract>", esc, sizeof(esc));
        snprintf(details, sizeof(details), "\"family\":\"AF_UNIX\",\"target\":\"%s\"", esc);
    } else if (fam == AF_INET && want >= 8) {
        snprintf(details, sizeof(details),
                 "\"family\":\"AF_INET\",\"target\":\"%u.%u.%u.%u:%u\"",
                 sa[4], sa[5], sa[6], sa[7], (unsigned)((sa[2] << 8) | sa[3]));
    } else if (fam == AF_INET6 && want >= sizeof(struct sockaddr_in6)) {
        struct sockaddr_in6 address;
        char host[INET6_ADDRSTRLEN];
        memcpy(&address, sa, sizeof(address));
        if (inet_ntop(AF_INET6, &address.sin6_addr, host, sizeof(host)))
            snprintf(details, sizeof(details),
                     "\"family\":\"AF_INET6\",\"target\":\"[%s]:%u\",\"scopeID\":%u",
                     host, (unsigned)ntohs(address.sin6_port), address.sin6_scope_id);
        else
            snprintf(details, sizeof(details), "\"family\":\"AF_INET6\"");
    } else {
        snprintf(details, sizeof(details), "\"family\":\"AF_%u\"", fam);
    }
    const char *kind = (fam == AF_INET || fam == AF_INET6) ? "network" : "opaque";
    return broker_decide(t, sc, kind, op, NULL, 0, details, kind[0] == 'o');
}

/* Refuse one syscall without asking the broker: the entry is turned into a
 * no-op and its exit stop returns -err. This only ever removes a capability
 * (the operation does not run), so it needs no approval and keeps the tree
 * monitored, unlike an 'allow' detach. */
static int skip_syscall(Tracee *t, struct user_regs_struct *r, int err)
{
    r->orig_rax = (unsigned long long)-1;
    if (set_regs(t->tid, r) < 0)
        kill_tree("a payload syscall could not be refused at the boundary", 1);
    t->inject_errno = err;
    return 0;
}

/* WSL hands an exec to Windows by binfmt_misc magic ("MZ", see
 * /proc/sys/fs/binfmt_misc/WSLInterop), not by file name: an ELF named
 * bun.exe runs natively, while a PE copied to a suffix-less name still goes
 * to Windows. The file is opened as O_PATH first so a non-regular object
 * (device, FIFO) is never opened for reading. An unreadable image falls back
 * to the name heuristic. */
static int windows_image(const char *path)
{
    size_t rl = strlen(path);
    int by_name = rl > 4 && strcasecmp(path + rl - 4, ".exe") == 0;
    int pfd = open(path, O_PATH | O_CLOEXEC);
    if (pfd < 0) return by_name;
    struct stat st;
    if (fstat(pfd, &st) < 0 || !S_ISREG(st.st_mode)) { close(pfd); return by_name; }
    struct statfs filesystem;
    if (fstatfs(pfd, &filesystem) < 0) { close(pfd); return by_name; }
    switch ((unsigned long)filesystem.f_type) {
    case 0x9fa0: case 0x62656572: case 0x64626720: case 0x74726163:
    case 0x73636673: case 0x62656570: case 0x27e0eb: case 0x63677270:
    case 0xcafe4a11:
        close(pfd);
        return by_name;
    default: break;
    }
    char via[64];
    snprintf(via, sizeof(via), "/proc/self/fd/%d", pfd);
    int fd = open(via, O_RDONLY | O_NONBLOCK | O_CLOEXEC | O_NOCTTY);
    close(pfd);
    if (fd < 0) return by_name;
    unsigned char magic[2];
    ssize_t n = pread(fd, magic, sizeof(magic), 0);
    close(fd);
    if (n != (ssize_t)sizeof(magic)) return 0;
    return magic[0] == 'M' && magic[1] == 'Z';
}

/* procps-ng 4 `ps` opens /proc/<pid>/environ of every listed process even
 * when no environment column is shown. Those environments hold other
 * programs' credentials, so the read stays a boundary for every other
 * reader; for the root-owned ps image it is refused with EACCES (what ps
 * already gets for other users' processes) instead of being reviewed once
 * per process. */
static int procps_environ_scan(Tracee *t, const char *path)
{
    pid_t pp;
    if (proc_check(path, &pp) != 1) return 0;
    size_t pl = strlen(path);
    if (pl < 8 || strcmp(path + pl - 8, "/environ") != 0) return 0;
    char link[64], exe[PATH_MAX];
    snprintf(link, sizeof(link), "/proc/%d/exe", (int)t->tid);
    ssize_t n = readlink(link, exe, sizeof(exe) - 1);
    if (n <= 0) return 0;
    exe[n] = 0;
    if (strcmp(exe, "/usr/bin/ps") != 0 && strcmp(exe, "/bin/ps") != 0) return 0;
    struct stat st;
    return lstat(exe, &st) == 0 && S_ISREG(st.st_mode) && st.st_uid == 0 &&
           (st.st_mode & 022) == 0;
}

/* glibc's NSS user/group lookups (getpwuid for `ls -l`, `ps`, `id`, ...)
 * connect to these AF_UNIX services before falling back to local files. */
#define NSS_OTHER   0
#define NSS_REFUSE  1  /* refuse with ENOENT: glibc falls back to its modules */
#define NSS_TRUSTED 2  /* root-owned read-only lookup service: plain pass */

static int nss_socket_check(Tracee *t, uintptr_t addr, unsigned long long len)
{
    if (addr == 0 || len < 3) return NSS_OTHER;
    struct sockaddr_un sa;
    size_t want = len > sizeof(sa) ? sizeof(sa) : (size_t)len;
    memset(&sa, 0, sizeof(sa));
    if (tmem_read(t->tid, addr, &sa, want) <= 0) return NSS_OTHER;
    g_gate_used_mutable = 1; /* sockaddr lives in tracee memory */
    if (sa.sun_family != AF_UNIX || sa.sun_path[0] == 0) return NSS_OTHER;
    char p[sizeof(sa.sun_path) + 1];
    size_t pl = want - offsetof(struct sockaddr_un, sun_path);
    memcpy(p, sa.sun_path, pl);
    p[pl] = 0;
    /* nscd is always refused, present or not: it answers GETFD* lookups by
     * passing descriptors (SCM_RIGHTS), and glibc treats any connect
     * failure as "no cache daemon" and reads the databases itself. */
    if (strcmp(p, "/var/run/nscd/socket") == 0 || strcmp(p, "/run/nscd/socket") == 0)
        return NSS_REFUSE;
    if (strncmp(p, "/run/systemd/userdb/", 20) != 0) return NSS_OTHER;
    const char *base = p + 20;
    if (!*base || strchr(base, '/') || strcmp(base, ".") == 0 || strcmp(base, "..") == 0)
        return NSS_OTHER;
    struct stat st;
    if (lstat(p, &st) < 0) return errno == ENOENT ? NSS_REFUSE : NSS_OTHER;
    struct stat ds;
    if (S_ISSOCK(st.st_mode) && st.st_uid == 0 &&
        lstat("/run/systemd/userdb", &ds) == 0 && S_ISDIR(ds.st_mode) &&
        ds.st_uid == 0 && (ds.st_mode & 022) == 0)
        return NSS_TRUSTED;
    return NSS_OTHER;
}

/* Scan a msghdr's control data for SCM_RIGHTS. */
static int has_scm_rights(Tracee *t, uintptr_t msghdr)
{
    unsigned char hdr[64];
    if (tmem_read(t->tid, msghdr, hdr, sizeof(hdr)) <= 0) return 0;
    g_gate_used_mutable = 1; /* msghdr/cmsg live in tracee memory */
    uint64_t control, controllen;
    memcpy(&control, hdr + 32, 8);
    memcpy(&controllen, hdr + 40, 8);
    if (control == 0 || controllen < 16 || controllen > 65536) return 0;
    unsigned char *cbuf = malloc((size_t)controllen);
    if (!cbuf) return 0;
    int found = 0;
    if (tmem_read(t->tid, (uintptr_t)control, cbuf, (size_t)controllen) > 0) {
        size_t off = 0;
        while (off + 16 <= controllen) {
            uint64_t clen;
            int32_t level, type;
            memcpy(&clen, cbuf + off, 8);
            memcpy(&level, cbuf + off + 8, 4);
            memcpy(&type, cbuf + off + 12, 4);
            if (clen < 16 || off + clen > controllen) break;
            if (level == SOL_SOCKET && type == SCM_RIGHTS) { found = 1; break; }
            off += (size_t)clen;
        }
    }
    free(cbuf);
    return found;
}

/* ------------------------------------------------------------------ */
/* Per-syscall gating                                                  */
/* ------------------------------------------------------------------ */

static int gate_entry(Tracee *t, struct user_regs_struct *r, int *exit_code)
{
    long nr = (long)r->orig_rax;
    char resolved[PATH_MAX];
    char resolved2[PATH_MAX];
    char fdbuf[PATH_MAX];
    char details[320];
    details[0] = 0;
    const char *sc = sc_name(nr);

    /* ABI check: the gate tables below are only valid for the x86_64
     * syscall numbering. A 32-bit/x32 entry stop arriving with an i386 or
     * x32 audit arch would silently be gated against the wrong table, so
     * it becomes an opaque execution-domain boundary (full approval only:
     * 'continue' is refused helper-side, 'allow' detaches natively). */
    {
        /* GET_SYSCALL_INFO.arch is the audit arch of the in-flight syscall.
         * (On some kernels si.op reports NONE even at syscall stops — the
         * arch field is still filled; never gate on op.) The gate tables
         * are x86_64-only: a compat/x32 entry would silently gate against
         * the wrong numbering, so it becomes an opaque exec-domain event. */
        struct ptrace_syscall_info si;
        int foreign = 0;
        memset(&si, 0, sizeof(si));
        if (ptrace(PTRACE_GET_SYSCALL_INFO, t->tid,
                   (void *)(long)sizeof(si), &si) < 0 ||
            si.arch == 0) {
            snprintf(details, sizeof(details), "\"arch\":\"unknown\"");
            foreign = 1;
        } else if (si.arch != AUDIT_ARCH_X86_64) {
            snprintf(details, sizeof(details), "\"arch\":\"0x%x\"",
                     (unsigned)si.arch);
            foreign = 1;
        } else if (nr & __X32_SYSCALL_BIT) {
            snprintf(details, sizeof(details), "\"arch\":\"x32\"");
            foreign = 1;
        }
        if (foreign) {
            /* sc_name(nr) would interpret a compat number as x86_64 —
             * report the ABI honestly instead. */
            int d = broker_decide(t, "foreign-abi", "opaque", "exec-domain",
                                  NULL, 0, details, 1);
            return apply_decision(t, d, exit_code);
        }
    }

    /* Un-monitorable capability entries are opaque boundary events with
     * requiresFullApproval: the broker may only 'allow' (detach -> native
     * execution) or 'deny'. 'continue' is refused helper-side — a continued
     * syscall here would hand the payload an async/cross-process channel we
     * cannot observe. */
    /* io_uring_setup is refused as ENOSYS instead (the answer a kernel with
     * io_uring disabled gives): libuv/Node, Bun and tokio only probe it and
     * fall back to epoll/threadpool I/O that stays observable. Without a
     * ring, io_uring_enter/register have nothing to act on. */
    if (nr == 425) return skip_syscall(t, r, ENOSYS);
    switch (nr) {
    case 101: case 304: case 310: case 311:        /* ptrace, open_by_handle_at, process_vm_* */
    case 206: case 207: case 208: case 209: case 210: case 333: /* Linux AIO */
    case 425: case 426: case 427:                 /* io_uring */
    case 321: case 298:                           /* bpf, perf_event_open */
    {
        int d = broker_decide(t, sc, "opaque", "capability", NULL, 0,
                              "\"cap\":\"unmonitorable\"", 1);
        return apply_decision(t, d, exit_code);
    }
    default: break;
    }

    /* clone family: CLONE_UNTRACED escapes tracing -> opaque full-approval;
     * namespace-creating clones -> privilege event. */
    if (nr == 56 || nr == 435) {
        unsigned long long flags = 0;
        if (nr == 56) {
            flags = r->rdi; /* register operand: stable by definition */
        } else {
            /* clone3 args live in tracee memory: mark mutable (freeze is
             * kept until exit) AND fail closed when unreadable — the
             * flags decide whether the child shares the fd table, and a
             * guessed-private default would miss a real CLONE_FILES. */
            if (tmem_read(t->tid, (uintptr_t)r->rdi, &flags, 8) != 8 ||
                getenv("BW_TEST_CLONE3_FAIL") /* test-only injection */)
                return observer_failure("observer_inspection", "a payload clone3 argument block could not be "
                          "read for the boundary check", 0);
            g_gate_used_mutable = 1;
        }
        t->clone_flags = flags;
        t->clone_flags_valid = 1;
        if (flags & CLONE_UNTRACED) {
            int d = broker_decide(t, sc, "opaque", "capability", NULL, 0,
                                  "\"flag\":\"CLONE_UNTRACED\"", 1);
            return apply_decision(t, d, exit_code);
        }
        if (flags & (CLONE_NEWNS | CLONE_NEWCGROUP | CLONE_NEWUTS |
                     CLONE_NEWIPC | CLONE_NEWUSER | CLONE_NEWPID |
                     CLONE_NEWNET | CLONE_NEWTIME)) {
            snprintf(details, sizeof(details), "\"flags\":\"0x%llx\"", flags);
            return apply_decision(t, broker_decide(t, sc, "privilege",
                    "namespace", NULL, 0, details, 1), exit_code) ? 2 : 0;
        }
        return 0;
    }

    /* exec family: interop targets and suid/sgid elevation are boundaries. */
    if (nr == 59 || nr == 322) {
        long dirfd = nr == 322 ? (long)r->rdi : AT_FDCWD;
        uintptr_t pp = nr == 322 ? (uintptr_t)r->rsi : (uintptr_t)r->rdi;
        if (nr == 322 && (r->r8 & AT_EMPTY_PATH) && pp == 0) {
            const char *fp = fd_path_or_null(t, dirfd, fdbuf);
            if (!fp) return 0;
            snprintf(resolved, sizeof(resolved), "%s", fp);
        } else if (!resolve_at(t->tid, dirfd, pp, resolved)) {
            return 0;
        }
        /* execve argv is rsi; execveat argv is rdx (rsi is the path). */
        uintptr_t argv_ptr = nr == 322 ? (uintptr_t)r->rdx : (uintptr_t)r->rsi;
        if (strncmp(resolved, "/mnt/", 5) == 0 || windows_image(resolved)) {
            Target tg = { .path = resolved };
            return apply_decision(t, broker_decide_argv(t, sc, "interop", "exec",
                    &tg, 1, details, 1, argv_ptr), exit_code) ? 2 : 0;
        }
        struct stat st;
        if (stat(resolved, &st) == 0 && (st.st_mode & (S_ISUID | S_ISGID))) {
            /* Traced setuid exec is suppressed by the kernel: only an
             * entry-side 'allow' (detach -> native exec) can run sudo/su. */
            Target tg = { .path = resolved };
            snprintf(details, sizeof(details), "\"mode\":\"0%o\"",
                     st.st_mode & 07777);
            return apply_decision(t, broker_decide_argv(t, sc, "privilege", "exec",
                    &tg, 1, details, 1, argv_ptr), exit_code) ? 2 : 0;
        }
        return 0;
    }

    /* Path-taking write family. nf1/nf2 select NOFOLLOW-last resolution
     * (canonicalized parent + lexical basename): unlink/rename/rmdir/
     * lchown/l*xattr and *creation* destinations operate on the link itself —
     * following the leaf would misjudge deleting an in-root symlink that
     * merely points outside as an out-of-root deletion. chown/open-family
     * follow semantics keep the full realpath. */
    long dirfd = AT_FDCWD;
    uintptr_t pptr = 0;
    const char *op = NULL;
    int two_paths = 0, nf1 = 0, nf2 = 0;
    uintptr_t p2 = 0;
    long d2 = AT_FDCWD;
    switch (nr) {
    case 76:  op = "modify";   pptr = r->rdi; break;                    /* truncate (follows) */
    case 82:  op = "rename";   pptr = r->rdi; p2 = r->rsi; two_paths = 1;
              nf1 = 1; nf2 = 1; break;                                  /* rename */
    case 83:  op = "create";   pptr = r->rdi; nf1 = 1; break;           /* mkdir */
    case 84:  op = "delete";   pptr = r->rdi; nf1 = 1; break;           /* rmdir */
    case 85:  op = "create";   pptr = r->rdi; break;                    /* creat (follows) */
    case 86:  op = "create";   pptr = r->rdi; p2 = r->rsi; two_paths = 1;
              nf1 = 1; nf2 = 1; break;  /* link() == linkat(flags=0): neither
                                           side follows the leaf symlink;
                                           the src inode's nlink is modified
                                           (real effect -> keep as target) */
    case 87:  op = "delete";   pptr = r->rdi; nf1 = 1; break;           /* unlink */
    case 88:  op = "create";   pptr = r->rsi; nf1 = 1; break;           /* symlink: linkpath only,
                                                                         source text untouched */
    case 90:  op = "metadata"; pptr = r->rdi; break;                    /* chmod */
    case 92:  op = "metadata"; pptr = r->rdi; break;                    /* chown */
    case 94:  op = "metadata"; pptr = r->rdi; nf1 = 1; break;           /* lchown */
    case 132: op = "metadata"; pptr = r->rdi; break;                    /* utime */
    case 133: op = "create";   pptr = r->rdi; nf1 = 1; break;           /* mknod */
    case 188: case 197:
              op = "metadata"; pptr = r->rdi; break;                    /* setxattr/removexattr (follow) */
    case 189: case 198:
              op = "metadata"; pptr = r->rdi; nf1 = 1; break;           /* lsetxattr/lremovexattr */
    case 235: op = "metadata"; pptr = r->rdi; break;                    /* utimes */
    case 258: op = "create";   dirfd = r->rdi; pptr = r->rsi; nf1 = 1; break; /* mkdirat */
    case 259: op = "create";   dirfd = r->rdi; pptr = r->rsi; nf1 = 1; break; /* mknodat */
    case 260: op = "metadata"; dirfd = r->rdi; pptr = r->rsi;
              nf1 = !!(r->r8 & AT_SYMLINK_NOFOLLOW); break;             /* fchownat */
    case 261: op = "metadata"; dirfd = r->rdi; pptr = r->rsi; break;    /* futimesat (follows) */
    case 263: op = "delete";   dirfd = r->rdi; pptr = r->rsi; nf1 = 1; break; /* unlinkat */
    case 264: case 316:
              op = "rename";   dirfd = r->rdi; pptr = r->rsi;
              d2 = (long)r->rdx; p2 = r->r10; two_paths = 1;
              nf1 = 1; nf2 = 1; break;                                  /* renameat(2) */
    case 265: op = "create";   dirfd = r->rdi; pptr = r->rsi;
              d2 = (long)r->rdx; p2 = r->r10; two_paths = 1;
              nf1 = !(r->r8 & AT_SYMLINK_FOLLOW);                     /* linkat src: nofollow unless
                                                                          AT_SYMLINK_FOLLOW requests it */
              nf2 = 1; break;                                           /* linkat dest: never followed */
    case 266: op = "create";   dirfd = r->rsi; pptr = r->rdx; nf1 = 1; break; /* symlinkat: linkpath only */
    case 268: op = "metadata"; dirfd = r->rdi; pptr = r->rsi; break;    /* fchmodat (follows) */
    case 452: op = "metadata"; dirfd = r->rdi; pptr = r->rsi;
              nf1 = !!(r->r10 & AT_SYMLINK_NOFOLLOW); break;            /* fchmodat2 */
    case 280: op = "metadata"; dirfd = r->rdi; pptr = r->rsi;
              nf1 = !!(r->r10 & AT_SYMLINK_NOFOLLOW); break;            /* utimensat */
    case 463: op = "metadata"; dirfd = r->rdi; pptr = r->rsi;
              nf1 = !!(r->rdx & AT_SYMLINK_NOFOLLOW); break;            /* setxattrat */
    case 466: op = "metadata"; dirfd = r->rdi; pptr = r->rsi;
              nf1 = !!(r->rdx & AT_SYMLINK_NOFOLLOW); break;            /* removexattrat */
    default: break;
    }
    if (op) {
        int ndirect = 0;
        if (pptr == 0) {
            /* NULL path: only meaningful as an fd-target form. utimensat
             * NULL => the dirfd file itself; the others need AT_EMPTY_PATH. */
            unsigned long long fl = 0;
            switch (nr) {
            case 280: fl = AT_EMPTY_PATH; break;              /* NULL always = dirfd file */
            case 260: fl = r->r8 & AT_EMPTY_PATH; break;      /* fchownat */
            case 268: case 452: fl = r->r10 & AT_EMPTY_PATH; break;
            case 463: case 466: fl = r->rdx & AT_EMPTY_PATH; break;
            default: break;
            }
            const char *fp = (fl & AT_EMPTY_PATH) ? fd_path_or_null(t, dirfd, fdbuf) : NULL;
            if (!fp) return 0;
            snprintf(resolved, sizeof(resolved), "%s", fp);
            nf1 = 0; /* an fd already names the object; no leaf symlink */
        } else {
            int ok = nf1 ? resolve_at_nofollow(t->tid, dirfd, pptr, resolved)
                         : resolve_at(t->tid, dirfd, pptr, resolved);
            if (!ok) return 0;
        }
        Target tg[2];
        tg[0].path = resolved; tg[0].nofollow = nf1;
        ndirect = 1;
        if (two_paths) {
            int ok2 = nf2 ? resolve_at_nofollow(t->tid, d2, p2, resolved2)
                          : resolve_at(t->tid, d2, p2, resolved2);
            if (!ok2) return 0;
            tg[1].path = resolved2; tg[1].nofollow = nf2;
            ndirect = 2;
        }
        /* link/rename touch source AND destination (a hardlink bumps the
         * source inode's link count): both go in one event's targets. */
        int d = decide_paths(t, sc, op, tg, ndirect, 1, details);
        if (d != GATE_PASS)
            return apply_decision(t, d, exit_code);
        return 0;
    }

    /* open/openat/openat2: flags decide read-class vs write-class. */
    if (nr == 2 || nr == 257 || nr == 437) {
        unsigned long long flags;
        if (nr == 2) flags = r->rsi;
        else if (nr == 257) flags = r->rdx;
        else {
            unsigned long long how[3] = {0, 0, 0};
            tmem_read(t->tid, (uintptr_t)r->rdx, how, 24);
            flags = how[0];
        }
        if (flags & O_PATH) return 0;
        dirfd = nr == 2 ? AT_FDCWD : (long)r->rdi;
        pptr = nr == 2 ? (uintptr_t)r->rdi : (uintptr_t)r->rsi;
        /* O_NOFOLLOW and O_CREAT|O_EXCL never traverse the leaf symlink. */
        int onf = (flags & O_NOFOLLOW) != 0 ||
                  (flags & (O_CREAT | O_EXCL)) == (O_CREAT | O_EXCL);
        if (onf ? !resolve_at_nofollow(t->tid, dirfd, pptr, resolved)
                : !resolve_at(t->tid, dirfd, pptr, resolved)) return 0;
        /* Runtimes (including Bun) probe trace_marker with O_WRONLY and
         * ignore the normal EACCES. An untraversable/invalid path cannot have
         * an open effect; return that OS error instead of inventing a write
         * crossing that the broker cannot even stat. This removes a syscall,
         * never authorizes one; ENOENT is excluded because O_CREAT may work. */
        struct stat open_info;
        if ((onf ? lstat(resolved, &open_info) : stat(resolved, &open_info)) < 0) {
            int failure = errno;
            if ((failure == ENOENT && !(flags & O_CREAT) &&
                 (flags & O_TMPFILE) != O_TMPFILE) ||
                failure == EACCES || failure == EPERM || failure == ENOTDIR ||
                failure == ELOOP || failure == ENAMETOOLONG)
                return skip_syscall(t, r, failure);
        }
        snprintf(details, sizeof(details), "\"flags\":\"0x%llx\"", flags);
        /* O_TMPFILE contains O_DIRECTORY bits: it needs an equality test,
         * not a mask test (an O_RDONLY|O_DIRECTORY open is a read). */
        int writey = (flags & (O_WRONLY | O_RDWR | O_CREAT | O_TRUNC)) != 0 ||
                     (flags & O_TMPFILE) == O_TMPFILE;
        if (!writey) {
            /* The watcher's own /proc entries carry the broker token in
             * cmdline. Process listers (ps, pgrep, top) read them for every
             * pid; refusing that read like a foreign user's process keeps
             * the token private without a review per listing. */
            pid_t pp;
            if (proc_check(resolved, &pp) == 2 || procps_environ_scan(t, resolved))
                return skip_syscall(t, r, EACCES);
        }
        const char *kind = writey ? "write" : "read";
        const char *o = writey ? ((flags & O_CREAT) ? "create" : "modify") : "open";
        int d = check_path(t, sc, kind, o, resolved, details);
        if (d != GATE_PASS)
            return apply_decision(t, d, exit_code);
        return 0;
    }

    /* fd-based writes: target resolved through /proc/pid/fd. */
    long wfd = -1;
    const char *fdop = NULL;
    switch (nr) {
    case 1: case 20: case 18: case 296: case 328:
        wfd = (long)r->rdi; fdop = "modify"; break;   /* write,writev,pwrite64,pwritev(2) */
    case 77: wfd = (long)r->rdi; fdop = "modify"; break;   /* ftruncate */
    case 285: wfd = (long)r->rdi; fdop = "modify"; break;  /* fallocate */
    case 91: wfd = (long)r->rdi; fdop = "metadata"; break; /* fchmod */
    case 93: wfd = (long)r->rdi; fdop = "metadata"; break; /* fchown */
    case 190: case 199: wfd = (long)r->rdi; fdop = "metadata"; break; /* fsetxattr/fremovexattr */
    case 40: wfd = (long)r->rdi; fdop = "modify"; break;   /* sendfile: rdi = out_fd */
    case 275: wfd = (long)r->rdx; fdop = "modify"; break;  /* splice: rdx = fd_out */
    case 276: wfd = (long)r->rsi; fdop = "modify"; break;  /* tee: rsi = fd_out */
    case 326: wfd = (long)r->rdx; fdop = "modify"; break;  /* copy_file_range: rdx = fd_out */
    default: break;
    }
    /* fd 0-2 are NOT skipped: stdio can be dup2-rebound onto a real file.
     * fd_path_or_null resolves the target — pipes/sockets/ttys return NULL
     * and pass; a real path is classified like any other write. */
    if (wfd >= 0 && fdop) {
        const char *fp = fd_path_or_null(t, wfd, fdbuf);
        if (fp) {
            int d = check_path(t, sc, "write", fdop, fp, details);
            if (d != GATE_PASS)
                return apply_decision(t, d, exit_code);
        }
        return 0;
    }

    /* mmap write-shared / msync / mprotect-to-write on file mappings. */
    if (nr == 9 || nr == 26 || nr == 10 || nr == 329) {
        int check = 0;
        unsigned long long addr = 0, len = 0;
        if (nr == 9) {
            unsigned long long mt = r->r10 & 0x0f;
            if ((r->rdx & 2) && (mt == 0x01 || mt == 0x03)) {
                /* PROT_WRITE + MAP_SHARED / MAP_SHARED_VALIDATE only —
                 * MAP_PRIVATE (0x02) writes go to a private copy. */
                const char *fp = fd_path_or_null(t, (long)r->r8, fdbuf);
                if (fp) {
                    int d = check_path(t, sc, "write", "modify", fp, details);
                    if (d != GATE_PASS)
                        return apply_decision(t, d, exit_code);
                }
            }
            return 0;
        }
        addr = r->rdi; len = r->rsi;
        if (nr == 26) check = 1;                       /* msync: always flushable */
        else if (r->rdx & 2) check = 1;                /* mprotect PROT_WRITE */
        if (check) {
            char mp[64], line[512], backfile[PATH_MAX] = "";
            snprintf(mp, sizeof(mp), "/proc/%d/maps", (int)t->tid);
            FILE *f = fopen(mp, "r");
            if (f) {
                unsigned long long end = addr + len;
                while (fgets(line, sizeof(line), f)) {
                    unsigned long long lo, hi;
                    if (sscanf(line, "%llx-%llx", &lo, &hi) != 2) continue;
                    if (addr >= lo && addr < hi && end <= hi) {
                        char *sp = strchr(line, '/');
                        if (sp) {
                            snprintf(backfile, sizeof(backfile), "%s", sp);
                            backfile[strcspn(backfile, "\n")] = 0;
                        }
                        break;
                    }
                }
                fclose(f);
            }
            if (backfile[0]) {
                char canon[PATH_MAX];
                const char *fp = canon_path(backfile, canon) ? canon : backfile;
                int d = check_path(t, sc, "write", "modify", fp, details);
                if (d != GATE_PASS)
                    return apply_decision(t, d, exit_code);
            }
        }
        return 0;
    }

    /* Network / IPC destinations. */
    if (nr == 42 || nr == 49) { /* connect / bind */
        if (nr == 42) {
            int nss = nss_socket_check(t, (uintptr_t)r->rsi, r->rdx);
            if (nss == NSS_REFUSE) return skip_syscall(t, r, ENOENT);
            if (nss == NSS_TRUSTED) return 0;
        }
        int d = gate_sockaddr(t, sc, nr == 42 ? "connect" : "bind",
                              (uintptr_t)r->rsi, r->rdx);
        if (d != GATE_PASS)
            return apply_decision(t, d, exit_code);
        return 0;
    }
    /* listen/accept(4) are real inbound contact points; socket()/socketpair()
     * merely create local handles and stay ungated. */
    if (nr == 50) { /* listen */
        int d = broker_decide(t, sc, "network", "listen", NULL, 0,
                              details, 0);
        return apply_decision(t, d, exit_code);
    }
    if (nr == 43 || nr == 288) { /* accept / accept4 */
        int d = broker_decide(t, sc, "network", "accept", NULL, 0,
                              details, 0);
        return apply_decision(t, d, exit_code);
    }
    if (nr == 44) { /* sendto */
        int d = gate_sockaddr(t, sc, "send", (uintptr_t)r->r8, r->r9);
        if (d != GATE_PASS)
            return apply_decision(t, d, exit_code);
        return 0;
    }
    if (nr == 46 || nr == 307) { /* sendmsg / sendmmsg */
        uintptr_t mh = (uintptr_t)r->rsi;
        unsigned long long vlen = nr == 307 ? r->rdx : 1;
        if (vlen > 8) vlen = 8;
        for (unsigned long long i = 0; i < vlen; i++) {
            uintptr_t cur = mh + i * 64;
            if (has_scm_rights(t, cur)) {
                int d = broker_decide(t, sc, "opaque", "sendfd", NULL, 0,
                                      "\"channel\":\"SCM_RIGHTS\"", 1);
                return apply_decision(t, d, exit_code);
            }
            uint64_t nameptr = 0, namelen = 0;
            tmem_read(t->tid, cur, &nameptr, 8);
            tmem_read(t->tid, cur + 8, &namelen, 4);
            if (nameptr && namelen >= 2) {
                int d = gate_sockaddr(t, sc, "send", (uintptr_t)nameptr, namelen);
                if (d != GATE_PASS)
                    return apply_decision(t, d, exit_code);
            }
        }
        return 0;
    }
    if (nr == 47 || nr == 299) { /* recvmsg / recvmmsg: check cmsg at exit */
        t->pending_recv = (int)nr;
        t->recv_msghdr = (uintptr_t)r->rsi;
        t->recv_vlen = nr == 299 ? (int)r->rdx : 1;
        return 0;
    }

    /* Privilege / namespace / capability events. */
    switch (nr) {
    case 165: case 166: case 155: case 161: case 272: case 308:
    case 428: case 429: case 430: case 431: case 432: case 433: case 442:
    case 163: case 167: case 168: case 169: case 153: case 172: case 173:
    case 175: case 176: case 313: case 246: case 320:
    case 170: case 171: case 164: case 227: case 159: case 305:
    case 179: case 443: {
        snprintf(details, sizeof(details), "\"arg0\":\"0x%llx\"",
                 (unsigned long long)r->rdi);
        int d = broker_decide(t, sc, "privilege", "capability", NULL, 0,
                              details, 1);
        return apply_decision(t, d, exit_code);
    }
    default: break;
    }

    /* ioctl(2): fd-local terminal/descriptor queries and state toggles pass;
     * every other request is an unclassified high-capability op and becomes
     * an opaque boundary (FICLONE/TIOCSTI/fs ioctls must not slip by). */
    if (nr == 16) {
        unsigned long long req = r->rsi;
        switch (req) {
        /* Legacy tty/fd codes are bare numbers; the *2 variants are
         * _IOR/_IOW-encoded (TCGETS2 = _IOR('T',0x2A,44) = 0x802C542A). */
        case 0x5401: /* TCGETS */    case 0x802C542A: /* TCGETS2 */
        case 0x5402: /* TCSETS */    case 0x402C542B: /* TCSETS2 */
        case 0x5403: /* TCSETSW */   case 0x402C542C: /* TCSETSW2 */
        case 0x5404: /* TCSETSF */   case 0x402C542D: /* TCSETSF2 */
        case 0x540F: /* TIOCGPGRP */ case 0x5410: /* TIOCSPGRP */
        case 0x5413: /* TIOCGWINSZ */ case 0x5414: /* TIOCSWINSZ */
        case 0x5423: /* TIOCSETD */  case 0x5424: /* TIOCGETD */
        case 0x541B: /* FIONREAD/TIOCINQ */
        case 0x5421: /* FIONBIO */   case 0x5425: /* FIONASYNC */
        case 0x5450: /* FIONCLEX */  case 0x5451: /* FIOCLEX */
            return 0;
        default: break;
        }
        snprintf(details, sizeof(details), "\"request\":\"0x%llx\"", req);
        if (getenv("BW_DEBUG"))
            fprintf(stderr, "[bw %.3f] ioctl fd=%lld req=0x%llx\n",
                    bw_now(), (long long)r->rdi, req);
        int d = broker_decide(t, sc, "opaque", "ioctl", NULL, 0, details, 1);
        return apply_decision(t, d, exit_code);
    }

    /* Per-pid resource/scheduling syscalls: pid==0 (self) and pids inside the
     * traced tree pass; an external target is an opaque boundary. */
    if (nr == 302 || nr == 203 || nr == 204 || nr == 314 || nr == 315 ||
        nr == 279 || nr == 256) {
        /* prlimit64, sched_setaffinity, sched_getaffinity, sched_getattr,
         * sched_setattr, migrate_pages, move_pages — pid is rdi, 0 = self. */
        long pid = (long)r->rdi;
        if (pid == 0 || tgid_in_tree((pid_t)pid)) return 0;
        snprintf(details, sizeof(details), "\"pid\":%ld", pid);
        int d = broker_decide(t, sc, "opaque", "cross-process", NULL, 0,
                              details, 1);
        return apply_decision(t, d, exit_code);
    }
    if (nr == 251) { /* ioprio_set(which, who): PROCESS/self only */
        long which = (long)r->rdi, who = (long)r->rsi;
        if (which == 1 && (who == 0 || tgid_in_tree((pid_t)who))) return 0;
        int d = broker_decide(t, sc, "opaque", "cross-process", NULL, 0,
                              "\"target\":\"external\"", 1);
        return apply_decision(t, d, exit_code);
    }
    if (nr == 434) { /* pidfd_open: a handle on an outside process */
        long pid = (long)r->rdi;
        if (pid <= 0 || tgid_in_tree((pid_t)pid)) return 0;
        int d = broker_decide(t, sc, "opaque", "cross-process", NULL, 0,
                              "\"target\":\"external-pid\"", 1);
        return apply_decision(t, d, exit_code);
    }
    /* Cross-process identity comparison, exported file handles, fanotify
     * host-wide observation: opaque capability, full approval only. */
    if (nr == 312 || nr == 303 || nr == 300 || nr == 301) {
        int d = broker_decide(t, sc, "opaque", "capability", NULL, 0,
                              "\"cap\":\"unmonitorable\"", 1);
        return apply_decision(t, d, exit_code);
    }
    /* fcntl(fd, F_NOTIFY) is legacy directory surveillance: read boundary
     * on the fd's target. Other fcntl commands are fd-local. */
    if (nr == 72 && (long)r->rsi == F_NOTIFY) {
        const char *fp = fd_path_or_null(t, (long)r->rdi, fdbuf);
        if (fp) {
            int d = check_path(t, sc, "read", "watch", fp, details);
            if (d != GATE_PASS)
                return apply_decision(t, d, exit_code);
        }
        return 0;
    }

    /* inotify watch on a path is surveillance of that object: read boundary. */
    if (nr == 254) {
        if (resolve_at(t->tid, AT_FDCWD, (uintptr_t)r->rsi, resolved)) {
            int d = check_path(t, sc, "read", "watch", resolved, details);
            if (d != GATE_PASS)
                return apply_decision(t, d, exit_code);
        }
        return 0;
    }

    /* Signals to pids outside the traced tree are host interactions. */
    if (nr == 62 || nr == 200 || nr == 234 || nr == 129 || nr == 297 || nr == 424) {
        /* Signal 0 delivers nothing: it only probes whether the target
         * exists, which /proc already reveals (uutils `tail` does kill(0,0)). */
        unsigned long long sig = (nr == 234 || nr == 297) ? r->rdx : r->rsi;
        if (sig == 0) return 0;
        long pid = nr == 424 ? -1 : (long)r->rdi;
        if (nr == 424 || pid <= 0 || !tgid_in_tree((pid_t)pid)) {
            int d = broker_decide(t, sc, "opaque", "signal", NULL, 0,
                                  "\"target\":\"external-pid\"", 1);
            return apply_decision(t, d, exit_code);
        }
        return 0;
    }

    /* Opaque cross-process / unbounded-capability events: SysV IPC, POSIX
     * mq, kernel keyrings, cross-process fd/memory access, kernel log. */
    switch (nr) {
    case 29: case 30: case 31: case 64: case 65: case 66: case 220:
    case 68: case 69: case 70: case 71:
    case 240: case 241: case 242: case 243: case 244: case 245:
    case 248: case 249: case 250:
    case 438: case 440: case 448: case 103: {
        int d = broker_decide(t, sc, "opaque", "ipc", NULL, 0, details, 1);
        return apply_decision(t, d, exit_code);
    }
    default: break;
    }

    if (nr == 157 && r->rdi == PR_SET_PTRACER) {
        int d = broker_decide(t, sc, "opaque", "capability", NULL, 0,
                              "\"option\":\"PR_SET_PTRACER\"", 1);
        return apply_decision(t, d, exit_code);
    }

    /* Unknown/future syscall numbers default to an opaque boundary event:
     * a new kernel primitive cannot slip past silently. */
    if (nr > LAST_KNOWN_NR || nr < 0) {
        snprintf(details, sizeof(details), "\"nr\":%ld", nr);
        int d = broker_decide(t, sc, "opaque", "opaque", NULL, 0, details, 1);
        return apply_decision(t, d, exit_code);
    }
    return 0;
}

/* Numbers whose entry (or exit, for recvmsg) can produce a boundary event.
 * pause_siblings — the TOCTOU freeze — is only worth paying for these; a
 * syscall outside this set never consults tracee memory and can be resumed
 * immediately. Keep in sync with gate_entry. */
static int nr_may_gate(long nr)
{
    if (nr > LAST_KNOWN_NR || nr < 0) return 1; /* unknown -> opaque event */
    switch (nr) {
    case 101: case 304: case 310: case 311:      /* ptrace, open_by_handle_at, process_vm_* */
    case 206: case 207: case 208: case 209: case 210: case 333: /* AIO */
    case 425: case 426: case 427:                /* io_uring */
    case 321: case 298:                          /* bpf, perf_event_open */
    case 56: case 435:                           /* clone/clone3 */
    case 59: case 322:                           /* execve/execveat */
    /* path-taking write family */
    case 76: case 82: case 83: case 84: case 85: case 86: case 87: case 88:
    case 90: case 92: case 94: case 132: case 133:
    case 188: case 189: case 197: case 198: case 235:
    case 258: case 259: case 260: case 261: case 263:
    case 264: case 316: case 265: case 266:
    case 268: case 452: case 280: case 463: case 466:
    /* open family */
    case 2: case 257: case 437:
    /* fd-based writes */
    case 1: case 20: case 18: case 296: case 328:
    case 77: case 285: case 91: case 93:
    case 190: case 199: case 40: case 275: case 276: case 326:
    /* mmap family */
    case 9: case 26: case 10: case 329:
    /* network / IPC */
    case 42: case 49: case 50: case 43: case 288:
    case 44: case 46: case 307: case 47: case 299:
    /* privilege */
    case 165: case 166: case 155: case 161: case 272: case 308:
    case 428: case 429: case 430: case 431: case 432: case 433: case 442:
    case 163: case 167: case 168: case 169: case 153: case 172: case 173:
    case 175: case 176: case 313: case 246: case 320:
    case 170: case 171: case 164: case 227: case 159: case 305:
    case 179: case 443:
    /* signals outside the tree */
    case 62: case 200: case 234: case 129: case 297: case 424:
    /* opaque cross-process */
    case 29: case 30: case 31: case 64: case 65: case 66: case 220:
    case 68: case 69: case 70: case 71:
    case 240: case 241: case 242: case 243: case 244: case 245:
    case 248: case 249: case 250:
    case 438: case 440: case 448: case 103:
    case 157:                                    /* prctl (PR_SET_PTRACER) */
    /* ioctl + cross-process/surveillance checks */
    case 16:
    case 302: case 203: case 204: case 314: case 315: case 279: case 256:
    case 251: case 434: case 312: case 303: case 300: case 301:
    case 254: case 72:
        return 1;
    default:
        return 0;
    }
}

/* Exit-side checks (recvmsg family SCM_RIGHTS). */
static int gate_exit(Tracee *t, struct user_regs_struct *r, int *exit_code)
{
    if (t->pending_recv) {
        int nr = t->pending_recv;
        t->pending_recv = 0;
        if ((long long)r->rax >= 0) {
            uintptr_t mh = t->recv_msghdr;
            int vlen = t->recv_vlen > 8 ? 8 : t->recv_vlen;
            for (int i = 0; i < vlen; i++) {
                if (has_scm_rights(t, mh + (uintptr_t)i * 64)) {
                    int d = broker_decide(t, sc_name(nr), "opaque", "recvfd",
                                          NULL, 0, "\"channel\":\"SCM_RIGHTS\"", 1);
                    return apply_decision(t, d, exit_code);
                }
            }
        }
    }
    return 0;
}

/* ------------------------------------------------------------------ */
/* Main supervision loop                                               */
/* ------------------------------------------------------------------ */

static pid_t spawn_child(char *const *argv)
{
    pid_t pid = fork();
    if (pid < 0) die("fork: %s", strerror(errno));
    if (pid == 0) {
        /* Own process group so the supervisor can kill the whole payload
         * tree (incl. after an 'allow' detach) with killpg, while the
         * watcher itself stays outside the group. */
        setpgid(0, 0);
        /* The payload must not inherit the supervisor's cancel handlers —
         * between fork and exec a TERM would otherwise be swallowed by our
         * flag-setting handler instead of killing the child. */
        signal(SIGTERM, SIG_DFL);
        signal(SIGINT, SIG_DFL);
        signal(SIGHUP, SIG_DFL);
        /* Restore code-hook environment deferred by the broker side: the
         * outer host shell ran with <storage> copies instead of the real
         * names (so BASH_ENV/exported functions/LD_* could not execute
         * unmonitored inside the untraced wrapper). Only the exact mapping
         * declared via --defer <storage>=<real> is restored — env vars that
         * merely share the prefix pass through untouched, and nothing the
         * wrapper did not create is deleted. */
        for (int di = 0; di < g_ndefer; di++) {
            const char *v = getenv(g_defer_store[di]);
            if (v) setenv(g_defer_real[di], v, 1);
            unsetenv(g_defer_store[di]);
        }
        /* Close every inherited fd > 2 (incl. the broker socket), stop for
         * seizure, then exec the payload shell. */
        {
            DIR *d = opendir("/proc/self/fd");
            if (d) {
                struct dirent *e;
                int dfd = dirfd(d);
                while ((e = readdir(d))) {
                    int fd = atoi(e->d_name);
                    if (fd > 2 && fd != dfd) close(fd);
                }
                closedir(d);
            }
        }
        raise(SIGSTOP);
        execv(argv[0], argv);
        _exit(127);
    }
    return pid;
}

/* Drive the entry gate for a tid stopped at (or held at) a syscall
 * entry. Called from handle_stop for fresh entry stops and from
 * release_fd_holds for held tids whose conflict just cleared — a held
 * syscall must still pass its own boundary check before it may run.
 * Owns the restart: returns RC_DETACHED (tree detached — never restart),
 * or 0 after either leaving the tid held (no restart) or resuming it. */
static int entry_gate(Tracee *t, int *exit_code)
{
    pid_t p = t->tid;
    struct user_regs_struct r;
    if (get_regs(p, &r) < 0) {
        if (g_fail_open)
            return observer_failure("observer_registers", "payload registers could not be inspected", 0);
        if (t->hold_sibs) { t->hold_sibs = 0;
                            resume_paused_siblings(t->tgid, p); }
        t->dead = 1;
        clear_inflight(t);
        return 0;
    }
    if (getenv("BW_DEBUG"))
        fprintf(stderr, "[bw] tid=%d %s nr=%lld rip=%llx rax=%llx rsi=%llx\n",
                (int)p, "entry", (long long)r.orig_rax,
                (unsigned long long)r.rip, (unsigned long long)r.rax,
                (unsigned long long)r.rsi);
    t->in_syscall = 1;
    /* Freeze sibling threads only for syscalls that actually read tracee
     * memory or can decide on a boundary — a plain getpid() must not pay
     * the pause/resume round-trip. recvmsg family is the exception: the
     * dangerous part (cmsg) lands at syscall EXIT, so the freeze happens
     * there instead — freezing a blocking recv at entry could starve the
     * sibling that supplies the data. */
    long nr = (long)r.orig_rax;
    /* clone_flags below belong to the syscall entering NOW — stale flags
     * from an earlier clone must never bless a later fork. */
    t->clone_flags_valid = 0;
    /* Rebind of an in-flight fd binding — or an fd allocation while a
     * closed-slot observation is in flight: this syscall is held at its
     * own entry stop, before it runs, until the consuming syscall exits.
     * Only the conflicting syscall waits; every other sibling operation
     * keeps running, so ordinary pipe concurrency (and the threads a
     * blocking pipe op may rendezvous with) is untouched. */
    {
        long lo = -1, hi = -1;
        int kind = fd_hold_class(nr, &r, &lo, &hi);
        if (getenv("BW_DEBUG") && kind)
            fprintf(stderr, "[bw %.3f] tid=%d holdtest nr=%ld kind=%d "
                    "lo=%ld hi=%ld -> %d\n",
                    bw_now(), (int)p, nr, kind, lo, hi,
                    fd_hold_conflict(t, kind, lo, hi));
        if (kind && fd_hold_conflict(t, kind, lo, hi)) {
            t->held_kind = kind;
            t->held_lo = lo;
            t->held_hi = hi;
            if (getenv("BW_DEBUG"))
                fprintf(stderr, "[bw] tid=%d HELD nr=%ld kind=%d "
                        "lo=%ld hi=%ld\n", (int)p, nr, kind, lo, hi);
            return 0; /* released by release_fd_holds -> re-enters here */
        }
    }
    int recvish = (nr == 47 || nr == 299);
    int paused = 0;
    if (nr_may_gate(nr) && !recvish) {
        if (pause_siblings(t->tgid, p) < 0)
            return observer_failure("observer_freeze", "a payload thread could not be frozen for the "
                      "boundary check", 0);
        paused = 1;
    }
    g_gate_used_mutable = 0;
    g_ngate_fds = 0;
    g_gate_saw_racy_fd = 0;
    int rc = gate_entry(t, &r, exit_code);
    memcpy(t->inflight_fds, g_gate_fds,
           (size_t)g_ngate_fds * sizeof(long));
    memcpy(t->inflight_kind, g_gate_fd_kind,
           (size_t)g_ngate_fds * sizeof(char));
    t->inflight_nfds = g_ngate_fds;
    if (paused && rc != RC_DETACHED) {
        if (g_gate_used_mutable) {
            /* The check consulted mutable tracee state (a path string, a
             * sockaddr/msghdr, an fd that resolves to a real path). Keep
             * the freeze until THIS syscall's exit stop so a sibling
             * cannot rewrite it between check and execution. */
            t->hold_sibs = 1;
        } else {
            /* Nothing mutable was consulted (e.g. a write to a pipe):
             * holding the freeze would only starve a same-process
             * rendezvous — release it now. */
            resume_paused_siblings(t->tgid, p);
        }
    }
    /* Test-only: stretch the consumer's decision→execution window, then
     * sweep pending sibling stops into the deferred queue BEFORE this tid
     * restarts. Non-mutable gates already unfroze siblings above, so a
     * sibling's rebind/allocator issued during the window queues its
     * entry stop; the sweep makes it deferred, and the main loop replays
     * deferred stops BEFORE the next waitpid — i.e. while this syscall's
     * in-flight record is still live. That turns the hold decision
     * deterministic instead of racing waitpid's sibling-iteration order.
     * Both only delay this tid longer; neither can widen a check. */
    if (g_postgate_delay_ms && g_gate_saw_racy_fd && rc != RC_DETACHED) {
        if (getenv("BW_DEBUG"))
            fprintf(stderr, "[bw] tid=%d delay %ldms nr=%ld nfds=%d\n",
                    (int)p, g_postgate_delay_ms, nr, t->inflight_nfds);
        usleep((useconds_t)g_postgate_delay_ms * 1000);
    }
    if (g_pregate_delay_ms && g_gate_saw_racy_fd && rc != RC_DETACHED &&
        live_sibling_count(t->tgid, p) > 0)
        pregate_drain();
    if (rc != RC_DETACHED)
        ptrace(PTRACE_SYSCALL, p, 0, 0);
    return rc;
}

/* Handle one waitpid stop. Returns 0 to keep watching, 2 to exit with
 * *exit_code set (post-'allow' native run finished). */
static int handle_stop(Tracee *t, int st, int *exit_code)
{
    pid_t p = t->tid;
    int sig = WSTOPSIG(st);
    int event = (st >> 16) & 0xffff;

    if (t->first_stop) {
        t->first_stop = 0;
        /* A born-running clone child's first syscall stop can be either
         * an ENTRY or an EXIT — the stop alone cannot tell. Skipping an
         * ENTRY would leave an ungated syscall running and invert
         * in_syscall for the tid's whole life (its later EXIT would
         * masquerade as an entry). Ask the kernel: a real ENTRY falls
         * through and is gated below; an EXIT only needs the phase set —
         * its boundary was decided in the kernel before we ever saw the
         * tid. Anything else (or an old kernel without the request)
         * resumes normally as before. */
        if (sig == SIGTRAP && !event) {
            struct ptrace_syscall_info si;
            memset(&si, 0, sizeof(si));
            long sn = ptrace(PTRACE_GET_SYSCALL_INFO, p,
                             (void *)(long)sizeof(si), &si);
            if (sn >= (long)offsetof(struct ptrace_syscall_info, op) + 1) {
                if (si.op == PTRACE_SYSCALL_INFO_ENTRY)
                    return entry_gate(t, exit_code); /* real entry: gate it */
                if (si.op == PTRACE_SYSCALL_INFO_EXIT)
                    t->in_syscall = 1; /* this WAS an exit stop */
            }
        }
        ptrace(PTRACE_SYSCALL, p, 0, 0);
        return 0;
    }
    if (event == PTRACE_EVENT_FORK || event == PTRACE_EVENT_VFORK ||
        event == PTRACE_EVENT_CLONE) {
        unsigned long np = 0;
        ptrace(PTRACE_GETEVENTMSG, p, 0, &np);
        Tracee *nt = tid_register((pid_t)np);
        /* The event NAME does not say whether the fd table is shared:
         * clone() reports FORK when its exit signal is SIGCHLD even with
         * CLONE_FILES set, and vfork has its own event. Decide from the
         * creating syscall's recorded flags instead — plain fork/vfork
         * (and any non-clone syscall) left clone_flags_valid cleared, so
         * their children always get a private-table identity. */
        if (nt && t->clone_flags_valid && (t->clone_flags & CLONE_FILES))
            nt->files_id = t->files_id;
        if (getenv("BW_DEBUG"))
            fprintf(stderr, "[bw] cloneev parent=%d new=%d flags=%llx "
                    "valid=%d files=%d->%d\n", (int)p, (int)np,
                    (unsigned long long)t->clone_flags,
                    t->clone_flags_valid, nt ? (int)nt->files_id : -1,
                    (int)t->files_id);
        ptrace(PTRACE_SYSCALL, p, 0, 0);
        return 0;
    }
    if (event == PTRACE_EVENT_STOP) {
        /* Our own interrupt stop for a sibling pause, or a late one for a
         * tid already resumed: either way just keep it moving/stopped. */
        if (t->paused_for) t->paused_confirmed = 1;
        else ptrace(PTRACE_SYSCALL, p, 0, 0);
        return 0;
    }
    if (event == PTRACE_EVENT_EXEC || event == PTRACE_EVENT_EXIT ||
        event == PTRACE_EVENT_VFORK_DONE) {
        if (t->hold_sibs) { t->hold_sibs = 0;
                            resume_paused_siblings(t->tgid, p); }
        /* Same ordering anchor as the syscall-exit path: pending sibling
         * stops must be decided while this tid's records are still
         * live. Re-queue this event behind them once. */
        if (g_pregate_delay_ms && t->inflight_nfds && !t->exit_requeued &&
            sweep_pending_to_deferred() > 0) {
            t->exit_requeued = 1;
            defer_stop(p, st);
            return 0;
        }
        /* Restart BEFORE releasing fd-holds: a released sibling re-drives
         * its entry gate, which may pause siblings — a stopped tid with
         * no pending stop can never confirm an interrupt and would wedge
         * the pause; a running one confirms normally. */
        ptrace(PTRACE_SYSCALL, p, 0, 0);
        clear_inflight(t); /* the consuming syscall finished or died */
        return 0;
    }
    if (sig != SIGTRAP) {
        ptrace(PTRACE_SYSCALL, p, 0, (void *)(long)sig);
        return 0;
    }

    struct user_regs_struct r;
    if (get_regs(p, &r) < 0) {
        if (g_fail_open)
            return observer_failure("observer_registers", "payload registers could not be inspected", 0);
        if (t->hold_sibs) { t->hold_sibs = 0;
                            resume_paused_siblings(t->tgid, p); }
        t->dead = 1;
        clear_inflight(t);
        return 0;
    }
    if (!t->in_syscall) {
        /* entry_gate owns the restart for this path (a released fd-hold
         * re-enters it too) — the tail below only restarts exit stops. */
        return entry_gate(t, exit_code);
    }
    if (getenv("BW_DEBUG"))
        fprintf(stderr, "[bw] tid=%d %s nr=%lld rip=%llx rax=%llx rsi=%llx\n",
                (int)p, "exit ",
                (long long)r.orig_rax, (unsigned long long)r.rip,
                (unsigned long long)r.rax, (unsigned long long)r.rsi);
    if (t->inject_errno) {
        r.rax = (unsigned long long)(-(long long)t->inject_errno);
        t->inject_errno = 0;
        if (set_regs(p, &r) < 0)
            kill_tree("a refused payload syscall could not return its error", 1);
    }
    /* The gated syscall completed: lift the entry freeze first, run the
     * exit gate while the tid still sits at its stop (recv cmsg inspects
     * its buffer), then restart it BEFORE clearing the fd records —
     * released siblings re-drive their entry gates and may pause
     * siblings; a stopped tid with no pending stop can never confirm an
     * interrupt (pause timeout → fail-closed kill), a running one
     * confirms normally. */
    if (t->hold_sibs) {
        t->hold_sibs = 0;
        resume_paused_siblings(t->tgid, p);
    }
    if (t->pending_recv &&
        pause_siblings(t->tgid, p) < 0)
        return observer_failure("observer_freeze", "a payload thread could not be frozen for the "
                  "boundary check", 0);
    /* Test-only ordering anchor: a sibling rebind/allocator stop that
     * arrived late still races this exit stop in waitpid's arbitrary
     * order. Sweep pending stops into the deferred queue FIRST, then
     * re-queue this exit stop behind them: the sibling replays while the
     * in-flight records are still live (held deterministically), then
     * this exit replays and releases. in_syscall stays set so the replay
     * re-enters this exit path; exit_requeued bounds it to one pass. */
    if (g_pregate_delay_ms && t->inflight_nfds && !t->exit_requeued &&
        sweep_pending_to_deferred() > 0) {
        t->exit_requeued = 1;
        defer_stop(p, st);
        return 0;
    }
    g_at_exit_stop = 1;
    int rc = gate_exit(t, &r, exit_code);
    g_at_exit_stop = 0;
    resume_paused_siblings(t->tgid, p);
    if (rc == RC_DETACHED) return 0; /* tid was detached; never resume it */
    ptrace(PTRACE_SYSCALL, p, 0, 0);
    clear_inflight(t); /* consuming syscall finished: release fd-holds */
    t->in_syscall = 0;
    return 0;
}

/* Wait for the next child waitpid report OR broker-channel failure.
 * SIGCHLD is blocked process-wide and consumed through signalfd, so this
 * never busy-loops. Returns:
 *   >0  pid with a pending waitpid status (in *st_out)
 *   -1  no children remain (ECHILD)
 *   -2  broker socket EOF/HUP/ERR or unexpected unsolicited traffic
 * 0 is impossible. */
static int g_sigfd = -1;

/* Idle traffic is a control frame, not a syscall reply. A started frame must
 * finish within one second and 511 bytes. Truncation/timeout conservatively
 * cancels: a fragmented user cancel must never become a fail-open EOF. */
static int read_idle_control(void)
{
    char line[512];
    size_t off = 0;
    double deadline = bw_now() + 1.0;
    for (;;) {
        if (g_term_signal) return -3;
        int remaining = (int)((deadline - bw_now()) * 1000);
        if (remaining <= 0) return -3;
        struct pollfd fd = { g_broker_fd, POLLIN, 0 };
        int ready = poll(&fd, 1, remaining);
        if (ready < 0 && errno == EINTR) continue;
        if (ready <= 0) return -3;
        char byte;
        ssize_t count = recv(g_broker_fd, &byte, 1, MSG_DONTWAIT);
        if (count < 0 && (errno == EINTR || errno == EAGAIN)) continue;
        if (count <= 0) return off ? -3 : -2;
        if (byte == '\n') {
            line[off] = 0;
            return is_cancel_frame(line) ? -3 : -2;
        }
        if (off + 1 >= sizeof(line)) return -3;
        line[off++] = byte;
    }
}

static int wait_event(int *st_out)
{
    for (;;) {
        if (g_term_signal) return -3; /* host cancel: TERM/INT/HUP */
        pid_t p = waitpid(-1, st_out, __WALL | WNOHANG);
        if (p > 0) return p;
        if (p < 0) {
            if (errno == EINTR) continue;
            return -1; /* ECHILD: no children left */
        }
        struct pollfd fds[2] = {
            { g_sigfd, POLLIN, 0 },
            { g_broker_fd, POLLIN | POLLRDHUP, 0 },
        };
        int pr = poll(fds, 2, -1);
        if (getenv("BW_DEBUG"))
            fprintf(stderr, "[bw] poll pr=%d sigfd=%d rev=%x broker=%d rev=%x\n",
                    pr, fds[0].fd, fds[0].revents, fds[1].fd, fds[1].revents);
        if (pr < 0) {
            if (errno == EINTR) continue;
            return -4; /* supervision poll broke: fail closed */
        }
        if (fds[1].revents) {
            /* Verify channel death before killing: revents alone can be
             * ambiguous (POLLIN|POLLRDHUP races). A peek of 0 IS the EOF —
             * definitive, no probe needed (a zero-byte send() can succeed
             * even on a FIN'd socket and must not veto it). Only a bare
             * HUP/RDHUP with no data needs the probe write. */
            char probe[64];
            ssize_t pn = recv(g_broker_fd, probe, sizeof(probe),
                              MSG_PEEK | MSG_DONTWAIT);
            int dead = 0;
            if (pn == 0 || pn > 0)
                dead = 1; /* EOF, or unsolicited bytes: protocol violation */
            else if (fds[1].revents & (POLLNVAL | POLLERR))
                dead = 1;
            else if (fds[1].revents & (POLLHUP | POLLRDHUP)) {
                ssize_t sn = send(g_broker_fd, "", 0,
                                  MSG_NOSIGNAL | MSG_DONTWAIT);
                int se = errno;
                if (getenv("BW_DEBUG"))
                    fprintf(stderr, "[bw %.3f] broker revents=0x%x peek=%zd "
                                    "send=%zd errno=%d\n",
                            bw_now(), fds[1].revents, pn, sn, se);
                if (sn < 0 &&
                    (se == EPIPE || se == ECONNRESET || se == ENOTCONN))
                    dead = 1;
            }
            if (dead) {
                if (pn > 0) {
                    return read_idle_control();
                }
                return -2;
            }
        }
        if (fds[0].revents & POLLIN) {
            struct signalfd_siginfo si;
            while (read(g_sigfd, &si, sizeof(si)) == sizeof(si)) {}
        }
    }
}

int main(int argc, char **argv)
{
    setvbuf(stderr, NULL, _IONBF, 0);
    clock_gettime(CLOCK_MONOTONIC, &g_t0);
    g_self_pid = getpid();

    /* Discover the payload before setup parsing, so even a stale canonical
     * root or an unsupported observer option can degrade losslessly. */
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--") == 0) {
            if (i + 1 < argc) g_payload_argv = &argv[i + 1];
            break;
        }
        if (strcmp(argv[i], "--fail-open") == 0) g_fail_open = 1;
    }

    const char *shell_args[64];
    int nargs = 0;
    static char dbuf[MAX_ROOTS][PATH_MAX];
    static char wbuf[MAX_ROOTS][PATH_MAX];
    for (int i = 1; i < argc; i++) {
        const char *a = argv[i];
        if (strcmp(a, "--fail-open") == 0) {
            g_fail_open = 1;
        } else if (strcmp(a, "--broker") == 0 && i + 1 < argc) {
            g_broker_path = argv[++i];
        } else if (strcmp(a, "--token") == 0 && i + 1 < argc) {
            i++;
            snprintf(g_token, sizeof(g_token), "%s", argv[i]);
            memset(argv[i], 'x', strlen(argv[i]));
        } else if (strcmp(a, "--root") == 0 && i + 1 < argc) {
            if (g_nroots >= MAX_ROOTS) die("too many --root entries");
            i++;
            char canon[PATH_MAX];
            /* canon_path realpaths the deepest existing ancestor and keeps
             * the not-yet-existing suffix: a file root (tool history file)
             * need not exist beforehand. The strcmp keeps the caller-side
             * contract that argv[i] is already that canonical form. */
            if (!canon_path(argv[i], canon) || strcmp(canon, argv[i]) != 0)
                die("--root must be a canonical path: %s", argv[i]);
            g_roots[g_nroots++] = argv[i];
        } else if (strcmp(a, "--deny-read") == 0 && i + 1 < argc) {
            if (g_ndeny_read >= MAX_ROOTS) die("too many --deny-read entries");
            i++;
            if (!canon_path(argv[i], dbuf[g_ndeny_read])) die("bad --deny-read path");
            g_deny_read[g_ndeny_read] = dbuf[g_ndeny_read];
            g_ndeny_read++;
        } else if (strcmp(a, "--deny-write") == 0 && i + 1 < argc) {
            if (g_ndeny_write >= MAX_ROOTS) die("too many --deny-write entries");
            i++;
            if (!canon_path(argv[i], wbuf[g_ndeny_write])) die("bad --deny-write path");
            g_deny_write[g_ndeny_write] = wbuf[g_ndeny_write];
            g_ndeny_write++;
        } else if (strcmp(a, "--protect") == 0 && i + 1 < argc) {
            if (g_nprotect >= MAX_ROOTS) die("too many --protect entries");
            i++;
            static char pbuf[MAX_ROOTS][PATH_MAX];
            if (!canon_path(argv[i], pbuf[g_nprotect])) die("bad --protect path");
            g_protect[g_nprotect] = pbuf[g_nprotect];
            g_nprotect++;
        } else if (strcmp(a, "--defer") == 0 && i + 1 < argc) {
            if (g_ndefer >= 256) die("too many --defer entries");
            i++;
            char *eq = strchr(argv[i], '=');
            if (!eq || eq == argv[i] || !eq[1])
                die("--defer must be <storage>=<name>");
            *eq = 0; /* split argv pair in place */
            g_defer_store[g_ndefer] = argv[i];
            g_defer_real[g_ndefer] = eq + 1;
            g_ndefer++;
        } else if (strcmp(a, "--readonly") == 0) {
            g_readonly = 1;
        } else if (strcmp(a, "--approve-timeout-ms") == 0 && i + 1 < argc) {
            i++;
            char *end = NULL;
            long v = strtol(argv[i], &end, 10);
            if (!end || *end || v < 5000 || v > 900000)
                die("--approve-timeout-ms must be 5000..900000");
            g_approve_timeout_ms = v;
        } else if (strcmp(a, "--") == 0) {
            for (int k = i + 1; k < argc && nargs < 63; k++)
                shell_args[nargs++] = argv[k];
            break;
        } else {
            die("unknown argument: %s", a);
        }
    }
    if (!g_broker_path || !g_token[0] || nargs < 1)
        die("usage: opencode-boundary-watch --broker <sock> --token <hex64> "
            "--root <path> [--readonly] [--deny-read p] [--deny-write p] "
            "[--protect p] [--defer s=n] [--approve-timeout-ms N] "
            "-- <shell> -c <script>");
    shell_args[nargs] = NULL;
    if (shell_args[0][0] != '/') die("payload executable must be absolute");

    /* Test-only knobs — each only narrows the payload's own freedom
     * (extra delay, forced verification failure); none can widen a
     * check. */
    {
        const char *d = getenv("BW_TEST_POSTGATE_DELAY_MS");
        if (d) {
            g_postgate_delay_ms = atol(d);
            if (g_postgate_delay_ms < 0) g_postgate_delay_ms = 0;
            if (g_postgate_delay_ms > 30000) g_postgate_delay_ms = 30000;
        }
        d = getenv("BW_TEST_PREGATE_DELAY_MS");
        if (d) {
            g_pregate_delay_ms = atol(d);
            if (g_pregate_delay_ms < 0) g_pregate_delay_ms = 0;
            if (g_pregate_delay_ms > 30000) g_pregate_delay_ms = 30000;
        }
    }

    /* Subreaper: payload descendants orphaned by kills (or by detached
     * parents dying first) reparent HERE, not to init — so a cancel can
     * still find and kill them, and waitpid(-1) ECHILD truthfully means
     * "the whole tree is gone". The cancel guarantee is load-bearing: if
     * the kernel refuses it, claim nothing and stop before spawning. */
    if (getenv("BW_TEST_SUBREAPER_FAIL") /* test-only injection */
            ? (errno = EOPNOTSUPP, 1)
            : prctl(PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0) < 0)
        die("PR_SET_CHILD_SUBREAPER: %s", strerror(errno));

    /* SIGCHLD is consumed via signalfd so the supervision loop can poll it
     * together with the broker socket — a broker disconnect (mode or lease
     * revoked) must abort even a quiescent payload. */
    sigset_t chld_mask;
    sigemptyset(&chld_mask);
    sigaddset(&chld_mask, SIGCHLD);
    if (sigprocmask(SIG_BLOCK, &chld_mask, NULL) < 0)
        die("sigprocmask: %s", strerror(errno));
    g_sigfd = signalfd(-1, &chld_mask, SFD_CLOEXEC | SFD_NONBLOCK);
    if (g_sigfd < 0) die("signalfd: %s", strerror(errno));

    /* Host cancel signals (TERM/INT/HUP — e.g. the host spawner's process
     * .kill()) only arm a flag: every wait loop polls it so teardown can
     * reap the WHOLE payload tree — detached and orphaned descendants
     * included (ptrace EXITKILL stops working the moment we detach, so
     * without this a host SIGTERM would strand them). The payload child
     * resets these to SIG_DFL between fork and exec. */
    {
        struct sigaction sac;
        memset(&sac, 0, sizeof(sac));
        sac.sa_handler = on_term_signal;
        sigemptyset(&sac.sa_mask);
        sigaction(SIGTERM, &sac, NULL);
        sigaction(SIGINT, &sac, NULL);
        sigaction(SIGHUP, &sac, NULL);
    }

    /* The broker channel is opened AFTER the payload child exists and is
     * seized: the child never inherits the socket fd at all (stronger than
     * relying on its own close-all-fds sweep). */
    pid_t root = spawn_child((char *const *)shell_args);
    g_root_pid = root;

    int st;
    /* The child is not yet traced: its raise(SIGSTOP) needs WUNTRACED. */
    for (;;) {
        if (waitpid(root, &st, WUNTRACED | WNOHANG) == root) break;
        struct pollfd fds[1] = { { g_sigfd, POLLIN, 0 } };
        int pr = poll(fds, 1, -1);
        if (pr < 0 && errno != EINTR) die("poll: %s", strerror(errno));
        if (pr > 0 && (fds[0].revents & POLLIN)) {
            struct signalfd_siginfo si;
            while (read(g_sigfd, &si, sizeof(si)) == sizeof(si)) {}
        }
    }
    if (!WIFSTOPPED(st)) die("child did not stop for seizure");

    unsigned opts = PTRACE_O_TRACEFORK | PTRACE_O_TRACEVFORK |
        PTRACE_O_TRACECLONE | PTRACE_O_TRACEEXEC | PTRACE_O_TRACEEXIT |
        PTRACE_O_EXITKILL;
    if (getenv("BW_TEST_SEIZE_FAIL") ? (errno = EPERM, 1) : ptrace(PTRACE_SEIZE, root, 0, opts) < 0)
        die("PTRACE_SEIZE: %s", strerror(errno));

    /* Connect the broker channel now that the payload is seized (the child
     * never inherits the fd). If the broker is unreachable, kill the
     * stopped child and die before any payload instruction runs. */
    {
        struct sockaddr_un sa;
        memset(&sa, 0, sizeof(sa));
        sa.sun_family = AF_UNIX;
        if (strlen(g_broker_path) >= sizeof(sa.sun_path)) {
            if (g_fail_open) setup_fail_open();
            kill(root, SIGKILL);
            die("broker path too long");
        }
        snprintf(sa.sun_path, sizeof(sa.sun_path), "%s", g_broker_path);
        g_broker_fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
        if (g_broker_fd < 0 ||
            connect(g_broker_fd, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
            if (g_fail_open) setup_fail_open();
            kill(root, SIGKILL);
            die("cannot connect to broker socket: %s", strerror(errno));
        }
    }

    Tracee *rt = tid_register(root);
    if (!rt) die("tracee table full");
    rt->first_stop = 0;
    ptrace(PTRACE_SYSCALL, root, 0, 0);

    /* Terminal semantics: the root's exit only RECORDS the result. The
     * single exit frame goes out when the whole tree is really gone
     * (waitpid ECHILD — we are parent or subreaper of every descendant).
     * A broker EOF at any point is a cancel, never "broker retired early":
     * the broker only closes after the helper exits or on revoke. */
    int exit_code = 255; /* overwritten by the root's real code; a bug must
                          * never ship a fabricated 0 to the broker */
    for (;;) {
        Deferred df;
        if (!g_detached && defer_pop_ready(&df)) {
            Tracee *t = tid_find(df.tid);
            if (!t) continue;
            if (WIFEXITED(df.status) || WIFSIGNALED(df.status)) {
                if (t->hold_sibs) { t->hold_sibs = 0;
                                    resume_paused_siblings(t->tgid, t->tid); }
                t->dead = 1;
                clear_inflight(t);
                if (df.tid == root)
                    exit_code = WIFEXITED(df.status)
                                ? WEXITSTATUS(df.status)
                                : 128 + WTERMSIG(df.status);
                continue;
            }
            if (handle_stop(t, df.status, &exit_code) == RC_DETACHED)
                g_detached = 1;
            continue;
        }
        pid_t p = wait_event(&st);
        if (p == -1) break;                       /* tree fully reaped */
        if (p == -2) {
            observer_failure("broker_eof", "the broker channel closed (command cancelled)", 0);
            close(g_broker_fd);
            g_broker_fd = -1;
            continue;
        }
        if (p == -3)
            kill_tree("the supervisor was terminated (cancelled)", 0);
        if (p == -4) {
            observer_failure("observer_poll", "supervision failed (poll error)", 0);
            continue;
        }
        Tracee *t = tid_find(p);
        if (!t) {
            t = tid_register(p);
            if (!t) { kill(p, SIGKILL); continue; }
        }
        if (WIFEXITED(st) || WIFSIGNALED(st)) {
            if (t->hold_sibs) { t->hold_sibs = 0;
                                resume_paused_siblings(t->tgid, t->tid); }
            /* Same ordering anchor: sibling stops pending at this death
             * report must still be decided against the live records. */
            if (g_pregate_delay_ms && t->inflight_nfds &&
                !t->exit_requeued && sweep_pending_to_deferred() > 0) {
                t->exit_requeued = 1;
                defer_stop(p, st);
                continue;
            }
            t->dead = 1;
            clear_inflight(t);
            if (p == root)
                exit_code = WIFEXITED(st) ? WEXITSTATUS(st)
                                          : 128 + WTERMSIG(st);
            /* Detached descendants may still be alive — keep supervising
             * until waitpid reports ECHILD; a broker close before then is
             * a cancel and must reach them. */
            continue;
        }
        if (!WIFSTOPPED(st) || g_detached) continue;
        if (handle_stop(t, st, &exit_code) == RC_DETACHED)
            g_detached = 1;
    }
    /* The root may have been reaped inside detach_all's interrupt-drain;
     * its real code wins over the default. */
    if (g_root_reaped_exit >= 0)
        exit_code = g_root_reaped_exit;
    /* Drain stragglers so no traced child outlives the watcher. */
    for (;;) {
        pid_t q = waitpid(-1, &st, __WALL | WNOHANG);
        if (q <= 0) break;
    }
    /* Terminal notification — sent exactly once, only now that the whole
     * tree is reaped (or the watcher is exiting after a quiet teardown):
     * the broker learns the real exit code and retires the call; no reply
     * is expected. */
    broker_send_exit(exit_code);
    return exit_code;
}
