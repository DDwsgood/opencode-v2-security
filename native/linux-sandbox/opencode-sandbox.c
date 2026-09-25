// opencode-sandbox — OS-level sandbox helper for opencode-v2-security.
//
// One binary, two stages:
//   stage1  opencode-sandbox -c <cmd>
//           Probes bwrap/userns/Landlock once, picks a sandbox path per the
//           §3.4 decision table, execs bwrap with the RO/RW floor argv ending
//           in this binary re-invoked as --stage2.
//   stage2  opencode-sandbox --stage2 --mode ro|rw [--no-landlock]
//                                 [--af-unix-block] --real-bash <path>
//                                 -- bash -c <cmd>
//           prctl(NO_NEW_PRIVS) -> seccomp floor -> (RO) Landlock ruleset ->
//           execvp(real_bash, bash -c cmd). In RW mode with
//           OPENCODE_SANDBOX_ALLOW_SUDO=1 the NNP+seccomp pair is skipped
//           (seccomp needs NNP without CAP_SYS_ADMIN); RO always keeps it.
//
// Environment contract (stage1; stage2 inherits):
//   OPENCODE_SANDBOX_MODE          ro|rw        (default rw)
//   OPENCODE_SANDBOX_SCRATCH       abs path     (default /tmp/opencode)
//   OPENCODE_REAL_BASH             abs path     (default /bin/bash)
//   OPENCODE_SANDBOX_BWRAP         bwrap path   (then /usr/bin/bwrap, then PATH)
//   OPENCODE_SANDBOX_HELPER        self path    (default /proc/self/exe)
//   OPENCODE_SANDBOX_RO_NETWORK    off|on       (default off -> --unshare-net)
//   OPENCODE_SANDBOX_RO_AF_UNIX_BLOCK 1|0       (default 1)
//   OPENCODE_SANDBOX_MASK_WSL_INTEROP 1|0       (default 1 -> --tmpfs /run/WSL)
//   OPENCODE_SANDBOX_MASK_SOCKETS  colon list   (default docker/podman/containerd)
//   OPENCODE_SANDBOX_DENY_WRITE    colon list   (default none; abs paths ->
//                                  --ro-bind <p> <p>: readable, not writable)
//   OPENCODE_SANDBOX_DENY_READ     colon list   (default none; abs paths ->
//                                  --tmpfs <p>: dir exists but is empty)
//   OPENCODE_SANDBOX_RW_NETWORK    1|0          (default 1; 0 -> --unshare-net
//                                  on the RW floor too; AF_UNIX still works,
//                                  so WSL interop survives)
//   OPENCODE_SANDBOX_ALLOW_SUDO    1|0          (default 0; RW only: runs
//                                  stage2 host-direct — NO bwrap at all:
//                                  no userns, socket masks, deny lists or
//                                  rwNetwork apply. stage2 then skips
//                                  NO_NEW_PRIVS + seccomp so sudo/setuid
//                                  work. RO always keeps the full floor.)
//   OPENCODE_SANDBOX_EXTRA_ARGS    \n-joined    (default none; each element
//                                  appended verbatim to the bwrap argv
//                                  before the "--" payload separator)
//   OPENCODE_SANDBOX_FALLBACK      <unset>|bwrap-only|landlock-only
//                                  (pin a path for probing/testing; unset=auto)
//
// Landlock is driven through raw syscalls 444/445/446; no libc landlock
// headers are required. Seccomp uses <linux/seccomp.h> + <linux/filter.h>
// which ship with any kernel-headers package and need no libseccomp.
//
// Exit status propagates unchanged through both exec chains (execve never
// forks off a status translation layer; bwrap forwards its child's status).

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <sched.h>
#include <signal.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

/* ------------------------------------------------------------------ */
/* Landlock raw interface (linux/landlock.h NOT required)              */
/* ------------------------------------------------------------------ */

#define SYS_LANDLOCK_CREATE_RULESET 444
#define SYS_LANDLOCK_ADD_RULE       445
#define SYS_LANDLOCK_RESTRICT_SELF  446

#define LANDLOCK_CREATE_RULESET_VERSION (1U << 0)

/* struct landlock_ruleset_attr, kernel layout (all fields exist since
 * ABI 4; zeroed extra fields are ignored by older ABIs). */
struct ll_ruleset_attr {
	uint64_t handled_access_fs;
	uint64_t handled_access_net;
	uint64_t scoped;
};

struct ll_path_beneath_attr {
	uint64_t allowed_access;
	int32_t  parent_fd;
};

#define LANDLOCK_RULE_PATH_BENEATH 1

/* FS access bits (verified against /usr/include/linux/landlock.h on host). */
#define LL_FS_WRITE_FILE   (1ULL << 1)
#define LL_FS_REMOVE_DIR   (1ULL << 4)
#define LL_FS_REMOVE_FILE  (1ULL << 5)
#define LL_FS_MAKE_CHAR    (1ULL << 6)
#define LL_FS_MAKE_DIR     (1ULL << 7)
#define LL_FS_MAKE_REG     (1ULL << 8)
#define LL_FS_MAKE_SOCK    (1ULL << 9)
#define LL_FS_MAKE_FIFO    (1ULL << 10)
#define LL_FS_MAKE_BLOCK   (1ULL << 11)
#define LL_FS_MAKE_SYM     (1ULL << 12)
#define LL_FS_REFER        (1ULL << 13)  /* ABI >= 2 */
#define LL_FS_TRUNCATE     (1ULL << 14)  /* ABI >= 3 */

#define LL_NET_BIND_TCP    (1ULL << 0)   /* ABI >= 4 */
#define LL_NET_CONNECT_TCP (1ULL << 1)

#define LL_SCOPE_ABSTRACT_UNIX_SOCKET (1ULL << 0) /* ABI >= 6 */
#define LL_SCOPE_SIGNAL               (1ULL << 1)

/* File-only Landlock rights: valid on any object type.
 * Directory-only rights (MAKE_*, REMOVE_DIR) may only appear on rules
 * whose target is a directory; the kernel returns EINVAL otherwise. */
#define LL_FS_FILE_ONLY_MASK \
	(LL_FS_WRITE_FILE | LL_FS_REMOVE_FILE | LL_FS_TRUNCATE)

static int landlock_abi(void)
{
	long r = syscall(SYS_LANDLOCK_CREATE_RULESET, NULL, 0,
			 LANDLOCK_CREATE_RULESET_VERSION);
	if (r < 0) {
		if (errno == ENOSYS || errno == EOPNOTSUPP)
			return 0;
		return -errno; /* unexpected error, e.g. seccomp EPERM */
	}
	return (int)r;
}

static uint64_t ll_fs_handled_mask(int abi)
{
	uint64_t m = LL_FS_WRITE_FILE | LL_FS_REMOVE_DIR | LL_FS_REMOVE_FILE |
		     LL_FS_MAKE_CHAR | LL_FS_MAKE_DIR | LL_FS_MAKE_REG |
		     LL_FS_MAKE_SOCK | LL_FS_MAKE_FIFO | LL_FS_MAKE_BLOCK |
		     LL_FS_MAKE_SYM;                       /* 0x1FF2 */
	if (abi >= 2)
		m |= LL_FS_REFER;                           /* 0x3FF2 */
	if (abi >= 3)
		m |= LL_FS_TRUNCATE;                        /* 0x7FF2 */
	return m;
}

/* Add a PATH_BENEATH rule. The request mask is intersected with what the
 * target's object type may carry (file-only bits for non-directories).
 * Returns 0 on success, -1 errno otherwise. */
static int ll_add_path_rule(int ruleset_fd, const char *path,
			    uint64_t request, int abi)
{
	struct stat st;
	struct ll_path_beneath_attr attr;
	int fd = open(path, O_PATH | O_CLOEXEC);
	if (fd < 0)
		return -1;
	if (fstat(fd, &st) < 0) {
		int e = errno;
		close(fd);
		errno = e;
		return -1;
	}
	uint64_t allowed = request;
	if (!S_ISDIR(st.st_mode))
		allowed &= LL_FS_FILE_ONLY_MASK;
	if (abi < 3)
		allowed &= ~LL_FS_TRUNCATE;
	if (abi < 2)
		allowed &= ~LL_FS_REFER;

	attr.allowed_access = allowed;
	attr.parent_fd = fd;
	long r = syscall(SYS_LANDLOCK_ADD_RULE, ruleset_fd,
			 LANDLOCK_RULE_PATH_BENEATH, &attr, 0);
	int e = errno;
	close(fd);
	if (r < 0) {
		errno = e;
		return -1;
	}
	return 0;
}

/* Build and apply the RO Landlock ruleset. Fatal exits on hard failure.
 * scratch must already exist (stage1 mkdir -p's it; callers of bare
 * stage2 are responsible for it too — a missing scratch is skipped so a
 * degraded environment still gets the write freeze). */
static void landlock_apply_ro(int abi, const char *scratch, int net_on)
{
	struct ll_ruleset_attr attr;
	memset(&attr, 0, sizeof(attr));
	attr.handled_access_fs = ll_fs_handled_mask(abi);
	if (abi >= 4 && !net_on)
		attr.handled_access_net = LL_NET_BIND_TCP | LL_NET_CONNECT_TCP;
	if (abi >= 6)
		attr.scoped = LL_SCOPE_ABSTRACT_UNIX_SOCKET | LL_SCOPE_SIGNAL;

	int fd = syscall(SYS_LANDLOCK_CREATE_RULESET, &attr, sizeof(attr), 0);
	if (fd < 0) {
		/* Older kernels may reject the enlarged struct/flags; retry
		 * with the ABI-1 field only. */
		int e = errno;
		if (e == EINVAL || e == E2BIG) {
			memset(&attr, 0, sizeof(attr));
			attr.handled_access_fs = ll_fs_handled_mask(abi);
			fd = syscall(SYS_LANDLOCK_CREATE_RULESET, &attr,
				     sizeof(attr.handled_access_fs), 0);
		}
		if (fd < 0) {
			fprintf(stderr,
				"opencode-sandbox: landlock_create_ruleset: %s\n",
				strerror(errno));
			exit(125);
		}
	}

	uint64_t fs_mask = ll_fs_handled_mask(abi);

	/* The only writable hierarchy. */
	struct stat st;
	if (stat(scratch, &st) == 0 && S_ISDIR(st.st_mode)) {
		if (ll_add_path_rule(fd, scratch, fs_mask, abi) < 0) {
			fprintf(stderr,
				"opencode-sandbox: landlock rule %s: %s\n",
				scratch, strerror(errno));
			exit(125);
		}
	}

	/* Device files: writable so git/tar/shell redirections keep working.
	 * /dev/null missing is fatal. */
	static const char *devs[] = {
		"/dev/null", "/dev/zero", "/dev/full",
		"/dev/random", "/dev/urandom", "/dev/tty",
	};
	uint64_t dev_mask =
		(abi >= 3) ? (LL_FS_WRITE_FILE | LL_FS_TRUNCATE) : LL_FS_WRITE_FILE;
	for (size_t i = 0; i < sizeof(devs) / sizeof(devs[0]); i++) {
		if (ll_add_path_rule(fd, devs[i], dev_mask, abi) < 0) {
			if (strcmp(devs[i], "/dev/null") == 0) {
				fprintf(stderr,
					"opencode-sandbox: landlock rule /dev/null: %s\n",
					strerror(errno));
				exit(125);
			}
			/* optional nodes: skip */
		}
	}
	if (stat("/dev/pts", &st) == 0 && S_ISDIR(st.st_mode)) {
		if (ll_add_path_rule(fd, "/dev/pts", dev_mask, abi) < 0)
			fprintf(stderr,
				"opencode-sandbox: warning: landlock rule /dev/pts: %s\n",
				strerror(errno));
	}

	if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0) {
		fprintf(stderr, "opencode-sandbox: prctl(NNP): %s\n",
			strerror(errno));
		exit(125);
	}
	if (syscall(SYS_LANDLOCK_RESTRICT_SELF, fd, 0) < 0) {
		fprintf(stderr,
			"opencode-sandbox: landlock_restrict_self: %s\n",
			strerror(errno));
		exit(125);
	}
	close(fd);
}

/* ------------------------------------------------------------------ */
/* Seccomp floor                                                       */
/* ------------------------------------------------------------------ */

#ifndef AF_UNIX
#define AF_UNIX 1
#endif

static void seccomp_install(int block_af_unix)
{
	/* Deny list -> EPERM. Jump math: each JEQ's jt must land on the
	 * common EPERM return; jf skips to the next check. The final JMP
	 * reaches the ALLOW return. See compute loop below — offsets are
	 * patched programmatically to avoid hand-math bugs. */
	static const int denied[] = {
#ifdef SYS_mount
		SYS_mount,
#endif
#ifdef SYS_umount2
		SYS_umount2,
#endif
#ifdef SYS_unshare
		SYS_unshare,
#endif
#ifdef SYS_setns
		SYS_setns,
#endif
#ifdef SYS_pivot_root
		SYS_pivot_root,
#endif
#ifdef SYS_bpf
		SYS_bpf,
#endif
#ifdef SYS_ptrace
		SYS_ptrace,
#endif
#ifdef SYS_process_vm_writev
		SYS_process_vm_writev,
#endif
#ifdef SYS_open_by_handle_at
		SYS_open_by_handle_at,
#endif
#ifdef SYS_init_module
		SYS_init_module,
#endif
#ifdef SYS_finit_module
		SYS_finit_module,
#endif
#ifdef SYS_delete_module
		SYS_delete_module,
#endif
#ifdef SYS_kexec_load
		SYS_kexec_load,
#endif
#ifdef SYS_kexec_file_load
		SYS_kexec_file_load,
#endif
#ifdef SYS_reboot
		SYS_reboot,
#endif
	};
	const int n_denied = (int)(sizeof(denied) / sizeof(denied[0]));
	/* Layout:
	 *   [0..2]                 arch check (LD arch, JEQ x86_64, KILL)
	 *   [3]                    LD nr
	 *   [4 .. 4+n-1]           n_denied JEQ -> common EPERM
	 *   af block (6 insns, only when block_af_unix):
	 *     JEQ socket      jt=+0 jf=+1   -> args0 check / next
	 *     JMP +1                       -> args0 check (socket matched)
	 *     JEQ socketpair  jt=+0 jf=+3  -> args0 check / JMP allow
	 *     LD args[0]
	 *     JEQ AF_UNIX     jt=+0 jf=+1  -> local EPERM / JMP allow
	 *     RET EPERM (local)
	 *   JMP -> ALLOW
	 *   RET EPERM (common target for deny-list JEQs)
	 *   RET ALLOW
	 */
	const int af_len = block_af_unix ? 6 : 0;
	const int nr_base = 4;
	const int eperm_idx = nr_base + n_denied + af_len + 1;
	const int allow_idx = eperm_idx + 1;
	struct sock_filter f[96];
	int i = 0;

	f[i++] = (struct sock_filter)BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
					    offsetof(struct seccomp_data, arch));
	f[i++] = (struct sock_filter)BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K,
					    AUDIT_ARCH_X86_64, 1, 0);
	f[i++] = (struct sock_filter)BPF_STMT(BPF_RET | BPF_K,
					    SECCOMP_RET_KILL_PROCESS);
	f[i++] = (struct sock_filter)BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
					    offsetof(struct seccomp_data, nr));
	if (i != nr_base) {
		fprintf(stderr, "opencode-sandbox: seccomp layout error\n");
		exit(125);
	}
	for (int k = 0; k < n_denied; k++) {
		int jt = eperm_idx - (nr_base + k + 1);
		f[i++] = (struct sock_filter)BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K,
						    (uint32_t)denied[k],
						    (uint8_t)jt, 0);
	}
	if (block_af_unix) {
		f[i++] = (struct sock_filter)BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K,
						    SYS_socket, 0, 1);
		f[i++] = (struct sock_filter)BPF_JUMP(BPF_JMP | BPF_JMP | BPF_K,
						    1, 0, 0);
		f[i++] = (struct sock_filter)BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K,
						    SYS_socketpair, 0, 3);
		f[i++] = (struct sock_filter)BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
					    offsetof(struct seccomp_data, args[0]));
		f[i++] = (struct sock_filter)BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K,
						    AF_UNIX, 0, 1);
		f[i++] = (struct sock_filter)BPF_STMT(BPF_RET | BPF_K,
					    SECCOMP_RET_ERRNO | EPERM);
	}
	/* JMP to ALLOW; then common EPERM; then ALLOW.
	 * Compute k before the i++ — argument evaluation order against the
	 * index increment is unspecified. */
	uint32_t ja = (uint32_t)(allow_idx - i - 1);
	f[i++] = (struct sock_filter)BPF_STMT(BPF_JMP | BPF_JMP | BPF_K, ja);
	f[i++] = (struct sock_filter)BPF_STMT(BPF_RET | BPF_K,
					    SECCOMP_RET_ERRNO | EPERM);
	f[i++] = (struct sock_filter)BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW);

	if (eperm_idx != i - 2 || allow_idx != i - 1) {
		fprintf(stderr,
			"opencode-sandbox: internal seccomp layout error (%d %d %d)\n",
			i, eperm_idx, allow_idx);
		exit(125);
	}

	struct sock_fprog prog = {
		.len = (unsigned short)i,
		.filter = f,
	};
	if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog) < 0) {
		fprintf(stderr, "opencode-sandbox: seccomp install: %s\n",
			strerror(errno));
		exit(125);
	}
}

/* ------------------------------------------------------------------ */
/* Shared helpers                                                      */
/* ------------------------------------------------------------------ */

static const char *env_or(const char *name, const char *dflt)
{
	const char *v = getenv(name);
	return (v && *v) ? v : dflt;
}

static int env_bool(const char *name, int dflt)
{
	const char *v = getenv(name);
	if (!v || !*v)
		return dflt;
	return strcmp(v, "0") != 0;
}

static void die(const char *what)
{
	fprintf(stderr, "opencode-sandbox: %s: %s\n", what, strerror(errno));
	exit(125);
}

static void mkdir_p(const char *path)
{
	char buf[PATH_MAX];
	size_t len = strlen(path);
	if (len >= sizeof(buf))
		return;
	memcpy(buf, path, len + 1);
	for (char *p = buf + 1; *p; p++) {
		if (*p == '/') {
			*p = '\0';
			mkdir(buf, 0700);
			*p = '/';
		}
	}
	mkdir(buf, 0700);
}

static int path_exists(const char *p)
{
	struct stat st;
	return stat(p, &st) == 0;
}

static int is_executable(const char *p)
{
	return access(p, X_OK) == 0;
}

/* Resolve bwrap: env override -> /usr/bin/bwrap -> PATH lookup. */
static int resolve_bwrap(char *out, size_t outlen)
{
	const char *env = getenv("OPENCODE_SANDBOX_BWRAP");
	if (env && *env) {
		if (is_executable(env)) {
			snprintf(out, outlen, "%s", env);
			return 1;
		}
		return 0;
	}
	if (is_executable("/usr/bin/bwrap")) {
		snprintf(out, outlen, "/usr/bin/bwrap");
		return 1;
	}
	const char *path = getenv("PATH");
	if (!path)
		return 0;
	char *copy = strdup(path);
	if (!copy)
		return 0;
	int found = 0;
	for (char *d = strtok(copy, ":"); d; d = strtok(NULL, ":")) {
		char cand[PATH_MAX];
		snprintf(cand, sizeof(cand), "%s/bwrap", d);
		if (is_executable(cand)) {
			snprintf(out, outlen, "%s", cand);
			found = 1;
			break;
		}
	}
	free(copy);
	return found;
}

/* Fork/exec/wait probe. Returns child exit status, or -1 on spawn fail. */
static int run_quiet(char *const argv[])
{
	pid_t pid = fork();
	if (pid < 0)
		return -1;
	if (pid == 0) {
		int dn = open("/dev/null", O_WRONLY);
		if (dn >= 0) {
			dup2(dn, STDOUT_FILENO);
			dup2(dn, STDERR_FILENO);
			if (dn > STDERR_FILENO)
				close(dn);
		}
		execv(argv[0], argv);
		_exit(127);
	}
	int st;
	while (waitpid(pid, &st, 0) < 0)
		if (errno != EINTR)
			return -1;
	if (WIFEXITED(st))
		return WEXITSTATUS(st);
	return -1;
}

/* ------------------------------------------------------------------ */
/* Probe state                                                         */
/* ------------------------------------------------------------------ */

struct probe {
	int have_bwrap;
	char bwrap[PATH_MAX];
	int have_userns;    /* userns+pidns full path works */
	int proc_needs_bind;/* --proc failed; use --bind /proc, drop pidns */
	int ll_abi;         /* >0 ABI, 0 none, <0 error */
};

static void do_probe(struct probe *p)
{
	memset(p, 0, sizeof(*p));
	p->have_bwrap = resolve_bwrap(p->bwrap, sizeof(p->bwrap));
	p->ll_abi = landlock_abi();

	p->have_userns = 0;
	p->proc_needs_bind = 0;
	if (p->have_bwrap) {
		char *a1[] = { p->bwrap, "--die-with-parent",
			       "--unshare-user", "--unshare-pid",
			       "--proc", "/proc", "--dev", "/dev",
			       "--ro-bind", "/", "/", "--", "true", NULL };
		if (run_quiet(a1) == 0) {
			p->have_userns = 1;
		} else {
			/* userns without usable pidns/proc mount */
			char *a2[] = { p->bwrap, "--die-with-parent",
				       "--unshare-user",
				       "--ro-bind", "/", "/",
				       "--bind", "/proc", "/proc",
				       "--", "true", NULL };
			if (run_quiet(a2) == 0) {
				p->have_userns = 1;
				p->proc_needs_bind = 1;
			}
		}
	}
	if (!p->have_bwrap) {
		/* test raw userns via unshare if present */
		if (is_executable("/usr/bin/unshare")) {
			char *a[] = { "/usr/bin/unshare", "-Ur", "true", NULL };
			p->have_userns = (run_quiet(a) == 0);
		}
	}
}

/* §3.4 decision table. Returns one of: "full", "bwrap-only",
 * "landlock-only", "unavailable". */
static const char *decide_path(const struct probe *p)
{
	const char *forced = getenv("OPENCODE_SANDBOX_FALLBACK");
	if (forced && *forced)
		return forced;
	if (p->have_bwrap && p->have_userns && p->ll_abi >= 3)
		return "full";
	if (p->have_bwrap && p->have_userns)
		return "bwrap-only";
	if (p->ll_abi >= 3)
		return "landlock-only"; /* bwrap absent or userns broken */
	return "unavailable";
}

/* ------------------------------------------------------------------ */
/* Stage2                                                              */
/* ------------------------------------------------------------------ */

static int stage2(int argc, char **argv)
{
	const char *mode = getenv("OPENCODE_SANDBOX_MODE");
	const char *real_bash = env_or("OPENCODE_REAL_BASH", "/bin/bash");
	/* Trusted-config caveat: bwrap --setenv from extraArgs reaches this
	 * environment, so a config author can widen the RO Landlock writable
	 * hierarchy via OPENCODE_SANDBOX_SCRATCH — same trust level as mode
	 * "full". Unlike mode/real_bash there is no argv override for scratch. */
	const char *scratch = env_or("OPENCODE_SANDBOX_SCRATCH", "/tmp/opencode");
	int no_landlock = 0;
	int af_block_forced = 0;
	int i;

	for (i = 1; i < argc; i++) {
		if (strcmp(argv[i], "--mode") == 0 && i + 1 < argc) {
			mode = argv[++i];
		} else if (strcmp(argv[i], "--real-bash") == 0 && i + 1 < argc) {
			real_bash = argv[++i];
		} else if (strcmp(argv[i], "--no-landlock") == 0) {
			no_landlock = 1;
		} else if (strcmp(argv[i], "--af-unix-block") == 0) {
			af_block_forced = 1;
		} else if (strcmp(argv[i], "--") == 0) {
			i++;
			break;
		}
	}
	/* Remaining argv is the wrapped command; expected "bash -c cmd" —
	 * we only need the final -c payload. Find "-c" and its operand. */
	const char *cmd = NULL;
	for (int k = i; k + 1 < argc; k++) {
		if (strcmp(argv[k], "-c") == 0) {
			cmd = argv[k + 1];
			break;
		}
	}
	if (!cmd) {
		/* last arg as fallback */
		if (i < argc)
			cmd = argv[argc - 1];
		else {
			fprintf(stderr, "opencode-sandbox: stage2: no command\n");
			return 125;
		}
	}

	int ro = (mode && strcmp(mode, "ro") == 0);
	int af_unix_block =
		af_block_forced ||
		(ro && env_bool("OPENCODE_SANDBOX_RO_AF_UNIX_BLOCK", 1));

	/* Load-bearing: neutralises setuid/sudo inside the sandbox.
	 * RW + OPENCODE_SANDBOX_ALLOW_SUDO=1 skips BOTH NNP and the seccomp
	 * floor (a seccomp install requires NNP or CAP_SYS_ADMIN). stage1
	 * also routed this spawn host-direct — no bwrap at all — since
	 * bwrap sets NNP unconditionally and would defeat the flag anyway.
	 * RO never reaches this branch: a read-only session with working
	 * sudo is a contradiction, so allowSudo is RW-scoped. */
	int allow_sudo = !ro && env_bool("OPENCODE_SANDBOX_ALLOW_SUDO", 0);
	if (!allow_sudo) {
		if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0)
			die("stage2 prctl(NO_NEW_PRIVS)");
		seccomp_install(af_unix_block);
	}

	if (ro && !no_landlock) {
		int abi = landlock_abi();
		if (abi < 3) {
			fprintf(stderr,
				"opencode-sandbox: RO requires Landlock ABI >= 3 "
				"(got %d); refuse to run unsandboxed\n",
				abi < 0 ? 0 : abi);
			return 125;
		}
		int net_on = strcmp(env_or("OPENCODE_SANDBOX_RO_NETWORK", "off"),
				    "on") == 0;
		landlock_apply_ro(abi, scratch, net_on);
	}

	char *bash_argv[] = { (char *)"bash", (char *)"-c",
			      (char *)cmd, NULL };
	execvp(real_bash, bash_argv);
	die("stage2 exec real bash");
	return 125;
}

/* ------------------------------------------------------------------ */
/* Stage1                                                              */
/* ------------------------------------------------------------------ */

struct argv_builder {
	char **v;
	int n, cap;
};

static void ab_push(struct argv_builder *b, const char *s)
{
	if (b->n + 1 >= b->cap) {
		b->cap = b->cap ? b->cap * 2 : 64;
		b->v = realloc(b->v, sizeof(char *) * b->cap);
		if (!b->v) {
			fprintf(stderr, "opencode-sandbox: OOM\n");
			exit(125);
		}
	}
	b->v[b->n++] = (char *)s;
}

static void mask_sockets(struct argv_builder *b, const char *spec)
{
	char *copy = strdup(spec);
	if (!copy)
		return;
	for (char *s = strtok(copy, ":"); s; s = strtok(NULL, ":")) {
		if (*s && path_exists(s)) {
			ab_push(b, "--bind");
			ab_push(b, "/dev/null");
			ab_push(b, s);
		}
	}
	/* note: copy intentionally leaked into exec'd image lifetime —
	 * freed implicitly at exec */
}

/* Colon-separated absolute-path deny lists, emitted AFTER the root bind
 * (same shadowing mechanism as mask_sockets: later mounts win):
 *   deny-read  dir  -> --tmpfs <p>   dir still exists but is empty inside
 *   deny-read  file -> --bind /dev/null <p>   contents unreadable
 *   deny-write -> --ro-bind <p> <p>  readable but not writable
 * A path on both lists gets the tmpfs first and then --remount-ro on the
 * same destination: empty AND read-only. (--ro-bind <p> <p> would bind
 * the ORIGINAL contents read-only — bwrap resolves bind sources in the
 * old root, not the staged one — so the remount is required for the
 * composition.) Both-lists file -> --ro-bind /dev/null <p>.
 * Entries must be absolute and exist at spawn time (bwrap cannot mount a
 * destination that isn't there); anything else is skipped. strtok
 * already drops empty ":" elements. */
static void emit_deny_lists(struct argv_builder *b,
			    const char *deny_read, const char *deny_write)
{
	char *read_paths[64];
	int n_read = 0;
	struct stat st;

	if (deny_read && *deny_read) {
		char *copy = strdup(deny_read);
		if (copy) {
			for (char *s = strtok(copy, ":"); s;
			     s = strtok(NULL, ":")) {
				if (s[0] != '/' || stat(s, &st) < 0)
					continue;
				if (S_ISDIR(st.st_mode)) {
					ab_push(b, "--tmpfs");
					ab_push(b, s);
				} else {
					ab_push(b, "--bind");
					ab_push(b, "/dev/null");
					ab_push(b, s);
				}
				if (n_read < (int)(sizeof(read_paths) /
						   sizeof(read_paths[0])))
					read_paths[n_read++] = s;
			}
		}
	}
	if (deny_write && *deny_write) {
		char *copy = strdup(deny_write);
		if (copy) {
			for (char *s = strtok(copy, ":"); s;
			     s = strtok(NULL, ":")) {
				if (s[0] != '/' || stat(s, &st) < 0)
					continue;
				int both = 0;
				for (int k = 0; k < n_read; k++)
					if (strcmp(read_paths[k], s) == 0) {
						both = 1;
						break;
					}
				if (both && S_ISDIR(st.st_mode)) {
					/* tmpfs already mounted above;
					 * remount it read-only. */
					ab_push(b, "--remount-ro");
					ab_push(b, s);
				} else if (both) {
					ab_push(b, "--ro-bind");
					ab_push(b, "/dev/null");
					ab_push(b, s);
				} else {
					ab_push(b, "--ro-bind");
					ab_push(b, s);
					ab_push(b, s);
				}
			}
		}
	}
	/* copies intentionally leak into the exec'd image lifetime */
}

/* OPENCODE_SANDBOX_EXTRA_ARGS: newline-separated raw bwrap argv elements
 * (the plugin joins sandbox.extraBwrapArgs with "\n" and validates: no
 * embedded \n or \0, no "--", no empty elements, <=64KB total). Each
 * non-empty element is appended verbatim immediately before the "--"
 * payload separator. No semantic validation here — bwrap rejects
 * contradictory flags (fail-closed) and the user owns this authority
 * layer. Trusted-config caveat: --setenv/--unsetenv entries apply to
 * stage2's environment and CAN override env-read stage2 configuration —
 * e.g. OPENCODE_SANDBOX_SCRATCH below widens the RO Landlock writable
 * hierarchy (equivalent authority to mode "full"). argv-passed controls
 * (--mode, --real-bash) and RO's argv-scoped allowSudo cannot be forged
 * this way. */
static void emit_extra_args(struct argv_builder *b, const char *spec)
{
	if (!spec || !*spec)
		return;
	char *copy = strdup(spec);
	if (!copy)
		return;
	for (char *s = strtok(copy, "\n"); s; s = strtok(NULL, "\n")) {
		if (*s)
			ab_push(b, s);
	}
	/* copy intentionally leaks into the exec'd image lifetime */
}

static const char *self_path(void)
{
	const char *env = getenv("OPENCODE_SANDBOX_HELPER");
	if (env && *env && is_executable(env))
		return env;
	static char buf[PATH_MAX];
	ssize_t n = readlink("/proc/self/exe", buf, sizeof(buf) - 1);
	if (n > 0) {
		buf[n] = '\0';
		return buf;
	}
	return "/proc/self/exe";
}

static int stage1(const char *cmd)
{
	const char *mode = env_or("OPENCODE_SANDBOX_MODE", "rw");
	const char *scratch = env_or("OPENCODE_SANDBOX_SCRATCH", "/tmp/opencode");
	const char *real_bash = env_or("OPENCODE_REAL_BASH", "/bin/bash");
	const char *mask_spec =
		env_or("OPENCODE_SANDBOX_MASK_SOCKETS",
		       "/run/docker.sock:/run/podman/podman.sock:"
		       "/run/containerd/containerd.sock");
	int ro = strcmp(mode, "ro") == 0;
	int rw = strcmp(mode, "rw") == 0;
	if (!ro && !rw) {
		fprintf(stderr,
			"opencode-sandbox: unknown mode '%s' (want ro|rw)\n",
			mode);
		return 125;
	}
	if (scratch[0] != '/' || strstr(scratch, "..")) {
		fprintf(stderr,
			"opencode-sandbox: scratch must be an absolute "
			"non-traversal path: '%s'\n", scratch);
		return 125;
	}
	mkdir_p(scratch);

	/* allowSudo=1 (RW only): route stage2 host-direct — no bwrap at all.
	 * sudo/setuid require NNP absent, and bwrap sets NNP unconditionally,
	 * so the flag can only work by bypassing the entire bwrap floor: no
	 * namespace isolation, no socket masks, no deny lists, no rwNetwork.
	 * stage2 additionally skips NNP + seccomp (seccomp install requires
	 * NNP without CAP_SYS_ADMIN). Nothing remains but the command itself
	 * — a deliberate authority-layer opt-out. RO ignores the flag. */
	if (rw && env_bool("OPENCODE_SANDBOX_ALLOW_SUDO", 0)) {
		char *a[16];
		int n = 0;
		a[n++] = (char *)self_path();
		a[n++] = "--stage2";
		a[n++] = "--mode";
		a[n++] = "rw";
		a[n++] = "--real-bash";
		a[n++] = (char *)real_bash;
		a[n++] = "--";
		a[n++] = "bash";
		a[n++] = "-c";
		a[n++] = (char *)cmd;
		a[n] = NULL;
		execv(a[0], a);
		die("exec stage2 (allowSudo host-direct)");
	}

	struct probe p;
	do_probe(&p);
	const char *path = decide_path(&p);

	char cwd[PATH_MAX];
	if (!getcwd(cwd, sizeof(cwd)))
		snprintf(cwd, sizeof(cwd), "/");

	char *stage2_mode = ro ? "ro" : "rw";

	/* Landlock-only: run stage2 directly on the host. */
	if (strcmp(path, "landlock-only") == 0) {
		char *a[16];
		int n = 0;
		a[n++] = (char *)self_path();
		a[n++] = "--stage2";
		a[n++] = "--mode";
		a[n++] = stage2_mode;
		a[n++] = "--real-bash";
		a[n++] = (char *)real_bash;
		if (ro)
			a[n++] = "--af-unix-block"; /* mandatory, plan §3.4 */
		a[n++] = "--";
		a[n++] = "bash";
		a[n++] = "-c";
		a[n++] = (char *)cmd;
		a[n] = NULL;
		execv(a[0], a);
		die("exec stage2 (landlock-only)");
	}

	if (strcmp(path, "unavailable") == 0 || !p.have_bwrap) {
		fprintf(stderr,
			"opencode-sandbox: OS sandbox unavailable "
			"(bwrap=%d userns=%d landlock_abi=%d). "
			"Refusing shell execution.\n",
			p.have_bwrap, p.have_userns, p.ll_abi);
		return 125;
	}

	/* bwrap paths: "full" or "bwrap-only". */
	int bwrap_only = strcmp(path, "bwrap-only") == 0;
	/* RO unshares the net by default; RW only when RW_NETWORK=0.
	 * AF_UNIX is unaffected by --unshare-net, so WSL interop
	 * (the interop sockets under /run/WSL, unmasked in RW) keeps
	 * working. */
	int unshare_net =
		(ro && strcmp(env_or("OPENCODE_SANDBOX_RO_NETWORK", "off"),
			      "off") == 0) ||
		(rw && !env_bool("OPENCODE_SANDBOX_RW_NETWORK", 1));
	int mask_wsl = ro && env_bool("OPENCODE_SANDBOX_MASK_WSL_INTEROP", 1);

	struct argv_builder b = { 0 };
	ab_push(&b, p.bwrap);
	ab_push(&b, "--new-session");
	/* RW deliberately runs on the host pidns with no die-with-parent:
	 * a private pidns would SIGKILL every backgrounded/detached child
	 * (dev servers, watchers, the WSL-interop restart chain) the moment
	 * the payload command exits, and without a pidns a fresh --proc
	 * cannot be mounted. RW therefore uses the same shape as the
	 * proc_needs_bind fallback: --bind /proc /proc. RO keeps maximum
	 * isolation (pidns + fresh /proc + die-with-parent); background
	 * death there is documented acceptable semantics. */
	if (ro)
		ab_push(&b, "--die-with-parent");
	ab_push(&b, "--unshare-user");
	ab_push(&b, "--cap-drop");
	ab_push(&b, "ALL");
	if (ro && !p.proc_needs_bind)
		ab_push(&b, "--unshare-pid");

	if (bwrap_only && ro) {
		ab_push(&b, "--ro-bind");
		ab_push(&b, "/");
		ab_push(&b, "/");
		ab_push(&b, "--bind");
		ab_push(&b, scratch);
		ab_push(&b, scratch);
	} else {
		ab_push(&b, "--bind");
		ab_push(&b, "/");
		ab_push(&b, "/");
	}
	if (!ro || p.proc_needs_bind) {
		/* RW always binds host /proc (no pidns to mount a fresh
		 * one into); RO falls back to this only when the probe
		 * showed --proc/--unshare-pid unsupported. */
		ab_push(&b, "--bind");
		ab_push(&b, "/proc");
		ab_push(&b, "/proc");
	} else {
		ab_push(&b, "--proc");
		ab_push(&b, "/proc");
	}
	ab_push(&b, "--dev");
	ab_push(&b, "/dev");
	if (unshare_net)
		ab_push(&b, "--unshare-net");
	mask_sockets(&b, mask_spec);
	if (mask_wsl && path_exists("/run/WSL")) {
		ab_push(&b, "--tmpfs");
		ab_push(&b, "/run/WSL");
	}
	emit_deny_lists(&b, getenv("OPENCODE_SANDBOX_DENY_READ"),
			getenv("OPENCODE_SANDBOX_DENY_WRITE"));
	if (ro) {
		ab_push(&b, "--setenv");
		ab_push(&b, "TMPDIR");
		ab_push(&b, scratch);
	}
	ab_push(&b, "--setenv");
	ab_push(&b, "GIT_CONFIG_COUNT");
	ab_push(&b, "1");
	ab_push(&b, "--setenv");
	ab_push(&b, "GIT_CONFIG_KEY_0");
	ab_push(&b, "safe.directory");
	ab_push(&b, "--setenv");
	ab_push(&b, "GIT_CONFIG_VALUE_0");
	ab_push(&b, cwd);
	ab_push(&b, "--chdir");
	ab_push(&b, cwd);
	emit_extra_args(&b, getenv("OPENCODE_SANDBOX_EXTRA_ARGS"));
	ab_push(&b, "--");

	if (bwrap_only && ro) {
		/* Plan §3.4: bwrap is the FS boundary; still route through
		 * stage2 for NNP+seccomp+AF_UNIX block (stronger than the
		 * documented direct-exec; keeps the floor uniform). */
		ab_push(&b, self_path());
		ab_push(&b, "--stage2");
		ab_push(&b, "--mode");
		ab_push(&b, "ro");
		ab_push(&b, "--no-landlock");
		ab_push(&b, "--af-unix-block");
		ab_push(&b, "--real-bash");
		ab_push(&b, real_bash);
		ab_push(&b, "--");
	} else {
		ab_push(&b, self_path());
		ab_push(&b, "--stage2");
		ab_push(&b, "--mode");
		ab_push(&b, stage2_mode);
		ab_push(&b, "--real-bash");
		ab_push(&b, real_bash);
		ab_push(&b, "--");
	}
	ab_push(&b, "bash");
	ab_push(&b, "-c");
	ab_push(&b, cmd);
	ab_push(&b, NULL);

	execv(p.bwrap, b.v);
	die("exec bwrap");
	return 125;
}

/* ------------------------------------------------------------------ */

static int probe_report(void)
{
	struct probe p;
	do_probe(&p);
	const char *path = decide_path(&p);
	printf("bwrap: %s\n", p.have_bwrap ? p.bwrap : "not found");
	printf("userns: %s%s\n", p.have_userns ? "yes" : "no",
	       p.proc_needs_bind ? " (pidns/proc mount unavailable; "
	       "using --bind /proc, no --unshare-pid)" : "");
	printf("landlock_abi: %d\n", p.ll_abi);
	printf("sandbox_path: %s\n", path);
	printf("mode: %s  scratch: %s  real_bash: %s\n",
	       env_or("OPENCODE_SANDBOX_MODE", "rw"),
	       env_or("OPENCODE_SANDBOX_SCRATCH", "/tmp/opencode"),
	       env_or("OPENCODE_REAL_BASH", "/bin/bash"));
	return 0;
}

static void usage(FILE *out)
{
	fprintf(out,
		"opencode-sandbox — P4 sandbox helper\n"
		"  opencode-sandbox -c <command>\n"
		"  opencode-sandbox --probe\n"
		"  opencode-sandbox --stage2 --mode ro|rw [--no-landlock]\n"
		"        [--af-unix-block] --real-bash <path> -- bash -c <cmd>\n");
}

int main(int argc, char **argv)
{
	if (argc >= 2 && strcmp(argv[1], "--probe") == 0)
		return probe_report();
	if (argc >= 2 && strcmp(argv[1], "--stage2") == 0)
		return stage2(argc - 1, argv + 1);
	if (argc >= 2 && strcmp(argv[1], "-c") == 0) {
		if (argc < 3) {
			fprintf(stderr, "opencode-sandbox: -c needs a command\n");
			return 125;
		}
		return stage1(argv[2]);
	}
	if (argc >= 2 &&
	    (strcmp(argv[1], "-h") == 0 || strcmp(argv[1], "--help") == 0)) {
		usage(stdout);
		return 0;
	}
	usage(stderr);
	return 125;
}
