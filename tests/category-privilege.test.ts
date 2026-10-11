import { describe, expect, test } from "bun:test"
import { commandNeedsOsPrivilege } from "../src/sandbox"

// --- `privilege` category: static privilege-launcher detection only.
// The old host-direct routing and escalation floor pre-check pipelines were
// removed with the single-policy rework; their behavioral tests are gone.

describe("commandNeedsOsPrivilege", () => {
  test("privilege launchers and boundary mutators are detected", () => {
    for (const script of [
      "sudo id",
      "sudo -n true",
      "doas id",
      "pkexec reboot",
      "su -c 'id'",
      "sudoedit /etc/sudoers",
      "runas /user:admin cmd",
      "chown root:root /etc/app.conf",
      "chown -R a b",
      "chgrp wheel /etc/app.conf",
      "setcap cap_net_raw+ep /bin/ping",
      "setfacl -m u:daemon:rwx /etc/app.conf",
      "mount /dev/sdb1 /mnt",
      "mount /dev/sda /mnt",
      "umount /mnt",
      "unshare -Ur bash",
      "nsenter -t 1 sh",
      "chroot /mnt /bin/sh",
      "chmod 4755 /usr/local/bin/helper",
      "chmod u+s /usr/local/bin/helper",
      "chmod 2755 /usr/local/bin/helper",
      "echo hi && sudo systemctl restart nginx",
      // Leading assignments and prefix wrappers keep the launcher in
      // command position.
      "FOO=1 sudo id",
      "env -i sudo id",
      "nice -n 5 sudo id",
      // Quoted payloads that are themselves executed are checked recursively.
      "sh -c 'sudo id'",
      "bash -lc 'chmod 4755 x'",
      "eval 'sudo id'",
      // The added silently-failing families.
      "sysctl -w kernel.x=1",
      "modprobe zram",
      "insmod x.ko",
      "rmmod x",
      "docker run --privileged x",
      "podman run --privileged x",
      "docker run -v /var/run/docker.sock:/var/run/docker.sock alpine",
      "echo 1 > /proc/sys/kernel/yama/ptrace_scope",
      "echo x | sudo tee /proc/sys/kernel/yama/ptrace_scope",
    ]) {
      expect(commandNeedsOsPrivilege(script)).toBe(true)
    }
  })

  test("third-round fixes: real execution forms are detected", () => {
    for (const script of [
      // Boolean container flags distinguish explicit values; the host PID
      // namespace matches in both spellings.
      "docker run --privileged=true alpine",
      "docker run --pid host alpine",
      "docker run --pid=host alpine",
      // Wrapper option/operand values that are themselves executed.
      "env -S 'sudo -n true'",
      "env --split-string 'sudo id'",
      "watch 'sudo id'",
      "watch -n 5 'sudo id'",
      // `case` branch commands sit in command position, both in the first
      // branch and in the `;;`-cut segments of later branches.
      "case x in x) sudo id ;; esac",
      "case x in a) echo hi ;; b) mount /dev/sdb1 /mnt ;; esac",
      // sysctl load forms apply settings — kernel writes, like -w.
      "sysctl -p",
      "sysctl -p /etc/sysctl.d/99-hardening.conf",
      "sysctl --system",
      "sysctl --load",
      // Unquoted-delimiter heredoc bodies expand $(…)/backticks.
      "cat <<EOF\n$(sudo id)\nEOF",
      "cat <<EOF\n`sudo id`\nEOF",
    ]) {
      expect(commandNeedsOsPrivilege(script)).toBe(true)
    }
  })

  test("third-round fixes: explicitly disabled or inert forms stay undetected", () => {
    for (const script of [
      // --privileged=false turns the flag off.
      "docker run --privileged=false alpine",
      // Quoted-delimiter heredoc bodies are literal text — $(…) and
      // backticks inside never execute.
      "cat <<'EOF'\n$(sudo id)\nEOF",
      "cat <<\"EOF\"\n$(sudo id)\nEOF",
      "cat <<'EOF'\n`sudo id`\nEOF",
      // Wrapper payloads and case branches that merely mention privilege
      // words in argument position.
      "env -S 'echo sudo'",
      "watch 'echo sudo'",
      "case x in x) echo sudo ;; esac",
      // A function definition names sudo without running it.
      "foo() { sudo id; }",
      // Non-host PID namespaces are not the host boundary.
      "docker run --pid=container:abc123 alpine",
    ]) {
      expect(commandNeedsOsPrivilege(script)).toBe(false)
    }
  })

  test("ordinary commands and non-setuid chmod stay undetected", () => {
    for (const script of [
      "ls -la",
      "cat /etc/passwd",
      "sum file",
      "mountain echo",
      "chmod 644 notes.txt",
      "chmod 644 x",
      "chmod +x build.sh",
      "chmod 1777 /tmp",
      "grep root /etc/passwd",
      // Privilege words in NON-execution positions never trigger the
      // host-direct routing (a false positive would strip the OS sandbox
      // from a harmless call).
      "echo sudo",
      "grep sudo README.md",
      "# sudo id",
      "echo hi # sudo id",
      "printf 'chmod 4755'",
      "FOO=sudo echo hi",
      "git commit -m \"use sudo carefully\"",
      "echo 'sudo id'",
      "echo \"sudo x\"",
      "command -v sudo",
      "cat /proc/sys/kernel/hostname",
      "sysctl -a",
      "docker ps",
      "bash -c 'echo hi'",
    ]) {
      expect(commandNeedsOsPrivilege(script)).toBe(false)
    }
  })

  test("routing-fix additions: privilege launchers and boundary tools are detected", () => {
    for (const script of [
      "runuser -u root -- id",
      "setpriv --reuid=0 id",
      "capsh --print",
      "useradd foo",
      "usermod -aG wheel foo",
      "userdel foo",
      "passwd root",
      "chpasswd < /tmp/hashes",
      "visudo",
      "iptables -L",
      "nft list ruleset",
      "ufw enable",
      "losetup /dev/loop0 disk.img",
      "setenforce 0",
      "kexec -e",
    ]) {
      expect(commandNeedsOsPrivilege(script)).toBe(true)
    }
  })

  test("routing-fix additions: the same words in non-execution positions stay undetected", () => {
    for (const script of [
      "echo runuser",
      "grep capsh README.md",
      "echo 'setpriv --reuid=0 id'",
      "# passwd root",
      "printf 'iptables -L'",
      "git commit -m \"use visudo\"",
    ]) {
      expect(commandNeedsOsPrivilege(script)).toBe(false)
    }
  })

  test("round2: shell heredoc bodies are scanned, non-shell consumers stay inert", () => {
    for (const script of [
      "bash <<'EOF'\nsudo id\nEOF",
      "bash <<EOF\nsudo id\nEOF",
      "sh <<EOF\nchown root:root /etc/app.conf\nEOF",
      "dash <<'D'\nrunuser -u root -- id\nD",
      "env bash <<EOF\nsetcap cap_net_raw+ep /bin/ping\nEOF",
      "command bash <<'EOF'\nmount /dev/sdb1 /mnt\nEOF",
      "bash <<A <<B\necho ok\nA\niptables -F\nB",
    ]) {
      expect(commandNeedsOsPrivilege(script)).toBe(true)
    }
    for (const script of [
      "cat <<EOF\nsudo id\nEOF",
      "cat <<'EOF'\nsudo id\nEOF",
      "python3 <<EOF\nprint(1)\nEOF",
      "python3 - <<'PY'\nprint('sudo')\nPY",
      "tee /tmp/out <<EOF\nsudo id\nEOF",
      "bash <<EOF\nls -la\necho done\nEOF",
      // stdin pipe (not a heredoc) stays a documented limitation.
      "echo 'sudo id' | sh",
    ]) {
      expect(commandNeedsOsPrivilege(script)).toBe(false)
    }
  })
})
