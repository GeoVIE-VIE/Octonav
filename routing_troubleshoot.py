#!/usr/bin/env python3
"""Routing-focused SSH + LLM troubleshooting helper.

Use this when you're debugging a routing problem between two (or more)
routers and you already suspect the issue lives at Layer 3 or above --
routing protocols, route tables, IP addressing, ACLs / route-maps /
policy, neighbor adjacencies, etc. The LLM is primed to ignore L1/L2
(cabling, link negotiation, MAC learning, STP, ...).

Standalone script. Python standard library only -- requires nothing
from pip and does not import from any other file in this repo. Just
drop the script and routers.txt into a directory and run it.

Workflow:
  1. Read routers.txt (one hostname/IP per line, '#' comments ignored).
  2. Prompt for SSH username, SSH password, and LLM API key.
  3. Prompt for commands -- one per line, blank line ends input. The
     same list runs on every router so outputs can be compared.
  4. SSH into each router, run each command, write the raw output to
     routing_output.txt with per-router banners and per-command
     sections.
  5. POST the aggregated file to the configured chat-completions
     endpoint. Save the assistant's analysis to routing_report.txt
     and print it to stdout.
"""

import errno
import getpass
import json
import os
import pty
import re
import select
import shutil
import signal
import ssl
import sys
import time
import urllib.error
import urllib.request


SCRIPT_DIR   = os.path.dirname(os.path.abspath(__file__))
ROUTERS_FILE = os.path.join(SCRIPT_DIR, "routers.txt")
OUTPUT_FILE  = os.path.join(SCRIPT_DIR, "routing_output.txt")
REPORT_FILE  = os.path.join(SCRIPT_DIR, "routing_report.txt")

# RHEL 9 / modern OpenSSL disables SHA-1 RSA signatures by default, which
# breaks SSH to older Brocade/Cisco images. These per-process env vars
# re-enable just this session -- no root / crypto-policies change needed.
os.environ.setdefault("OPENSSL_ENABLE_SHA1_SIGNATURES", "yes")
os.environ.setdefault("CRYPTO_POLICY", "LEGACY")

# --- LLM configuration -----------------------------------------------------
LLM_ENDPOINT = "https://xyz.xyz.xyz/v1/chat/completions"
LLM_MODEL    = "gemini-2.5-flash"
SYSTEM_PROMPT = (
    "You are an AI network engineer helping troubleshoot a routing "
    "problem between the routers whose command output is pasted "
    "below. Focus on Layer 3 and above: IP addressing, subnetting, "
    "routing protocols (BGP / OSPF / EIGRP / IS-IS / static), "
    "route-table contents and preference, neighbor / adjacency state, "
    "ACLs, route-maps, policy-based routing, VRFs, redistribution, "
    "and interface IP / MTU mismatches. Assume Layer 1 and Layer 2 "
    "are already verified healthy -- do not suggest cable swaps, "
    "duplex / speed renegotiation, STP convergence, or ARP flushes "
    "unless something in the provided output directly implicates "
    "those layers. Compare the configurations and state of the "
    "routers side-by-side and identify the most likely root cause "
    "of the routing issue, citing the specific lines of output that "
    "support your conclusion."
)
LLM_TIMEOUT_SECS = 240


# ===========================================================================
# SSH infrastructure (stdlib-only pty-driven SSH session, vendor detection)
# ===========================================================================

_ANSI_RE       = re.compile(r"\x1b\[[0-9;?]*[A-Za-z]|\x1b\][^\x07]*\x07|\r|\x08")
_MORE_RE       = re.compile(rb"--\s*[Mm]ore\s*--")
_PAGER_LINE_RE = re.compile(r"--\s*[Mm]ore\s*--[^\r\n]*")


def _strip_ansi(text):
    return _ANSI_RE.sub("", text)


class AuthFailure(Exception):
    """Raised when the device rejects the supplied credentials."""


class SSHSession:
    """Minimal interactive SSH session driven via a pty."""

    PROMPT_RE = re.compile(rb"[\r\n][^\r\n]{0,80}[>#]\s*$")
    PW_RE     = re.compile(rb"(?i)(password|passphrase)[^:]*:\s*$")
    FAIL_RE   = re.compile(
        rb"(?i)(permission denied|authentication fail|access denied|"
        rb"connection (refused|closed|reset)|no route to host|"
        rb"could not resolve hostname|host key verification failed)"
    )

    SSH_OPTS = [
        "-F", "/dev/null",
        "-o", "StrictHostKeyChecking=no",
        "-o", "UserKnownHostsFile=/dev/null",
        "-o", "GlobalKnownHostsFile=/dev/null",
        "-o", "PubkeyAuthentication=no",
        "-o", "GSSAPIAuthentication=no",
        "-o", "HostbasedAuthentication=no",
        "-o", "PreferredAuthentications=password,keyboard-interactive",
        "-o", "NumberOfPasswordPrompts=1",
        "-o", "LogLevel=ERROR",
        "-o", "ConnectTimeout=30",
        "-o", "ServerAliveInterval=15",
        "-o", "KexAlgorithms=+diffie-hellman-group1-sha1,"
              "diffie-hellman-group14-sha1,"
              "diffie-hellman-group-exchange-sha1",
        "-o", "HostKeyAlgorithms=+ssh-rsa,ssh-dss,ssh-rsa-cert-v01@openssh.com",
        "-o", "PubkeyAcceptedKeyTypes=+ssh-rsa",
        "-o", "PubkeyAcceptedAlgorithms=+ssh-rsa",
        "-o", "Ciphers=+aes128-cbc,aes192-cbc,aes256-cbc,3des-cbc",
        "-o", "MACs=+hmac-sha1,hmac-sha1-96,hmac-md5",
    ]

    def __init__(self, host, username, password, timeout=30):
        self.host = host
        self.username = username
        self.password = password
        self.timeout = timeout
        self.pid = None
        self.fd = None

    def connect(self):
        if not shutil.which("ssh"):
            raise RuntimeError("'ssh' binary not found in PATH")
        argv = ["ssh"] + self.SSH_OPTS + ["-l", self.username, self.host]
        pid, fd = pty.fork()
        if pid == 0:
            try:
                os.execvp("ssh", argv)
            except Exception as e:
                sys.stderr.write(f"exec ssh failed: {e}\n")
                os._exit(127)
        self.pid = pid
        self.fd = fd

        buf = self._read_until([self.PW_RE, self.PROMPT_RE, self.FAIL_RE], self.timeout)
        if self.FAIL_RE.search(buf):
            self._raise_for_failure(buf)
        if self.PW_RE.search(buf):
            os.write(self.fd, self.password.encode() + b"\n")
            buf = self._read_until([self.PROMPT_RE, self.FAIL_RE, self.PW_RE], self.timeout)
            if self.PW_RE.search(buf):
                raise AuthFailure("authentication failed (password rejected)")
            if self.FAIL_RE.search(buf):
                self._raise_for_failure(buf)
        return _strip_ansi(buf.decode(errors="replace"))

    @classmethod
    def _raise_for_failure(cls, buf):
        text = _strip_ansi(buf.decode(errors="replace")).lower()
        if re.search(r"permission denied|authentication fail|access denied", text):
            raise AuthFailure(cls._describe_failure(buf))
        raise RuntimeError(cls._describe_failure(buf))

    def close(self):
        if self.fd is not None:
            try:
                os.write(self.fd, b"exit\n")
            except OSError:
                pass
            try:
                os.close(self.fd)
            except OSError:
                pass
            self.fd = None
        if self.pid is not None:
            for _ in range(20):
                try:
                    done, _ = os.waitpid(self.pid, os.WNOHANG)
                    if done:
                        break
                except ChildProcessError:
                    break
                time.sleep(0.05)
            else:
                try:
                    os.kill(self.pid, signal.SIGTERM)
                    os.waitpid(self.pid, 0)
                except (ProcessLookupError, ChildProcessError):
                    pass
            self.pid = None

    def __enter__(self):
        self.connect()
        return self

    def __exit__(self, *exc):
        self.close()

    def _read_until(self, patterns, timeout):
        buf = b""
        deadline = time.time() + timeout
        while True:
            remaining = deadline - time.time()
            if remaining <= 0:
                raise TimeoutError(
                    f"timeout after {timeout}s; last bytes: {buf[-200:]!r}"
                )
            try:
                r, _, _ = select.select([self.fd], [], [], min(remaining, 1.0))
            except (OSError, ValueError):
                break
            if self.fd in r:
                try:
                    chunk = os.read(self.fd, 4096)
                except OSError as e:
                    if e.errno in (errno.EIO, errno.EBADF):
                        break
                    raise
                if not chunk:
                    break
                buf += chunk
                for pat in patterns:
                    if pat.search(buf):
                        return buf
        return buf

    def send_command(self, cmd, timeout=None):
        if self.fd is None:
            raise RuntimeError("session not connected")
        os.write(self.fd, cmd.encode() + b"\n")

        effective_timeout = timeout or self.timeout
        deadline = time.time() + effective_timeout
        buf = b""
        while True:
            remaining = deadline - time.time()
            if remaining <= 0:
                raise TimeoutError(
                    f"timeout after {effective_timeout}s; last bytes: {buf[-200:]!r}"
                )
            try:
                r, _, _ = select.select([self.fd], [], [], min(remaining, 1.0))
            except (OSError, ValueError):
                break
            if self.fd not in r:
                continue
            try:
                chunk = os.read(self.fd, 4096)
            except OSError as e:
                if e.errno in (errno.EIO, errno.EBADF):
                    break
                raise
            if not chunk:
                break
            buf += chunk
            tail = buf[-256:]
            if _MORE_RE.search(tail):
                try:
                    os.write(self.fd, b" ")
                except OSError:
                    pass
                continue
            if self.PROMPT_RE.search(tail):
                break

        text = _strip_ansi(buf.decode(errors="replace"))
        text = _PAGER_LINE_RE.sub("", text)
        lines = text.splitlines()
        cleaned = []
        dropped_echo = False
        for line in lines:
            if not dropped_echo and cmd.strip() and cmd.strip() in line:
                dropped_echo = True
                continue
            cleaned.append(line)
        if cleaned and re.match(r"^\S.*[>#]\s*$", cleaned[-1]):
            cleaned.pop()
        return "\n".join(cleaned)

    @staticmethod
    def _describe_failure(buf):
        txt = _strip_ansi(buf.decode(errors="replace")).strip()
        last = txt.splitlines()[-3:] if txt else []
        return "connection failed: " + " | ".join(l.strip() for l in last if l.strip())


def _peek_prompt(sess):
    try:
        os.write(sess.fd, b"\n")
        buf = sess._read_until([SSHSession.PROMPT_RE], 5)
        text = _strip_ansi(buf.decode(errors="replace")).strip()
        return text.splitlines()[-1] if text else ""
    except Exception:
        return ""


_BROCADE_VERSION_SUBSTRINGS = (
    "brocade", "foundry", "ruckus", "commscope",
    "fastiron", "netiron", "ironware", "serveriron",
    "icx", "mlxe",
)
_BROCADE_VERSION_TOKENS = (
    "fcx", "fgs", "fls", "fesx",
    "mlx", "ces", "cer",
    "ni-mlx", "ni-ces", "ni-cer",
)
_BROCADE_VERSION_TOKEN_RE = re.compile(
    r"(?<![A-Za-z])(?:" + "|".join(re.escape(t) for t in _BROCADE_VERSION_TOKENS) + r")(?![A-Za-z])",
    re.IGNORECASE,
)
_CISCO_VERSION_KEYWORDS = (
    "cisco ios software", "cisco ios-xe", "cisco ios xe",
    "cisco nexus", "cisco adaptive", "cisco internetwork",
    "nx-os", "ios-xe", "ios xe", "catalyst",
)
_BROCADE_PROMPT_RE = re.compile(r"^(?:SSH|telnet|console)@", re.IGNORECASE)


def detect_vendor(sess):
    prompt = _peek_prompt(sess)
    if _BROCADE_PROMPT_RE.match(prompt):
        sys.stderr.write(
            f"    vendor=brocade (prompt {prompt!r} uses SSH@/telnet@/console@)\n"
        )
        return "brocade"

    out = sess.send_command("show version", timeout=30)
    low = out.lower()

    matched_cisco = next((k for k in _CISCO_VERSION_KEYWORDS if k in low), None)
    if matched_cisco:
        sys.stderr.write(f"    vendor=cisco (show-version matched {matched_cisco!r})\n")
        return "cisco"

    matched_brocade = next((k for k in _BROCADE_VERSION_SUBSTRINGS if k in low), None)
    if matched_brocade:
        sys.stderr.write(f"    vendor=brocade (show-version matched {matched_brocade!r})\n")
        return "brocade"

    m = _BROCADE_VERSION_TOKEN_RE.search(low)
    if m:
        sys.stderr.write(
            f"    vendor=brocade (show-version letter-bounded token {m.group(0)!r})\n"
        )
        return "brocade"

    if "cisco" in low:
        sys.stderr.write("    vendor=cisco (fallback: 'cisco' substring)\n")
        return "cisco"

    snippet = " | ".join(l.strip() for l in out.splitlines() if l.strip())[:240]
    sys.stderr.write(
        f"    vendor=UNKNOWN; show-version snippet: {snippet!r}; prompt: {prompt!r}\n"
    )
    return None


def get_hostname(sess):
    try:
        os.write(sess.fd, b"\n")
        buf = sess._read_until([SSHSession.PROMPT_RE], 5)
        text = _strip_ansi(buf.decode(errors="replace")).strip()
        last = text.splitlines()[-1] if text else ""
        m = re.match(r"^(\S+?)(?:\(.*\))?[>#]\s*$", last)
        if m:
            return m.group(1)
    except Exception:
        pass
    return "unknown"


def read_devices(path):
    hosts = []
    with open(path) as f:
        for raw in f:
            line = raw.split("#", 1)[0].strip()
            if not line:
                continue
            hosts.append(line.split(",", 1)[0].strip().split()[0])
    return hosts


# ===========================================================================
# Router collection + LLM
# ===========================================================================

def prompt_commands():
    """Read commands from stdin until the user enters an empty line."""
    print("Enter commands to run on every router, one per line.")
    print("Blank line to finish.")
    cmds = []
    while True:
        try:
            line = input(f"  cmd[{len(cmds) + 1}]> ").rstrip()
        except EOFError:
            break
        if not line:
            break
        cmds.append(line)
    return cmds


def _disable_paging(sess):
    for cmd in ("terminal length 0", "skip-page-display"):
        try:
            sess.send_command(cmd, timeout=10)
        except Exception:
            pass


def collect(sess, commands):
    results = []
    for cmd in commands:
        sys.stderr.write(f"    > {cmd}\n")
        try:
            out = sess.send_command(cmd, timeout=300)
        except Exception as e:
            out = f"<error running {cmd!r}: {e}>"
        results.append((cmd, out))
    return results


def write_output_file(path, sections):
    with open(path, "w") as f:
        for hostname, vendor, cmds in sections:
            banner = f"== {hostname} [{vendor}] "
            f.write("=" * 80 + "\n")
            f.write(banner + "=" * max(0, 80 - len(banner)) + "\n")
            f.write("=" * 80 + "\n\n")
            for cmd, out in cmds:
                f.write(f"--- {cmd} ---\n")
                f.write(out.rstrip() + "\n\n")


def call_llm(api_key, payload_text):
    body = {
        "model": LLM_MODEL,
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user",   "content": payload_text},
        ],
    }
    data = json.dumps(body).encode("utf-8")
    req = urllib.request.Request(
        LLM_ENDPOINT,
        data=data,
        headers={
            "Authorization": f"Bearer {api_key}",
            "Content-Type":  "application/json",
            "Accept":        "application/json",
        },
        method="POST",
    )
    ctx = ssl.create_default_context()
    try:
        with urllib.request.urlopen(req, context=ctx, timeout=LLM_TIMEOUT_SECS) as resp:
            raw = resp.read().decode("utf-8")
    except urllib.error.HTTPError as e:
        err = e.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"LLM HTTP {e.code}: {err[:500]}")
    except urllib.error.URLError as e:
        raise RuntimeError(f"LLM URL error: {e.reason}")
    try:
        obj = json.loads(raw)
    except json.JSONDecodeError:
        raise RuntimeError(f"LLM returned non-JSON: {raw[:500]}")
    try:
        return obj["choices"][0]["message"]["content"]
    except (KeyError, IndexError, TypeError):
        raise RuntimeError(f"unexpected LLM response shape: {raw[:500]}")


def main():
    no_llm = "--no-llm" in sys.argv[1:] or "--offline" in sys.argv[1:]

    if not os.path.exists(ROUTERS_FILE):
        sys.stderr.write(f"routers.txt not found at {ROUTERS_FILE}\n")
        sys.exit(1)

    routers = read_devices(ROUTERS_FILE)
    if not routers:
        sys.stderr.write("no routers in routers.txt\n")
        sys.exit(1)
    if len(routers) < 2:
        sys.stderr.write(
            "warning: only one router listed -- side-by-side "
            "comparison needs at least two.\n"
        )

    username = input("Username: ").strip()
    password = getpass.getpass("Password: ")
    api_key = ""
    if not no_llm:
        api_key = getpass.getpass("LLM API key (leave blank to skip API call): ")
        if not api_key:
            no_llm = True
            sys.stderr.write("no API key -- skipping LLM call, output will be printed instead\n")

    commands = prompt_commands()
    if not commands:
        sys.stderr.write("no commands entered; aborting\n")
        sys.exit(1)

    sys.stderr.write(
        f"\nrunning {len(commands)} command(s) on {len(routers)} router(s)\n"
    )

    sections = []
    for host in routers:
        sys.stderr.write(f"[*] {host}\n")
        try:
            with SSHSession(host, username, password) as sess:
                _disable_paging(sess)
                vendor = detect_vendor(sess) or "unknown"
                hostname = get_hostname(sess)
                rows = collect(sess, commands)
                sections.append((hostname, vendor, rows))
        except AuthFailure as e:
            sys.stderr.write(f"auth failed: {e}\n")
            sys.stderr.write(
                "aborting before trying remaining routers to avoid "
                "locking out the account. rerun with the correct password.\n"
            )
            sys.exit(3)
        except TimeoutError as e:
            sys.stderr.write(f"    timeout: {e}\n")
        except Exception as e:
            sys.stderr.write(f"    error: {e}\n")

    if not sections:
        sys.stderr.write("no data collected\n")
        sys.exit(2)

    write_output_file(OUTPUT_FILE, sections)
    sys.stderr.write(f"\nwrote {OUTPUT_FILE}\n")

    with open(OUTPUT_FILE) as f:
        payload = f.read()

    if no_llm:
        print()
        print("#" * 78)
        print("# LLM call skipped. Collected output below -- copy from terminal")
        print(f"# or transfer {OUTPUT_FILE} to a host that can reach the API.")
        print("#" * 78)
        print()
        sys.stdout.write(payload)
        sys.stdout.flush()
        sys.stderr.write(f"\n{OUTPUT_FILE} is ready for transfer.\n")
        return

    sys.stderr.write(
        f"sending {len(payload)} bytes to {LLM_ENDPOINT} ({LLM_MODEL}) ...\n"
    )
    try:
        answer = call_llm(api_key, payload)
    except Exception as e:
        sys.stderr.write(f"LLM call failed: {e}\n")
        sys.stderr.write(
            f"\nfalling back to printing {OUTPUT_FILE} so you can send "
            "it from a host that can reach the API.\n\n"
        )
        print("#" * 78)
        print(f"# LLM unreachable. Collected output below ({OUTPUT_FILE}):")
        print("#" * 78)
        print()
        sys.stdout.write(payload)
        sys.stdout.flush()
        sys.exit(4)

    with open(REPORT_FILE, "w") as f:
        f.write(answer.rstrip() + "\n")

    print(answer)
    sys.stderr.write(f"\nwrote {REPORT_FILE}\n")


if __name__ == "__main__":
    main()
