#!/usr/bin/env python3
"""SSH into every device in devices.txt, run a fixed set of
troubleshooting commands, write the raw output to commands.txt, then
ask an OpenAI-compatible chat-completions endpoint (model
'gemini-2.5-flash' via the configured gateway) to review the output
as a network engineer and suggest next steps.

Standalone script. Python standard library only -- requires nothing
from pip and does not import from any other file in this repo. Just
drop the script and devices.txt into a directory and run it.

Inputs:
  * devices.txt  -- one hostname/IP per line, '#' comments ignored.
  * SSH username / password -- prompted once at startup.
  * LLM API key  -- prompted once at startup (via getpass, so it is
                    never echoed to the terminal and never persisted).

Outputs:
  * commands.txt             -- raw command output, grouped per device.
  * troubleshoot_report.txt  -- the LLM's analysis.

Edit LLM_ENDPOINT and the TROUBLESHOOT_COMMANDS lists below to suit
your environment.
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


SCRIPT_DIR    = os.path.dirname(os.path.abspath(__file__))
DEVICES_FILE  = os.path.join(SCRIPT_DIR, "devices.txt")
COMMANDS_FILE = os.path.join(SCRIPT_DIR, "commands.txt")
REPORT_FILE   = os.path.join(SCRIPT_DIR, "troubleshoot_report.txt")

# RHEL 9 / modern OpenSSL disables SHA-1 RSA signatures by default, which
# breaks SSH to older Brocade/Cisco images. These per-process env vars
# re-enable just this session -- no root / crypto-policies change needed.
os.environ.setdefault("OPENSSL_ENABLE_SHA1_SIGNATURES", "yes")
os.environ.setdefault("CRYPTO_POLICY", "LEGACY")

# --- LLM configuration -----------------------------------------------------
LLM_ENDPOINT = "https://xyz.xyz.xyz/v1/chat/completions"
LLM_MODEL    = "gemini-2.5-flash"
SYSTEM_PROMPT = (
    "You are an AI network engineer aiding in performing "
    "troubleshooting for the devices mentioned."
)
LLM_TIMEOUT_SECS = 180

# --- Per-vendor command list ----------------------------------------------
# Edit to taste. Each command is executed verbatim on the device.
TROUBLESHOOT_COMMANDS = {
    "cisco": [
        "show version",
        "show running-config",
        "show interfaces status",
        "show ip interface brief",
        "show logging",
        "show cdp neighbors",
        "show mac address-table",
    ],
    "brocade": [
        "show version",
        "show running-config",
        "show interface brief",
        "show logging",
        "show lldp neighbors",
        "show mac-address",
    ],
}


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
# Troubleshoot collection + LLM
# ===========================================================================

def collect_commands(sess, vendor):
    results = []
    for cmd in TROUBLESHOOT_COMMANDS[vendor]:
        sys.stderr.write(f"    > {cmd}\n")
        try:
            out = sess.send_command(cmd, timeout=300)
        except Exception as e:
            out = f"<error running {cmd!r}: {e}>"
        results.append((cmd, out))
    return results


def write_commands_file(path, sections):
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


def _disable_paging(sess):
    for cmd in ("terminal length 0", "skip-page-display"):
        try:
            sess.send_command(cmd, timeout=10)
        except Exception:
            pass


def main():
    if not os.path.exists(DEVICES_FILE):
        sys.stderr.write(f"devices.txt not found at {DEVICES_FILE}\n")
        sys.exit(1)

    devices = read_devices(DEVICES_FILE)
    if not devices:
        sys.stderr.write("no devices in devices.txt\n")
        sys.exit(1)

    username = input("Username: ").strip()
    password = getpass.getpass("Password: ")
    api_key  = getpass.getpass("LLM API key: ")
    if not api_key:
        sys.stderr.write("no LLM API key supplied; aborting\n")
        sys.exit(1)

    sections = []
    for host in devices:
        sys.stderr.write(f"[*] {host}\n")
        try:
            with SSHSession(host, username, password) as sess:
                _disable_paging(sess)
                vendor = detect_vendor(sess)
                if vendor not in TROUBLESHOOT_COMMANDS:
                    sys.stderr.write("    unknown vendor, skipping\n")
                    continue
                hostname = get_hostname(sess)
                cmds = collect_commands(sess, vendor)
                sections.append((hostname, vendor, cmds))
        except AuthFailure as e:
            sys.stderr.write(f"auth failed: {e}\n")
            sys.stderr.write(
                "aborting before trying remaining devices to avoid "
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

    write_commands_file(COMMANDS_FILE, sections)
    sys.stderr.write(f"\nwrote {COMMANDS_FILE}\n")

    with open(COMMANDS_FILE) as f:
        payload = f.read()

    sys.stderr.write(
        f"sending {len(payload)} bytes to {LLM_ENDPOINT} ({LLM_MODEL}) ...\n"
    )
    try:
        answer = call_llm(api_key, payload)
    except Exception as e:
        sys.stderr.write(f"LLM call failed: {e}\n")
        sys.exit(4)

    with open(REPORT_FILE, "w") as f:
        f.write(answer.rstrip() + "\n")

    print(answer)
    sys.stderr.write(f"\nwrote {REPORT_FILE}\n")


if __name__ == "__main__":
    main()
