#!/usr/bin/env python3
"""SSH into Cisco IOS or Brocade FastIron/ICX switches and report
hostname, port, description/port-name, and VLAN membership.

Standard library only -- no netmiko / paramiko required.
Requires the system `ssh` client (OpenSSH). Linux or macOS.

Device list: devices.txt in the same directory as this script.
Format: one hostname or IP per line. Blank lines and lines starting
with '#' are ignored. Vendor (Cisco vs. Brocade) is always
auto-detected on connection.

Output: prints a table to stdout and writes port_vlan_report.csv.
"""

import csv
import errno
import getpass
import os
import pty
import re
import select
import shutil
import signal
import sys
import time
from collections import Counter, defaultdict


SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
DEVICES_FILE = os.path.join(SCRIPT_DIR, "devices.txt")
OUTPUT_CSV = os.path.join(SCRIPT_DIR, "port_vlan_report.csv")

# RHEL 9 / modern OpenSSL disables SHA-1 RSA signatures by default, which
# breaks SSH to older Brocade/Cisco images. These per-process env vars
# re-enable just this session -- no root / crypto-policies change needed.
os.environ.setdefault("OPENSSL_ENABLE_SHA1_SIGNATURES", "yes")
os.environ.setdefault("CRYPTO_POLICY", "LEGACY")

# ANSI escape sequence stripper (switches sometimes emit colour/cursor codes)
_ANSI_RE = re.compile(r"\x1b\[[0-9;?]*[A-Za-z]|\x1b\][^\x07]*\x07|\r|\x08")


class AuthFailure(Exception):
    """Raised when the device rejects the supplied credentials."""
# Pager output: Cisco "--More--" and Brocade "--More--, next page: Space ..."
_MORE_RE = re.compile(rb"--\s*[Mm]ore\s*--")
_PAGER_LINE_RE = re.compile(r"--\s*[Mm]ore\s*--[^\r\n]*")


def _strip_ansi(text):
    return _ANSI_RE.sub("", text)


# ---------------------------------------------------------------------------
# SSH session (pty-driven, stdlib only)
# ---------------------------------------------------------------------------

class SSHSession:
    """Minimal interactive SSH session driven via a pty."""

    PROMPT_RE = re.compile(rb"[\r\n][^\r\n]{0,80}[>#]\s*$")
    PW_RE = re.compile(rb"(?i)(password|passphrase)[^:]*:\s*$")
    FAIL_RE = re.compile(
        rb"(?i)(permission denied|authentication fail|access denied|"
        rb"connection (refused|closed|reset)|no route to host|"
        rb"could not resolve hostname|host key verification failed)"
    )

    SSH_OPTS = [
        # Skip any system-wide ssh_config that might override our settings.
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
        # Broaden crypto for older Brocade / Cisco images. The '+' prefix
        # appends to the compiled-in defaults without requiring root.
        "-o", "KexAlgorithms=+diffie-hellman-group1-sha1,"
              "diffie-hellman-group14-sha1,"
              "diffie-hellman-group-exchange-sha1",
        "-o", "HostKeyAlgorithms=+ssh-rsa,ssh-dss,ssh-rsa-cert-v01@openssh.com",
        # Older OpenSSH uses PubkeyAcceptedKeyTypes; newer uses
        # PubkeyAcceptedAlgorithms. Passing both is harmless -- unknown
        # options warn to stderr but do not abort the connection.
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
        self.prompt_terminators = (b">", b"#")

    # ---- process lifecycle ----

    def connect(self):
        if not shutil.which("ssh"):
            raise RuntimeError("'ssh' binary not found in PATH")

        argv = ["ssh"] + self.SSH_OPTS + ["-l", self.username, self.host]
        pid, fd = pty.fork()
        if pid == 0:
            # child
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
        # At the prompt.
        return _strip_ansi(buf.decode(errors="replace"))

    @classmethod
    def _raise_for_failure(cls, buf):
        """Classify a failure buffer and raise AuthFailure or RuntimeError."""
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

    # ---- I/O ----

    def _read_until(self, patterns, timeout):
        buf = b""
        deadline = time.time() + timeout
        while True:
            remaining = deadline - time.time()
            if remaining <= 0:
                raise TimeoutError(
                    f"timeout after {timeout}s; last bytes: "
                    f"{buf[-200:]!r}"
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
        """Send a command and return its output (prompt + echo stripped).

        Automatically feeds a space to '--More--' pager prompts so the
        command completes even before paging is disabled.
        """
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
                    f"timeout after {effective_timeout}s; last bytes: "
                    f"{buf[-200:]!r}"
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
                # Feed a space to advance the pager, then keep reading.
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

    # ---- helpers ----

    @staticmethod
    def _describe_failure(buf):
        txt = _strip_ansi(buf.decode(errors="replace")).strip()
        last = txt.splitlines()[-3:] if txt else []
        return "connection failed: " + " | ".join(l.strip() for l in last if l.strip())


# ---------------------------------------------------------------------------
# Vendor detection
# ---------------------------------------------------------------------------

def detect_vendor(sess):
    """Return 'cisco' or 'brocade' by probing the device."""
    out = sess.send_command("show version", timeout=30).lower()
    if any(k in out for k in ("brocade", "foundry", "fastiron", "icx", "ruckus", "netiron")):
        return "brocade"
    if any(k in out for k in ("cisco", "ios software", "nx-os", "ios-xe", "ios xe")):
        return "cisco"
    return None


def get_hostname(sess):
    """Derive the device hostname from its prompt."""
    # Send a newline to re-print the prompt, then read it.
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


# ---------------------------------------------------------------------------
# Cisco IOS parsing
# ---------------------------------------------------------------------------

def _expand_cisco_port_list(s):
    ports = []
    for chunk in re.split(r",\s*", s.strip()):
        chunk = chunk.strip()
        if not chunk:
            continue
        m = re.match(r"([A-Za-z\-]+)?\s*([\d/]+)(?:-(\d+))?$", chunk)
        if not m:
            ports.append(chunk)
            continue
        prefix, start, end = m.group(1) or "", m.group(2), m.group(3)
        if end is None:
            ports.append(f"{prefix}{start}".strip())
        else:
            head, _, last = start.rpartition("/")
            try:
                for n in range(int(last), int(end) + 1):
                    ports.append(f"{prefix}{head + '/' if head else ''}{n}".strip())
            except ValueError:
                ports.append(chunk)
    return ports


def collect_cisco(sess):
    vlan_brief = sess.send_command("show vlan brief", timeout=60)
    desc_out = sess.send_command("show interfaces description", timeout=60)
    status_out = sess.send_command("show interfaces status", timeout=60)
    trunk_out = sess.send_command("show interfaces trunk", timeout=60)

    port_vlan = {}
    current_vlan = None
    ports_blob = ""
    for line in vlan_brief.splitlines():
        m = re.match(r"^\s*(\d+)\s+\S.*?\s+(?:active|act/lshut|suspended)\s*(.*)$", line)
        if m:
            if current_vlan and ports_blob:
                for p in _expand_cisco_port_list(ports_blob):
                    port_vlan[p] = current_vlan
            current_vlan = m.group(1)
            ports_blob = m.group(2).strip()
        elif current_vlan and re.match(r"^\s{10,}\S", line):
            ports_blob += ", " + line.strip()
    if current_vlan and ports_blob:
        for p in _expand_cisco_port_list(ports_blob):
            port_vlan[p] = current_vlan

    status_map = {}
    for line in status_out.splitlines():
        m = re.match(r"^(\S+)\s+(.{0,19}?)\s{2,}(\S+)\s+(\S+)\s+", line)
        if m and m.group(1).lower() != "port":
            port, name, _status, vlan = m.group(1), m.group(2).strip(), m.group(3), m.group(4)
            status_map[port] = {"name": name, "vlan": vlan}

    trunk_map = {}
    in_allowed = False
    for line in trunk_out.splitlines():
        if line.startswith("Port") and "Vlans allowed on trunk" in line:
            in_allowed = True
            continue
        if in_allowed:
            if not line.strip():
                in_allowed = False
                continue
            m = re.match(r"^(\S+)\s+(.+)$", line)
            if m:
                trunk_map[m.group(1)] = m.group(2).strip()

    desc_map = {}
    for line in desc_out.splitlines():
        if line.startswith("Interface") or not line.strip():
            continue
        m = re.match(r"^(\S+)\s+\S+\s+\S+\s*(.*)$", line)
        if m:
            desc_map[m.group(1)] = m.group(2).strip()

    rows = []
    all_ports = set(status_map) | set(port_vlan) | set(desc_map) | set(trunk_map)
    for port in sorted(all_ports, key=_port_sort_key):
        desc = desc_map.get(port, status_map.get(port, {}).get("name", ""))
        if port in trunk_map:
            vlan = f"trunk:{trunk_map[port]}"
        else:
            vlan = status_map.get(port, {}).get("vlan") or port_vlan.get(port, "")
        rows.append({"port": port, "description": desc, "vlan": vlan})
    return rows


# ---------------------------------------------------------------------------
# Brocade FastIron / ICX parsing
# ---------------------------------------------------------------------------

def _expand_brocade_port_list(tokens):
    ports = []
    i = 0
    while i < len(tokens):
        t = tokens[i]
        if t.lower() in ("ethe", "ethernet"):
            if i + 3 < len(tokens) and tokens[i + 2].lower() == "to":
                ports.extend(_brocade_range(tokens[i + 1], tokens[i + 3]))
                i += 4
            elif i + 1 < len(tokens):
                ports.append(tokens[i + 1])
                i += 2
            else:
                i += 1
        else:
            i += 1
    return ports


def _brocade_range(start, end):
    head_s, _, last_s = start.rpartition("/")
    head_e, _, last_e = end.rpartition("/")
    if head_s != head_e:
        return [start, end]
    try:
        return [f"{head_s}/{n}" for n in range(int(last_s), int(last_e) + 1)]
    except ValueError:
        return [start, end]


# Port descriptions containing any of these tokens are excluded from the
# Brocade report because they are known uplink / trunk / AP / management
# ports that do not fit the per-port "what VLAN is this in" model.
# Matching is case-insensitive substring -- "has X in the description" --
# so run-together names like 'MYIS01UPLINK' and underscore-wrapped names
# like '_IS02_' are both caught.
_BROCADE_SKIP_TOKENS = (
    "IS01", "IS02",
    "DR01", "DR02",
    "IR01", "IR02",
    "OS01", "OS02",
    "MGMT",        # 'Sup mgmt port', 'mgmt', etc.
    "MANAGEMENT",  # 'Management Port', 'Switch Management', etc.
)
# 'AP' is a short token. Require that the 'A' and 'P' not be flanked by
# another letter, so we still catch AP, -AP-, AP5, AP01, AP-01, etc., but
# skip false positives like APARTMENT, TRAPPING, HANDICAP, CHEAP.
_BROCADE_SKIP_AP_RE = re.compile(
    r"(?<![A-Za-z])AP(?![A-Za-z])",
    re.IGNORECASE,
)


def _should_skip_brocade(desc):
    if not desc:
        return False
    upper = desc.upper()
    if any(tok in upper for tok in _BROCADE_SKIP_TOKENS):
        return True
    if _BROCADE_SKIP_AP_RE.search(desc):
        return True
    return False


def collect_brocade(sess):
    """Parse 'show running-config' and emit one row per access port.

    Policy (per the operator's requirements):
      * A port is reported only if its 'interface ethernet' stanza has
        'authentication auth-default-vlan <N>'. Nothing else sources the
        VLAN -- vlan blocks, dual-mode, brief Pvid are all ignored.
      * The vlan column is just the number.
      * Ports whose port-name matches the skip list (IS01/IS02/DR01/DR02/
        IR01/IR02/OS01/OS02/AP) are dropped; these are known uplink/AP
        ports that live on multiple VLANs.
    """
    run_out = sess.send_command("show running-config", timeout=180)

    port_name = {}
    port_auth_default = {}

    lines = run_out.splitlines()
    i = 0
    while i < len(lines):
        line = lines[i]
        stripped = line.strip()

        m = re.match(r"^interface\s+ethernet\s+(\S+)", stripped, re.IGNORECASE)
        if m and not line.startswith((" ", "\t")):
            port = m.group(1)
            i += 1
            while i < len(lines):
                inner = lines[i]
                s = inner.strip()
                if s == "!" or (inner and not inner.startswith((" ", "\t"))):
                    break
                pn = re.match(r"^port-name\s+(.+)$", s, re.IGNORECASE)
                if pn:
                    port_name[port] = pn.group(1).strip().strip('"')
                ad = re.match(
                    r"^authentication\s+auth-default-vlan\s+(\d+)\s*$",
                    s, re.IGNORECASE,
                )
                if ad:
                    port_auth_default[port] = ad.group(1)
                i += 1
            continue

        i += 1

    rows = []
    skipped = 0
    for port in sorted(port_auth_default, key=_port_sort_key):
        desc = port_name.get(port, "")
        if _should_skip_brocade(desc):
            sys.stderr.write(f"    skip {port} vlan={port_auth_default[port]} desc={desc!r}\n")
            skipped += 1
            continue
        rows.append({
            "port": port,
            "description": desc,
            "vlan": port_auth_default[port],
        })
    sys.stderr.write(
        f"    ({len(rows)} kept, {skipped} filtered out of "
        f"{len(port_auth_default)} ports with auth-default-vlan)\n"
    )
    return rows


# ---------------------------------------------------------------------------
# Orchestration
# ---------------------------------------------------------------------------

def _port_sort_key(p):
    return [int(x) if x.isdigit() else x.lower() for x in re.findall(r"\d+|\D+", p)]


def read_devices(path):
    hosts = []
    with open(path) as f:
        for raw in f:
            line = raw.split("#", 1)[0].strip()
            if not line:
                continue
            hosts.append(line.split(",", 1)[0].strip().split()[0])
    return hosts


def process_device(host, username, password):
    with SSHSession(host, username, password) as sess:
        # Try to enter enable mode on Cisco. Brocade is typically enabled
        # at login; 'enable' there either no-ops or prompts for a password
        # we don't have. Best effort, ignore failures.
        try:
            os.write(sess.fd, b"enable\n")
            sess._read_until([SSHSession.PROMPT_RE, SSHSession.PW_RE], 5)
        except Exception:
            pass

        # Disable paging up front, before we know the vendor. Each command
        # is a no-op on the other platform (invalid-input error + reprompt),
        # so sending both is safe and keeps 'show version' from hitting
        # --More--.
        for paging_cmd in ("terminal length 0", "skip-page-display"):
            try:
                sess.send_command(paging_cmd, timeout=10)
            except Exception:
                pass

        vendor = detect_vendor(sess)
        if vendor not in ("cisco", "brocade"):
            raise RuntimeError(f"could not determine vendor for {host}")

        hostname = get_hostname(sess)

        if vendor == "cisco":
            rows = collect_cisco(sess)
        else:
            rows = collect_brocade(sess)

        for r in rows:
            r["hostname"] = hostname
            r["vendor"] = vendor
        return rows


def main():
    if not shutil.which("ssh"):
        sys.stderr.write("error: 'ssh' binary not found in PATH\n")
        sys.exit(1)

    if not os.path.exists(DEVICES_FILE):
        sys.stderr.write(f"devices.txt not found at {DEVICES_FILE}\n")
        sys.exit(1)

    devices = read_devices(DEVICES_FILE)
    if not devices:
        sys.stderr.write("no devices in devices.txt\n")
        sys.exit(1)

    username = input("Username: ").strip()
    password = getpass.getpass("Password: ")

    all_rows = []
    for host in devices:
        sys.stderr.write(f"[*] {host} ... ")
        sys.stderr.flush()
        try:
            rows = process_device(host, username, password)
            vendor = rows[0]["vendor"] if rows else "?"
            all_rows.extend(rows)
            sys.stderr.write(f"ok [{vendor}] ({len(rows)} ports)\n")
        except AuthFailure as e:
            # Stop immediately on auth failure. We use the same credentials
            # for every device, so if one rejects them the rest will too --
            # and retrying could lock the account out.
            sys.stderr.write(f"auth failed: {e}\n")
            sys.stderr.write(
                "aborting before trying remaining devices to avoid "
                "locking out the account. rerun with the correct password.\n"
            )
            sys.exit(3)
        except TimeoutError as e:
            sys.stderr.write(f"timeout ({e})\n")
        except Exception as e:
            sys.stderr.write(f"error: {e}\n")

    if not all_rows:
        sys.stderr.write("no data collected\n")
        sys.exit(2)

    fieldnames = ["hostname", "vendor", "port", "description", "vlan"]
    with open(OUTPUT_CSV, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fieldnames)
        w.writeheader()
        for r in all_rows:
            w.writerow({k: r.get(k, "") for k in fieldnames})

    widths = {k: max(len(k), *(len(str(r.get(k, ""))) for r in all_rows)) for k in fieldnames}
    fmt = "  ".join("{:<" + str(widths[k]) + "}" for k in fieldnames)
    print(fmt.format(*fieldnames))
    print(fmt.format(*("-" * widths[k] for k in fieldnames)))
    for r in all_rows:
        print(fmt.format(*(str(r.get(k, "")) for k in fieldnames)))

    # Summary: total ports per VLAN across all devices.
    counts = Counter(r["vlan"] for r in all_rows if r.get("vlan"))
    if counts:
        print()
        print("VLAN totals:")
        vlan_width = max(len(str(v)) for v in counts)
        for vlan in sorted(counts, key=lambda v: (0, int(v)) if v.isdigit() else (1, v)):
            print(f"  VLAN {str(vlan):<{vlan_width}} : {counts[vlan]}")

    sys.stderr.write(f"\nwrote {OUTPUT_CSV}\n")


if __name__ == "__main__":
    main()
