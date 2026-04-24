#!/usr/bin/env python3
"""SSH into every device in devices.txt, run a fixed set of
troubleshooting commands, write the raw output to commands.txt, then
ask an OpenAI-compatible chat-completions endpoint (model
'gemini-2.5-flash' via the configured gateway) to review the output
as a network engineer and suggest next steps.

Standard library only. Reuses the SSH/pty machinery from
switch_port_vlan_checker.py which lives next to this file.

Inputs:
  * devices.txt     -- one hostname/IP per line, '#' comments ignored.
                       Shared with switch_port_vlan_checker.py.
  * SSH username / password -- prompted once at startup.
  * LLM API key -- prompted once at startup (via getpass, so it is
                   never echoed to the terminal and never persisted).

Outputs:
  * commands.txt              -- raw command output, grouped per device.
  * troubleshoot_report.txt   -- the LLM's analysis.

Edit LLM_ENDPOINT and the TROUBLESHOOT_COMMANDS lists below to suit
your environment.
"""

import getpass
import json
import os
import ssl
import sys
import urllib.error
import urllib.request

from switch_port_vlan_checker import (
    AuthFailure,
    SSHSession,
    detect_vendor,
    get_hostname,
    read_devices,
)


SCRIPT_DIR     = os.path.dirname(os.path.abspath(__file__))
DEVICES_FILE   = os.path.join(SCRIPT_DIR, "devices.txt")
COMMANDS_FILE  = os.path.join(SCRIPT_DIR, "commands.txt")
REPORT_FILE    = os.path.join(SCRIPT_DIR, "troubleshoot_report.txt")

# --- LLM configuration -----------------------------------------------------
# Edit LLM_ENDPOINT to your real chat-completions URL.
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


# --- Collection -----------------------------------------------------------

def collect_commands(sess, vendor):
    """Run every troubleshooting command for this vendor and return
    an ordered list of (cmd, output) tuples so the on-disk order is
    predictable."""
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
    """sections = list of (hostname, vendor, [(cmd, output), ...])."""
    with open(path, "w") as f:
        for hostname, vendor, cmds in sections:
            banner = f"== {hostname} [{vendor}] "
            f.write("=" * 80 + "\n")
            f.write(banner + "=" * max(0, 80 - len(banner)) + "\n")
            f.write("=" * 80 + "\n\n")
            for cmd, out in cmds:
                f.write(f"--- {cmd} ---\n")
                f.write(out.rstrip() + "\n\n")


# --- LLM call -------------------------------------------------------------

def call_llm(api_key, payload_text):
    """POST an OpenAI-compatible chat-completions request and return
    the assistant's message content as a string. stdlib only."""
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


# --- Orchestration --------------------------------------------------------

def _disable_paging(sess):
    """Send both vendors' paging-off commands; errors on the wrong
    vendor are harmless (% Invalid input ... and re-prompt)."""
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

    api_key = getpass.getpass("LLM API key: ")
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
                    sys.stderr.write(f"    unknown vendor, skipping\n")
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
