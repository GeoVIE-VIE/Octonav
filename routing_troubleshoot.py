#!/usr/bin/env python3
"""Routing-focused SSH + LLM troubleshooting helper.

Use this when you're debugging a routing problem between two (or more)
routers and you already suspect the issue lives at Layer 3 or above --
routing protocols, route tables, IP addressing, ACLs / route-maps /
policy, neighbor adjacencies, etc. The LLM is primed to ignore L1/L2
(cabling, link negotiation, MAC learning, STP, ...).

Workflow:
  1. Read routers.txt (one hostname/IP per line, same format as
     devices.txt; '#' comments and blank lines ignored).
  2. Prompt for SSH username, SSH password, and LLM API key.
  3. Prompt for a list of commands -- one per line, empty line ends
     input. The SAME list runs on every router so outputs can be
     compared.
  4. SSH into each router, run each command, write the raw output to
     routing_output.txt with per-router banners and per-command
     sections.
  5. POST the aggregated file to the configured chat-completions
     endpoint. Save the assistant's analysis to routing_report.txt
     and print it to stdout.

Standard library only. Reuses the SSH/pty machinery from
switch_port_vlan_checker.py which lives next to this file.
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


SCRIPT_DIR   = os.path.dirname(os.path.abspath(__file__))
ROUTERS_FILE = os.path.join(SCRIPT_DIR, "routers.txt")
OUTPUT_FILE  = os.path.join(SCRIPT_DIR, "routing_output.txt")
REPORT_FILE  = os.path.join(SCRIPT_DIR, "routing_report.txt")

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


# --- Helpers --------------------------------------------------------------

def prompt_commands():
    """Read commands from stdin until the user enters an empty line.

    Returns a list of non-empty command strings. The same list will be
    executed on every router.
    """
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
    """Send both vendors' paging-off commands; the wrong-vendor one
    prints an 'invalid input' error and re-prompts, which is harmless."""
    for cmd in ("terminal length 0", "skip-page-display"):
        try:
            sess.send_command(cmd, timeout=10)
        except Exception:
            pass


def collect(sess, commands):
    """Run each command verbatim and return a list of (cmd, output)."""
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


def call_llm(api_key, payload_text):
    """POST to the OpenAI-compatible chat-completions endpoint and
    return the assistant message. stdlib only."""
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

def main():
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
    api_key  = getpass.getpass("LLM API key: ")
    if not api_key:
        sys.stderr.write("no LLM API key supplied; aborting\n")
        sys.exit(1)

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
