#!/usr/bin/env python3
"""SSH into Cisco IOS or Brocade FastIron/ICX switches and report
hostname, port, description/port-name, and VLAN membership.

Device list: devices.txt in the same directory as this script.
Format (one per line):
    hostname[,vendor]
where vendor is 'cisco' or 'brocade'. If omitted, vendor is auto-detected.
Blank lines and lines starting with '#' are ignored.

Output: prints a table to stdout and writes port_vlan_report.csv.
"""

import csv
import getpass
import os
import re
import sys
from collections import defaultdict

try:
    from netmiko import ConnectHandler
    from netmiko.exceptions import NetmikoAuthenticationException, NetmikoTimeoutException
except ImportError:
    sys.stderr.write(
        "netmiko is required. Install with: pip install netmiko\n"
    )
    sys.exit(1)


SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
DEVICES_FILE = os.path.join(SCRIPT_DIR, "devices.txt")
OUTPUT_CSV = os.path.join(SCRIPT_DIR, "port_vlan_report.csv")


def read_devices(path):
    devices = []
    with open(path) as f:
        for raw in f:
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            parts = [p.strip() for p in line.split(",")]
            host = parts[0]
            vendor = parts[1].lower() if len(parts) > 1 and parts[1] else None
            devices.append((host, vendor))
    return devices


def detect_vendor(conn):
    """Return 'cisco' or 'brocade' by probing the device."""
    out = conn.send_command("show version", read_timeout=30)
    low = out.lower()
    if "brocade" in low or "foundry" in low or "fastiron" in low or "icx" in low or "ruckus" in low:
        return "brocade"
    if "cisco" in low or "ios" in low or "nx-os" in low:
        return "cisco"
    return None


def get_hostname(conn, vendor):
    """Return the device's configured hostname."""
    try:
        prompt = conn.find_prompt()
        # Strip trailing prompt chars (#, >, (config)..., etc.)
        name = re.sub(r"[>#].*$", "", prompt).strip()
        name = re.sub(r"\(.*\)$", "", name).strip()
        if name:
            return name
    except Exception:
        pass
    return "unknown"


# ---------------------------------------------------------------------------
# Cisco IOS parsing
# ---------------------------------------------------------------------------

def _expand_cisco_port_list(s):
    """Expand 'Gi1/0/1-3, Gi1/0/5' style lists into individual interfaces."""
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


def collect_cisco(conn):
    """Return list of dicts: port, description, vlan."""
    vlan_brief = conn.send_command("show vlan brief", read_timeout=60)
    desc_out = conn.send_command("show interfaces description", read_timeout=60)
    status_out = conn.send_command("show interfaces status", read_timeout=60)
    trunk_out = conn.send_command("show interfaces trunk", read_timeout=60)

    # Map port -> vlan from 'show vlan brief' (access ports only)
    port_vlan = {}
    current_vlan = None
    ports_blob = ""
    # Parse the tabular output. Rows look like:
    # 10   DATA     active    Gi1/0/1, Gi1/0/2, Gi1/0/3
    #                                  Gi1/0/4
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

    # Supplement with 'show interfaces status' (gives short-name port + access VLAN)
    # Port      Name        Status        Vlan       Duplex  Speed Type
    status_map = {}
    for line in status_out.splitlines():
        m = re.match(r"^(\S+)\s+(.{0,19}?)\s{2,}(\S+)\s+(\S+)\s+", line)
        if m and m.group(1).lower() != "port":
            port, name, _status, vlan = m.group(1), m.group(2).strip(), m.group(3), m.group(4)
            status_map[port] = {"name": name, "vlan": vlan}

    # Trunks: gather allowed VLAN list per trunk port
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

    # Descriptions
    # Interface   Status   Protocol  Description
    desc_map = {}
    for line in desc_out.splitlines():
        if line.startswith("Interface") or not line.strip():
            continue
        m = re.match(r"^(\S+)\s+\S+\s+\S+\s*(.*)$", line)
        if m:
            desc_map[m.group(1)] = m.group(2).strip()

    # Merge. Use status_map as the canonical port list.
    rows = []
    all_ports = set(status_map.keys()) | set(port_vlan.keys()) | set(desc_map.keys()) | set(trunk_map.keys())
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
    """Expand 'ethe 1/1/1 to 1/1/24' or 'ethe 1/1/1 ethe 1/1/5' lists."""
    ports = []
    i = 0
    while i < len(tokens):
        t = tokens[i]
        if t.lower() in ("ethe", "ethernet"):
            if i + 3 < len(tokens) and tokens[i + 2].lower() == "to":
                start, end = tokens[i + 1], tokens[i + 3]
                ports.extend(_brocade_range(start, end))
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


def collect_brocade(conn):
    vlan_out = conn.send_command("show vlan", read_timeout=120)
    # 'show interface brief' gives concise port + name + VLAN
    brief = conn.send_command("show interface brief", read_timeout=120)

    # Parse `show vlan` blocks:
    # PORT-VLAN 10, Name DATA, Priority Level -, ...
    #  Untagged Ports : ethe 1/1/1 to 1/1/24
    #  Tagged Ports   : ethe 1/1/48
    port_vlan_untagged = {}
    port_vlan_tagged = defaultdict(list)
    current_vlan = None
    for raw in vlan_out.splitlines():
        line = raw.strip()
        m = re.match(r"^PORT-VLAN\s+(\d+)", line, re.IGNORECASE)
        if m:
            current_vlan = m.group(1)
            continue
        if current_vlan is None:
            continue
        m = re.match(r"^(Untagged|Tagged)\s+Ports\s*:\s*(.*)$", line, re.IGNORECASE)
        if m:
            kind = m.group(1).lower()
            tokens = m.group(2).split()
            for p in _expand_brocade_port_list(tokens):
                if kind == "untagged":
                    port_vlan_untagged[p] = current_vlan
                else:
                    port_vlan_tagged[p].append(current_vlan)

    # Parse `show interface brief` for names.
    # Port   Link    State    Dupl Speed Trunk Tag Pvid Pri MAC            Name
    # 1/1/1  Up      Forward  Full 1G    None  No  10   0   aaaa.bbbb.cccc MyName
    brief_map = {}
    header_seen = False
    name_col = None
    for line in brief.splitlines():
        if not header_seen:
            if re.search(r"^\s*Port\s+Link", line):
                header_seen = True
                name_col = line.lower().find("name")
            continue
        if not line.strip():
            continue
        parts = line.split()
        if not parts:
            continue
        port = parts[0]
        if not re.match(r"^\d+(/\d+)+$", port):
            continue
        name = ""
        if name_col is not None and len(line) > name_col:
            name = line[name_col:].strip()
        brief_map[port] = name

    rows = []
    all_ports = set(brief_map.keys()) | set(port_vlan_untagged.keys()) | set(port_vlan_tagged.keys())
    for port in sorted(all_ports, key=_port_sort_key):
        desc = brief_map.get(port, "")
        untagged = port_vlan_untagged.get(port)
        tagged = port_vlan_tagged.get(port, [])
        if tagged and untagged:
            vlan = f"untagged:{untagged} tagged:{','.join(tagged)}"
        elif tagged:
            vlan = f"tagged:{','.join(tagged)}"
        elif untagged:
            vlan = untagged
        else:
            vlan = ""
        rows.append({"port": port, "description": desc, "vlan": vlan})
    return rows


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _port_sort_key(p):
    # Split letters and digits so Gi1/0/2 sorts before Gi1/0/10.
    return [int(x) if x.isdigit() else x.lower() for x in re.findall(r"\d+|\D+", p)]


def process_device(host, vendor_hint, username, password):
    base = {
        "host": host,
        "username": username,
        "password": password,
        "fast_cli": False,
    }
    # Try a sensible device_type based on hint, else default to autodetect.
    if vendor_hint == "cisco":
        device_type = "cisco_ios"
    elif vendor_hint == "brocade":
        device_type = "brocade_fastiron"
    else:
        device_type = "autodetect"

    if device_type == "autodetect":
        # netmiko autodetect is heavy; just connect as a generic terminal.
        device_type = "generic_termserver"

    conn = ConnectHandler(device_type=device_type, **base)
    try:
        try:
            conn.enable()
        except Exception:
            pass

        vendor = vendor_hint or detect_vendor(conn)
        if vendor not in ("cisco", "brocade"):
            raise RuntimeError(f"could not determine vendor for {host}")

        # Disable paging.
        if vendor == "cisco":
            conn.send_command("terminal length 0", expect_string=r"[>#]")
        else:
            conn.send_command("skip-page-display", expect_string=r"[>#]")

        hostname = get_hostname(conn, vendor)
        if vendor == "cisco":
            rows = collect_cisco(conn)
        else:
            rows = collect_brocade(conn)
        for r in rows:
            r["hostname"] = hostname
            r["vendor"] = vendor
        return rows
    finally:
        conn.disconnect()


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

    all_rows = []
    for host, vendor in devices:
        sys.stderr.write(f"[*] {host} ({vendor or 'auto'}) ... ")
        sys.stderr.flush()
        try:
            rows = process_device(host, vendor, username, password)
            all_rows.extend(rows)
            sys.stderr.write(f"ok ({len(rows)} ports)\n")
        except NetmikoAuthenticationException:
            sys.stderr.write("auth failed\n")
        except NetmikoTimeoutException:
            sys.stderr.write("timeout\n")
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

    # Console table.
    widths = {k: max(len(k), *(len(str(r.get(k, ""))) for r in all_rows)) for k in fieldnames}
    fmt = "  ".join("{:<" + str(widths[k]) + "}" for k in fieldnames)
    print(fmt.format(*fieldnames))
    print(fmt.format(*("-" * widths[k] for k in fieldnames)))
    for r in all_rows:
        print(fmt.format(*(str(r.get(k, "")) for k in fieldnames)))

    sys.stderr.write(f"\nwrote {OUTPUT_CSV}\n")


if __name__ == "__main__":
    main()
