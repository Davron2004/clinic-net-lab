"""Talking to the running lab: which machines exist, their addresses, running commands."""
import functools
import ipaddress
import json
import os
import subprocess
import time
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
RUN = Path(os.environ.get("CLINIC_RUN_DIR", ROOT / "run"))
LAB = os.environ.get("CLINIC_LAB", "clinic")


def load_policy(name="clinic"):
    with open(ROOT / "policy" / f"{name}.yml") as f:
        return yaml.safe_load(f)


def variant():
    """Which network is deployed: 'clinic' (segmented) or 'flat' (before)."""
    try:
        return (RUN / "variant").read_text().strip()
    except FileNotFoundError:
        return "clinic"


def container(policy, node):
    spec = policy["nodes"].get(node, {})
    return f"clab-{LAB}-{spec.get('container', node)}"


def sh(node_container, cmd, timeout=30):
    """Run a shell command inside a lab machine. Returns (exit_code, output)."""
    try:
        p = subprocess.run(["docker", "exec", node_container, "bash", "-c", cmd],
                           capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return 124, "timeout"
    return p.returncode, (p.stdout + p.stderr).strip()


@functools.lru_cache(maxsize=None)
def _live_ip(node_container):
    code, out = sh(node_container, "ip -4 -o addr show dev eth1 | awk '{print $4}' | cut -d/ -f1")
    return out.splitlines()[0] if code == 0 and out else None


@functools.lru_cache(maxsize=None)
def gateway_of(node_container):
    code, out = sh(node_container, "ip -4 route show default | awk '{print $3}'")
    return out.splitlines()[0] if code == 0 and out else None


def ip_of(policy, node, net=None):
    net = net or variant()
    ip = policy["nodes"][node]["ip"][net]
    return _live_ip(container(policy, node)) if ip == "dhcp" else str(ip)


def ip_index(policy, net=None):
    """Map every known address (including live DHCP leases) to a node name."""
    net = net or variant()
    index = {}
    for name, spec in policy["nodes"].items():
        if spec.get("container"):
            continue
        ip = ip_of(policy, name, net)
        if ip:
            index[ip] = name
    # The router answers on one address per zone; all of them are "router".
    for zone in policy["zones"].values():
        if net == "clinic" and zone.get("subnet"):
            gw = str(next(ipaddress.ip_network(zone["subnet"]).hosts()))
            index[gw] = "router"
    index["198.51.100.2"] = "router"
    return index


def emit(event):
    """Append one event to run/events.jsonl, which the clinic map follows live."""
    event.setdefault("ts", time.time())
    RUN.mkdir(parents=True, exist_ok=True)
    with open(RUN / "events.jsonl", "a") as f:
        f.write(json.dumps(event) + "\n")
