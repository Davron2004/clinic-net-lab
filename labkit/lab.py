"""Talking to the running lab: which machines exist, their addresses, running commands."""
import functools
import ipaddress
import json
import os
import subprocess
import time
import uuid
from contextlib import contextmanager
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


# Exit code sh() returns when the command never ran inside the machine
# (the machine is missing, stopped or paused). docker exec itself says 1 in
# those cases, which a probe would mistake for "blocked".
NOT_RUN = 125


def sh(node_container, cmd, timeout=30):
    """Run a shell command inside a lab machine. Returns (exit_code, output).

    Exit codes: the command's own, 124 if it timed out, NOT_RUN if Docker
    could not run it at all.
    """
    try:
        p = subprocess.run(["docker", "exec", node_container, "bash", "-c", cmd],
                           capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return 124, "timeout"
    except FileNotFoundError:
        return NOT_RUN, "docker is not installed here"
    if p.returncode != 0 and p.stderr.startswith("Error response from daemon"):
        return NOT_RUN, p.stderr.strip()
    return p.returncode, (p.stdout + p.stderr).strip()


# A machine is "alive" when it finished booting and can reach its own
# gateway. Machines without a default route (the simulated internet) only
# need to have booted.
ALIVE_CHECK = (
    'test -f /run/clinic/ready || { echo "has not finished booting"; exit 1; }; '
    "gw=$(ip -4 route show default | awk '{print $3; exit}'); "
    'if [ -n "$gw" ]; then ping -c 1 -W 2 "$gw" >/dev/null || { echo "cannot ping its gateway $gw"; exit 1; }; fi'
)


def alive(node_container):
    """Is this machine running and on the network? Returns (ok, reason)."""
    code, out = sh(node_container, ALIVE_CHECK, timeout=15)
    if code == 0:
        return True, ""
    return False, out.splitlines()[-1] if out else f"check failed (exit {code})"


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
        # Inside the VPN a laptop has a second address; the firewall log shows that one.
        if net == "clinic" and spec.get("tunnel_ip"):
            index[str(spec["tunnel_ip"])] = name
    # The router answers on one address per zone; all of them are "router".
    for zone in policy["zones"].values():
        if net == "clinic" and zone.get("subnet"):
            gw = str(next(ipaddress.ip_network(zone["subnet"]).hosts()))
            index[gw] = "router"
    index["198.51.100.2"] = "router"
    if net == "clinic":
        index["10.10.60.1"] = "router"   # the router's end of the VPN tunnel
    return index


def emit(event):
    """Append one event to run/events.jsonl, which the clinic map follows live."""
    event.setdefault("ts", time.time())
    RUN.mkdir(parents=True, exist_ok=True)
    with open(RUN / "events.jsonl", "a") as f:
        f.write(json.dumps(event) + "\n")


# ---------------------------------------------------------------- quiet time
# Measurements (the isolation suite, attack scenarios) pause the routine
# traffic generator (labkit/traffic.py) so their results and the map's replay
# contain only their own packets. The handshake:
#   1. the measurement drops a flag file in run/traffic-pause/
#   2. the generator stops starting new actions, waits for the ones in flight
#      to finish, then lists the flag in run/traffic-state.json
#   3. the measurement starts only once it sees its flag listed there
# The generator rewrites the state file several times a second; a state file
# that is not fresh means no generator is running, so there is nothing to wait for.
PAUSE_DIR = RUN / "traffic-pause"
TRAFFIC_STATE = RUN / "traffic-state.json"
STATE_FRESH = 3      # seconds: an older state file means the generator is not running
PAUSE_WAIT = 45      # seconds: longer than any one routine action can take (traffic.py: 10 s + 20 s)


def traffic_state():
    try:
        state = json.loads(TRAFFIC_STATE.read_text())
    except (FileNotFoundError, ValueError):
        return None
    return state if time.time() - state.get("ts", 0) < STATE_FRESH else None


@contextmanager
def quiet_traffic():
    """Pause routine traffic for the duration of the with-block."""
    PAUSE_DIR.mkdir(parents=True, exist_ok=True)
    flag = PAUSE_DIR / uuid.uuid4().hex
    flag.write_text(str(os.getpid()))
    try:
        deadline = time.time() + PAUSE_WAIT
        while True:
            state = traffic_state()
            if state is None or flag.name in state.get("paused_for", []):
                break
            if time.time() > deadline:
                raise RuntimeError("the routine traffic generator did not pause "
                                   f"within {PAUSE_WAIT}s (./lab traffic off, then try again)")
            time.sleep(0.1)
        yield
    finally:
        flag.unlink(missing_ok=True)
