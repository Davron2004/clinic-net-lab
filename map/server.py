#!/usr/bin/env python3
"""The clinic map: a live picture of the lab network for a non-technical audience.

Serves one web page (map/static) and streams what happens in the lab to it
with Server-Sent Events. Everything it knows comes from files under run/
(CLINIC_RUN_DIR):

    variant               which network is deployed: "clinic" or "flat"
    logs/firewall.jsonl   one line per packet the firewall logged (ulogd JSON)
    events.jsonl          test, attack and patient-record events (labkit.lab.emit)
    alerts.jsonl          alerts from the security monitor, when one is running
    results/latest.json   the last isolation test run

policy/clinic.yml supplies zones, machines and addresses, so the map redraws
itself when machines or zones are added there.

It runs in the toolbox container (./lab map), which has the Docker CLI, so the
page's buttons can run the isolation tests and the ransomware scenario.

    python map/server.py [--port 8080]
"""
import argparse
import importlib.util
import ipaddress
import json
import os
import queue
import re
import subprocess
import sys
import threading
import time
from collections import deque
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from labkit import lab  # noqa: E402

STATIC = Path(__file__).resolve().parent / "static"
ROUTER = "router"

POLL_SECONDS = 0.1           # how often run/ files are checked for new lines
RETRANSMIT_SECONDS = 10      # TCP resends an unanswered SYN; same attempt, same source port
MATCH_SECONDS = 15           # a test result can arrive this long after its first packet
UNLOGGED_WAIT_SECONDS = 1.5  # how long a result waits for its firewall line before drawing on its own
STALE_RUN_SECONDS = 90       # a test or attack with no news for this long has died
ALERT_GRACE_SECONDS = 20     # alerts trail what caused them; this long after a run still belongs to it
HEARTBEAT_SECONDS = 15       # keeps idle browser connections open

# Programs the page's buttons may start. Nothing else can be run from the page.
JOBS = {
    "tests": [sys.executable, "-u", "tests/isolation.py"],
    "attack": [sys.executable, "-u", "scenarios/ransomware.py"],
}


def attack_paths():
    """How many paths the ransomware scenario tries, so the page can say so
    before the attempts come in. None if the scenario cannot be read."""
    try:
        spec = importlib.util.spec_from_file_location("ransomware_scenario", ROOT / "scenarios" / "ransomware.py")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)  # only definitions; main() runs from the command line
        return len(module.ATTEMPTS)
    except Exception as e:
        log(f"could not count the ransomware's attack paths: {e!r}")
        return None


def log(msg):
    print(f"[map {time.strftime('%H:%M:%S')}] {msg}", flush=True)


# ------------------------------------------------------------------ topology

class Topology:
    """Zones, machines and addresses of the deployed network, read from policy."""

    def __init__(self, policy, net):
        self.policy = policy
        self.net = net
        self.zones = {}
        for name, spec in (policy.get("zones") or {}).items():
            spec = spec or {}
            self.zones[name] = {
                "id": name,
                "label": spec.get("label") or name.replace("-", " ").title(),
                "vlan": spec.get("vlan"),
                "subnet": spec.get("subnet"),
                # A zone with a VLAN is a room inside the clinic; one without
                # (the internet, a home office) is outside the building.
                "inside": spec.get("vlan") is not None,
            }
        # Names that stand for another machine: the clinic's public address is
        # the router, and tests say "gateway" for the router on the local network.
        self.alias = {"gateway": ROUTER}
        self.nodes = {}
        for name, spec in (policy.get("nodes") or {}).items():
            spec = spec or {}
            if spec.get("container"):
                self.alias[name] = spec["container"]
                continue
            ip = (spec.get("ip") or {}).get(net)
            self.nodes[name] = {
                "id": name,
                "label": spec.get("label") or name,
                "zone": spec.get("zone"),
                "ip": None if ip in (None, "dhcp") else str(ip),
                "dhcp": ip == "dhcp",
                "icon": spec.get("icon"),
                # Reaches the clinic through the VPN (segmented clinic only).
                "vpn": bool(spec.get("tunnel_ip")) and net == "clinic",
            }
        self.flows = [
            {k: f.get(k) for k in ("id", "from", "to", "port", "expect", "what")}
            for f in policy.get("flows") or []
        ]
        # Policy flows by (from, to, port). Two flows can share that and
        # disagree (the home laptop reaching the EMR through the VPN is
        # allowed, without it is not); a firewall line cannot tell them
        # apart, so such a connection gets no expectation from policy.
        self.expect = {}
        for f in self.flows:
            key = (f["from"], self.resolve(f["to"]), f["port"])
            other = self.expect.get(key)
            self.expect[key] = f if key not in self.expect or (other and other["expect"] == f["expect"]) else None
        self.ips = {}
        self._dhcp_checked = 0.0
        self._index()

    def _index(self):
        try:
            self.ips = dict(lab.ip_index(self.policy, self.net))
        except Exception as e:  # the lab may not be running; the page still loads
            log(f"could not read machine addresses: {e}")
            self.ips = {}
        self._refresh_dhcp()

    def _refresh_dhcp(self):
        """Ask machines that get their address from DHCP what it is right now."""
        self._dhcp_checked = time.monotonic()
        for name, node in self.nodes.items():
            if not node["dhcp"]:
                continue
            code, out = lab.sh(lab.container(self.policy, name),
                               "ip -4 -o addr show dev eth1 | awk '{print $4}' | cut -d/ -f1", timeout=5)
            ip = out.splitlines()[0].strip() if code == 0 and out else None
            if ip:
                self.ips = {k: v for k, v in self.ips.items() if v != name}
                self.ips[ip] = name
                node["ip"] = ip

    def resolve(self, name):
        return self.alias.get(name, name)

    def expectation(self, a, b, port):
        """The policy flow for a connection, if policy has one."""
        flow = self.expect.get((a, b, port))
        if flow is None and self.forwarded(a, b):
            flow = self.expect.get((a, ROUTER, port))
        return flow or {}

    def forwarded(self, a, b):
        """From outside straight to a machine inside: the only way is a port
        forward on the clinic's public address, so policy describes it as a
        connection to the router (clinic-wan)."""
        return self.outside(a) and b != ROUTER and not self.outside(b)

    def same_connection(self, probe_key, line_key):
        """Does a test result describe the connection the firewall logged?"""
        if probe_key == line_key:
            return True
        (pa, pb, pport), (la, lb, lport) = probe_key, line_key
        # A test aimed at the public address; the firewall logged the inside
        # machine it was forwarded to.
        return pa == la and pport == lport and pb == ROUTER and self.forwarded(la, lb)

    def zone_of(self, node):
        if node and node.startswith("@"):
            return node[1:]
        if node == ROUTER:
            return None
        return (self.nodes.get(node) or {}).get("zone")

    def outside(self, node):
        zone = self.zones.get(self.zone_of(node))
        return bool(zone) and not zone["inside"]

    def endpoint(self, ip):
        """Which machine an address belongs to. "@zone" means an unknown machine
        in that zone; anything outside the clinic is drawn as the internet."""
        if ip in self.ips:
            return self.ips[ip]
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return None
        if addr in ipaddress.ip_network("10.0.0.0/8"):
            # Probably a new DHCP lease. Re-check at most every few seconds.
            if time.monotonic() - self._dhcp_checked > 5:
                self._refresh_dhcp()
                if ip in self.ips:
                    return self.ips[ip]
            for zone in self.zones.values():
                if zone["subnet"] and addr in ipaddress.ip_network(zone["subnet"], strict=False):
                    # A zone with one machine (say, a VPN subnet for the home
                    # laptop) can only mean that machine.
                    members = [n for n, spec in self.nodes.items() if spec["zone"] == zone["id"]]
                    return members[0] if len(members) == 1 else "@" + zone["id"]
            return None
        # Every other address is somewhere on the internet (including the
        # internet machine's own uplink addresses).
        return "internet" if "internet" in self.nodes else None

    def route(self, a, b):
        """How a connection travels: through the router, through one zone's
        switch only, directly across the flat network, or outside the clinic."""
        out_a, out_b = self.outside(a), self.outside(b)
        if out_a and out_b:
            return "outside"
        if ROUTER in (a, b) or out_a or out_b:
            return "router"
        if self.net == "flat":
            return "direct"
        return "switch" if self.zone_of(a) == self.zone_of(b) else "router"

    def to_json(self):
        return {
            "variant": self.net,
            "zones": list(self.zones.values()),
            "nodes": list(self.nodes.values()),
            "flows": self.flows,
        }


def classify(observed, expect):
    """allowed / blocked, or what went wrong compared with policy."""
    if expect == "deny" and observed == "allow":
        return "violation"
    if expect == "allow" and observed == "deny":
        return "broken"
    return "allowed" if observed == "allow" else "blocked"


# ------------------------------------------------------------------ files

class Follower:
    """Reads lines as they are appended to a file, like `tail -F`.

    Copes with the file not existing yet, and with it being emptied or
    replaced (./lab up starts every deployment with an empty run/)."""

    def __init__(self, path, from_end=False):
        self.path = Path(path)
        self.from_end = from_end
        self.f = None
        self.ino = None
        self.pos = 0
        self.partial = b""

    def _close(self):
        if self.f:
            self.f.close()
        self.f, self.ino, self.pos, self.partial = None, None, 0, b""

    def lines(self):
        try:
            st = self.path.stat()
        except FileNotFoundError:
            self._close()
            self.from_end = False  # when it comes back, it is a new file: read all of it
            return []
        if self.f is None or st.st_ino != self.ino or st.st_size < self.pos:
            self._close()
            self.f = open(self.path, "rb")
            self.ino = st.st_ino
            if self.from_end:
                self.pos = self.f.seek(0, os.SEEK_END)
            self.from_end = False
        if st.st_size == self.pos:
            return []
        data = self.partial + self.f.read()
        self.pos = self.f.tell()
        *complete, self.partial = data.split(b"\n")
        out = []
        for raw in complete:
            raw = raw.strip()
            if not raw:
                continue
            try:
                out.append(json.loads(raw))
            except ValueError:
                continue
        return out


# ------------------------------------------------------------------ live state

class Engine:
    """Turns raw lab output into the events the page draws, and remembers
    enough state that a page opened mid-demo shows the right picture."""

    def __init__(self, run_dir):
        self.run = Path(run_dir)
        self.lock = threading.RLock()
        self.clients = set()
        self.seq = 0
        self.variant = None
        self.monitoring = None
        self.policy_mtime = None
        self.topo = None
        self.job = None
        self.last_job = None
        self.firewall = Follower(self.run / "logs" / "firewall.jsonl", from_end=True)
        self.events = Follower(self.run / "events.jsonl")
        self.alerts_file = Follower(self.run / "alerts.jsonl")
        self.attack_paths = attack_paths()
        self._reset()

    # -- lifecycle

    def _reset(self):
        self.tests = {"running": False, "total": 0, "results": {}, "summary": None, "ts": None}
        self.scenario = {"running": False, "node": None, "attempts": 0, "breaches": 0,
                         "planned": self.attack_paths, "result": None, "ts": None}
        self.records = None
        self.alerts = deque(maxlen=200)
        self.windows = deque(maxlen=20)  # when tests and attacks ran, to explain alerts
        self.activity = deque(maxlen=8)
        self.counters = {"allowed": 0, "blocked": 0, "violations": 0}
        self.seen = {}        # retransmit dedupe: 5-tuple -> last time seen
        self.recent = deque()  # firewall flows waiting to be matched with a test result
        self.pending = []     # test results waiting for their firewall line

    def load(self):
        """Read everything already on disk without animating it."""
        with self.lock:
            self._check_variant(force=True, quiet=True)
            for ev in self.events.lines():
                self._on_event(ev, quiet=True)
            for al in self.alerts_file.lines():
                self._on_alert(al, quiet=True)
            if self.tests["summary"] is None:
                self._load_latest_results()
            self.pending.clear()
        self._check_records_async()

    def _check_variant(self, force=False, quiet=False):
        net = lab.variant()
        policy_file = ROOT / "policy" / "clinic.yml"
        try:
            mtime = policy_file.stat().st_mtime
        except FileNotFoundError:
            mtime = None
        try:
            self.monitoring = (self.run / "monitoring").read_text().strip() or None
        except OSError:
            self.monitoring = None
        if not force and net == self.variant and mtime == self.policy_mtime:
            return
        changed_net = net != self.variant
        self.variant, self.policy_mtime = net, mtime
        self.topo = Topology(lab.load_policy(), net)
        if changed_net and not force:
            # A new deployment: nothing from the old one applies.
            self._reset()
            self._check_records_async()
        log(f"network: {net}, {len(self.topo.nodes)} machines, {len(self.topo.zones)} zones")
        if not quiet:
            self._broadcast_state()

    def _load_latest_results(self):
        try:
            data = json.loads((self.run / "results" / "latest.json").read_text())
        except (FileNotFoundError, ValueError):
            return
        summary = data.get("summary") or {}
        if summary.get("variant") not in (None, self.variant):
            return
        self.tests["summary"] = summary
        self.tests["total"] = summary.get("total", 0)
        for r in data.get("results", []):
            if r.get("id"):
                self.tests["results"][r["id"]] = {"pass": r.get("pass"), "observed": r.get("observed")}

    def _check_records_async(self):
        """Fingerprint the EMR's records now, so the page shows them before any attack."""
        if not self.topo or "emr" not in self.topo.nodes:
            return

        def check():
            code, out = lab.sh(lab.container(self.topo.policy, "emr"), "clinic-integrity", timeout=15)
            try:
                result = json.loads(out) if code == 0 else None
            except ValueError:
                result = None
            if not result:
                return
            with self.lock:
                if self.records is None:
                    self.records = dict(result, node="emr", encrypted=0, phase="live", ts=time.time())
                    self._publish({"kind": "records", "records": self.records})

        threading.Thread(target=check, daemon=True).start()

    # -- publishing

    def subscribe(self):
        q = queue.Queue(maxsize=5000)
        with self.lock:
            self.clients.add(q)
            return q, self.snapshot()

    def unsubscribe(self, q):
        with self.lock:
            self.clients.discard(q)

    def _publish(self, msg):
        data = json.dumps(msg, separators=(",", ":"))
        for q in list(self.clients):
            try:
                q.put_nowait(data)
            except queue.Full:  # a tab that stopped reading; it reconnects and gets a fresh state
                self.clients.discard(q)

    def snapshot(self):
        with self.lock:
            return {
                "kind": "state",
                "lab": lab.LAB,
                "topology": self.topo.to_json() if self.topo else None,
                "tests": self.tests,
                "scenario": self.scenario,
                "records": self.records,
                "alerts": list(self.alerts),
                "activity": list(self.activity),
                "counters": self.counters,
                "monitoring": self.monitoring,
                "job": self.job,
                "last_job": self.last_job,
                "now": time.time(),
            }

    def _broadcast_state(self):
        self._publish(self.snapshot())

    # -- the main loop

    def pump(self):
        last_policy_check = 0.0
        while True:
            try:
                with self.lock:
                    now = time.monotonic()
                    if now - last_policy_check > 1:
                        self._check_variant()
                        last_policy_check = now
                    # Firewall lines first: a connection is logged when it
                    # starts, before the test that made it reports back.
                    for line in self.firewall.lines():
                        self._on_firewall(line)
                    for ev in self.events.lines():
                        self._on_event(ev)
                    for al in self.alerts_file.lines():
                        self._on_alert(al)
                    self._tick()
            except Exception as e:  # never let one bad line stop the map
                log(f"error: {e!r}")
            time.sleep(POLL_SECONDS)

    def _tick(self):
        now = time.time()
        for p in [p for p in self.pending if p["deadline"] <= now]:
            self.pending.remove(p)
            self._flow_from_probe(p["event"])
        while self.recent and now - self.recent[0]["at"] > MATCH_SECONDS:
            self.recent.popleft()
        if len(self.seen) > 5000:
            self.seen = {k: t for k, t in self.seen.items() if now - t < RETRANSMIT_SECONDS}
        # A run started from the command line that crashed never reports its end.
        for name, state in (("tests", self.tests), ("scenario", self.scenario)):
            if state["running"] and not self.job and now - (state["ts"] or now) > STALE_RUN_SECONDS:
                state["running"] = False
                self._publish({"kind": name, name: state})

    # -- firewall log

    def _on_firewall(self, d):
        verdict, _, rule = (d.get("oob.prefix") or "").partition(":")
        if verdict not in ("allow", "deny"):
            return
        src, dst = d.get("src_ip"), d.get("dest_ip")
        port = d.get("dest_port")
        proto = {1: "icmp", 6: "tcp", 17: "udp"}.get(d.get("ip.protocol"), "ip")
        ts = d.get("oob.time.sec", time.time()) + d.get("oob.time.usec", 0) / 1e6
        # One connection attempt can be logged several times: TCP resends an
        # unanswered SYN after 1s, 2s, ... from the same source port.
        key = (src, d.get("src_port"), dst, port, proto)
        now = time.time()
        last = self.seen.get(key)
        self.seen[key] = now
        if last is not None and now - last < RETRANSMIT_SECONDS:
            return
        a, b = self.topo.endpoint(src), self.topo.endpoint(dst)
        if not a or not b:
            return
        match = (a, b, port)
        for p in self.pending:
            if self.topo.same_connection(p["key"], match):
                self.pending.remove(p)
                # Drawn where the packet really went (a port forward's target).
                self._flow_from_probe(p["event"], observed=verdict, rule=rule, ts=ts, to=b)
                return
        policy = self.topo.expectation(a, b, port)
        fid = self._flow(a, b, port, proto, verdict, policy.get("expect"), "firewall",
                         what=policy.get("what"), test=policy.get("id"), rule=rule, ts=ts)
        self.recent.append({"key": match, "at": now, "fid": fid})

    # -- events.jsonl

    def _on_event(self, ev, quiet=False):
        kind = ev.get("type")
        ts = ev.get("ts") or time.time()
        if kind in ("test-start", "scenario-start"):
            self.windows.append({"kind": "test" if kind == "test-start" else "attack", "start": ts, "end": None})
        elif kind in ("test-end", "scenario-end"):
            for w in reversed(self.windows):
                if w["kind"] == ("test" if kind == "test-end" else "attack") and w["end"] is None:
                    w["end"] = ts
                    break
        if kind == "test-start":
            self.tests = {"running": True, "total": ev.get("total", 0), "results": {},
                          "summary": self.tests["summary"], "ts": ts}
            if not quiet:
                self._publish({"kind": "tests", "tests": self.tests})
        elif kind == "test-end":
            self.tests.update(running=False, summary={k: v for k, v in ev.items() if k != "type"}, ts=ts)
            if not quiet:
                self._publish({"kind": "tests", "tests": self.tests, "finished": True})
        elif kind == "probe":
            self._on_probe(ev, quiet)
        elif kind == "scenario-start":
            self.scenario = {"running": True, "name": ev.get("name"), "node": ev.get("node"),
                             "attempts": 0, "breaches": 0, "planned": self.attack_paths, "result": None, "ts": ts}
            if not quiet:
                self._publish({"kind": "scenario", "scenario": self.scenario})
        elif kind == "scenario-end":
            self.scenario.update(running=False, result={k: v for k, v in ev.items() if k != "type"}, ts=ts)
            if ev.get("records"):
                self._set_records(dict(ev["records"], node="emr", encrypted=ev.get("encrypted", 0),
                                       phase="after", ts=ts), quiet)
            if not quiet:
                self._publish({"kind": "scenario", "scenario": self.scenario, "finished": True})
        elif kind == "integrity":
            fields = {k: ev.get(k) for k in ("node", "phase", "total", "intact", "changed", "missing", "added")}
            encrypted = (self.records or {}).get("encrypted", 0) if ev.get("phase") == "after" else 0
            self._set_records(dict(fields, encrypted=encrypted, ts=ts), quiet)
        elif kind == "encrypt":
            rec = dict(self.records or {"node": ev.get("node"), "total": 0})
            count = ev.get("count", 0)
            total = rec.get("total") or count
            rec.update(encrypted=count, intact=max(0, total - count), phase="encrypting", ts=ts)
            self._set_records(rec, quiet)
            if not quiet:
                src = self.scenario.get("node") or "imaging"
                dst = self.topo.resolve(ev.get("node") or "emr")
                self._flow(src, dst, 445, "tcp", "allow", "deny", "attack", ts=ts, stream=True,
                           what=f"Encrypting patient record {count} of {total}", count_it=False)

    def _set_records(self, rec, quiet):
        self.records = rec
        if not quiet:
            self._publish({"kind": "records", "records": rec})

    def _on_probe(self, ev, quiet):
        source = ev.get("source")
        ts = ev.get("ts") or time.time()
        if source == "test" and ev.get("id"):
            self.tests["results"][ev["id"]] = {"pass": ev.get("pass"), "observed": ev.get("observed")}
            self.tests["ts"] = ts
            if not quiet:
                self._publish({"kind": "result", "id": ev["id"], "pass": ev.get("pass"),
                               "observed": ev.get("observed"), "expect": ev.get("expect")})
        elif source == "attack":
            self.scenario["attempts"] += 1
            self.scenario["ts"] = ts
            if ev.get("observed") == "allow" and ev.get("expect") == "deny":
                self.scenario["breaches"] += 1
            if not quiet:
                self._publish({"kind": "scenario", "scenario": self.scenario})
        # A probe that could not run (observed "error") says nothing about
        # the network, so there is no connection to draw.
        if quiet or ev.get("observed") == "error":
            return
        a, b = ev.get("from"), self.topo.resolve(ev.get("to"))
        key = (a, b, ev.get("port"))
        now = time.time()
        for r in self.recent:
            if self.topo.same_connection(key, r["key"]):
                # Already drawn from the firewall log when the packet left.
                self.recent.remove(r)
                return
        if self.topo.route(a, b) == "router":
            # Its firewall line may still be on its way; draw once, not twice.
            self.pending.append({"key": key, "deadline": now + UNLOGGED_WAIT_SECONDS, "event": ev})
        else:
            self._flow_from_probe(ev)

    def _flow_from_probe(self, ev, observed=None, rule=None, ts=None, to=None):
        self._flow(ev.get("from"), to or self.topo.resolve(ev.get("to")), ev.get("port"),
                   "udp" if ev.get("probe") == "dns" else "tcp",
                   observed or ev.get("observed"), ev.get("expect"), ev.get("source") or "test",
                   what=ev.get("what"), test=ev.get("id"), rule=rule, ts=ts or ev.get("ts"))

    def _flow(self, a, b, port, proto, observed, expect, source, what=None, test=None,
              rule=None, ts=None, stream=False, count_it=True):
        if a not in self.topo.nodes and a != ROUTER and not str(a).startswith("@"):
            return None
        if b not in self.topo.nodes and b != ROUTER and not str(b).startswith("@"):
            return None
        route = self.topo.route(a, b)
        result = classify(observed, expect)
        by = None
        if observed == "deny":
            by = {"router": "firewall" if self.variant == "clinic" else "router",
                  "switch": "switch"}.get(route, "no-answer")
        if count_it:
            if result == "violation":
                self.counters["violations"] += 1
            elif route == "router" and result in ("allowed", "blocked", "broken"):
                self.counters["allowed" if observed == "allow" else "blocked"] += 1
        self.seq += 1
        msg = {"kind": "flow", "id": self.seq, "from": a, "to": b, "port": port, "proto": proto,
               "result": result, "route": route, "by": by, "source": source, "test": test,
               "what": what, "rule": rule, "stream": stream, "ts": ts or time.time(),
               "counters": dict(self.counters)}
        self.activity.append(msg)
        self._publish(msg)
        return self.seq

    # -- alerts.jsonl

    def _on_alert(self, al, quiet=False):
        if not isinstance(al, dict) or not al.get("title"):
            return
        alert = {k: al.get(k) for k in ("ts", "level", "rule_id", "title", "node", "src_ip",
                                        "dst_ip", "dst_port", "category", "source")}
        alert["ts"] = alert["ts"] or time.time()
        alert["title"] = self._name_addresses(alert)
        # Point the map at the machines involved, by name.
        alert["src"] = self.topo.endpoint(al["src_ip"]) if al.get("src_ip") else None
        alert["dst"] = self.topo.endpoint(al["dst_ip"]) if al.get("dst_ip") else None
        # The test suite does forbidden things on purpose, so the alerts it
        # sets off are expected; the page shows them quietly.
        alert["during"] = self._window_at(alert["ts"])
        self.alerts.append(alert)
        if not quiet:
            self._publish({"kind": "alert", "alert": alert})

    def _name_addresses(self, alert):
        """Say "Guest laptop" where the monitor could only say "Guest Wi-Fi
        device 10.10.50.110" (it does not know DHCP leases; the map does),
        and name files without their folders."""
        title = alert["title"]
        for ip in {alert.get("src_ip"), alert.get("dst_ip")} - {None}:
            node = self.topo.endpoint(ip)
            if node not in self.topo.nodes:
                continue
            label = self.topo.nodes[node]["label"]
            for zone in self.topo.zones.values():
                title = title.replace(f"{zone['label']} device {ip}", label)
            title = re.sub(rf"(?<![\d.]){re.escape(ip)}(?![\d.])", label, title)
        # "/srv/emr/records/patient-0009.json" -> "patient-0009.json"
        return re.sub(r"(?<![\w.])(?:/[\w.-]+)+/([\w.-]+)", r"\1", title)

    def _window_at(self, ts):
        for w in reversed(self.windows):
            end = w["end"] if w["end"] is not None else time.time()
            if w["start"] - 1 <= ts <= end + ALERT_GRACE_SECONDS:
                return w["kind"]
        return None

    # -- buttons

    def busy(self):
        return self.job or self.tests["running"] or self.scenario["running"]

    def start_job(self, name):
        with self.lock:
            if self.busy():
                return False
            log(f"starting {name}: {' '.join(JOBS[name][1:])}")
            proc = subprocess.Popen(JOBS[name], cwd=ROOT, stdout=subprocess.PIPE,
                                    stderr=subprocess.STDOUT, text=True)
            self.job = {"name": name, "started": time.time()}
            self._publish({"kind": "job", "job": self.job})
        threading.Thread(target=self._wait_job, args=(name, proc), daemon=True).start()
        return True

    def _wait_job(self, name, proc):
        tail = deque(maxlen=6)
        for line in proc.stdout:
            line = line.rstrip()
            if line:
                tail.append(line)
                print(f"[{name}] {line}", flush=True)
        code = proc.wait()
        # Exit 1 means "the network failed the check", which is a result, not a crash.
        ok = code in (0, 1)
        log(f"{name} finished with exit code {code}")
        with self.lock:
            self.job = None
            self.last_job = {"name": name, "code": code, "ok": ok,
                             "tail": [] if ok else list(tail), "ts": time.time()}
            self._publish({"kind": "job", "job": None, "last_job": self.last_job})


# ------------------------------------------------------------------ HTTP

CONTENT_TYPES = {
    ".html": "text/html; charset=utf-8",
    ".css": "text/css; charset=utf-8",
    ".js": "text/javascript; charset=utf-8",
    ".svg": "image/svg+xml",
    ".png": "image/png",
    ".ico": "image/x-icon",
    ".woff2": "font/woff2",
    ".json": "application/json",
}


# The page's buttons start programs in a container that can drive Docker, so
# only this page may press them. Any other web page open in the same browser
# could otherwise send a POST to localhost (cross-site request forgery), and a
# hostile DNS name pointed at 127.0.0.1 could load the map as its own page (DNS
# rebinding). Three checks close both:
#   - Host must be this map's own address (localhost or 127.0.0.1 on MAP_PORT);
#   - a POST must carry an Origin of that same address;
#   - a POST must carry RUN_HEADER. A plain HTML form cannot add headers, and a
#     script on another site that adds one needs a CORS preflight, which this
#     server never approves.
RUN_HEADER = "X-Clinic-Map"


def allowed_hosts(port):
    return {f"{name}:{port}" for name in ("localhost", "127.0.0.1", "[::1]")}


class Handler(BaseHTTPRequestHandler):
    server_version = "ClinicMap/1.0"
    engine = None  # set in main()
    hosts = allowed_hosts(8080)  # set in main(), from the published port

    def log_message(self, fmt, *args):
        pass  # requests are not interesting; jobs and errors are logged instead

    def _send(self, status, body, content_type="application/json"):
        if isinstance(body, (dict, list)):
            body = json.dumps(body).encode()
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _host_ok(self):
        return (self.headers.get("Host") or "").lower() in self.hosts

    def _forbidden(self):
        return self._send(HTTPStatus.FORBIDDEN, {"error": "forbidden"})

    def do_GET(self):
        path = self.path.split("?", 1)[0]
        if path == "/healthz":
            return self._send(HTTPStatus.OK, b"ok\n", "text/plain")
        if not self._host_ok():
            return self._forbidden()
        if path == "/api/events":
            return self._events()
        if path == "/api/state":
            return self._send(HTTPStatus.OK, self.engine.snapshot())
        return self._static(path)

    def do_POST(self):
        path = self.path.split("?", 1)[0]
        origin = (self.headers.get("Origin") or "").lower().removeprefix("http://")
        if not self._host_ok() or origin not in self.hosts or self.headers.get(RUN_HEADER) != "run":
            log(f"refused POST {path}: host={self.headers.get('Host')!r} origin={self.headers.get('Origin')!r}")
            return self._forbidden()
        name = path.removeprefix("/api/run/")
        if not path.startswith("/api/run/") or name not in JOBS:
            return self._send(HTTPStatus.NOT_FOUND, {"error": "not found"})
        if not self.engine.start_job(name):
            return self._send(HTTPStatus.CONFLICT, {"error": "something is already running"})
        return self._send(HTTPStatus.ACCEPTED, {"started": name})

    def _static(self, path):
        rel = "index.html" if path in ("", "/") else path.lstrip("/")
        target = (STATIC / rel).resolve()
        if not target.is_relative_to(STATIC.resolve()) or not target.is_file():
            return self._send(HTTPStatus.NOT_FOUND, b"not found\n", "text/plain")
        ctype = CONTENT_TYPES.get(target.suffix, "application/octet-stream")
        self._send(HTTPStatus.OK, target.read_bytes(), ctype)

    def _events(self):
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        q, snapshot = self.engine.subscribe()
        try:
            self.wfile.write(b"retry: 1500\n\n")
            self.wfile.write(f"data: {json.dumps(snapshot)}\n\n".encode())
            self.wfile.flush()
            while q in self.engine.clients:
                try:
                    data = q.get(timeout=HEARTBEAT_SECONDS)
                    chunk = f"data: {data}\n\n"
                except queue.Empty:
                    chunk = ": still here\n\n"
                self.wfile.write(chunk.encode())
                self.wfile.flush()
        except (BrokenPipeError, ConnectionResetError, TimeoutError):
            pass
        finally:
            self.engine.unsubscribe(q)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--port", type=int, default=8080)
    ap.add_argument("--host", default="0.0.0.0")
    args = ap.parse_args()

    # Listen first: a browser opened the moment ./lab up prints the address
    # waits in the queue while the lab's state is read, instead of being refused.
    server = ThreadingHTTPServer((args.host, args.port), Handler)
    server.daemon_threads = True
    # In the container the server listens on 8080 and Docker publishes it on
    # MAP_PORT; the browser's Host and Origin carry the published port.
    public = os.environ.get("MAP_PORT", args.port)
    Handler.hosts = allowed_hosts(public)
    engine = Engine(lab.RUN)
    engine.load()
    Handler.engine = engine
    threading.Thread(target=engine.pump, daemon=True).start()
    log(f"clinic map for lab '{lab.LAB}' on http://localhost:{public}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
