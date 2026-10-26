#!/usr/bin/env python3
"""Routine clinic traffic: what a normal working day looks like on the network.

Every few seconds (with random jitter) one ordinary, allowed action happens
on a real machine: the front desk opens a chart, a doctor looks at an X-ray,
the imaging workstation sends a new study to the archive, the lab analyzer
sends a result to the EMR, someone prints, a guest browses. The firewall
logs each new connection like any other, so the clinic map looks alive.

It stays out of the way of measurements: while the isolation suite or an
attack scenario is running (seen in run/events.jsonl) it pauses, so their
results and the map's replay of them contain only their own traffic.

Started by ./lab up in its own container; set CLINIC_TRAFFIC=0 to turn it
off (CI does), or use ./lab traffic off / on.
"""
import json
import random
import shlex
import sys
import threading
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from labkit import lab  # noqa: E402

MIN_GAP, MAX_GAP = 2.5, 7.0   # seconds between actions
STALE_RUN = 300               # a test/attack with no end event after this long is assumed dead

# (weight, from, to, port, probe kind for the event, what, command run on the source machine)
# {ip} is the target's address. Commands must exit 0 when the action worked.
COMMON = [
    (3, "reception-pc", "emr", 443, "https", "Front desk opens a patient chart",
     "curl -skf -o /dev/null --max-time 5 https://{ip}/"),
    (3, "doctor-pc", "emr", 443, "https", "Doctor reviews a chart and lab results",
     "curl -skf -o /dev/null --max-time 5 https://{ip}/"),
    (3, "doctor-pc", "pacs", 8042, "pacs-web", "Doctor views a patient's images",
     'curl -sf -o /dev/null --max-time 5 -u "$PACS_AUTH" "http://{ip}:8042/studies?expand"'),
    (2, "imaging", "pacs", 4242, "dicom", "Imaging workstation sends a new study to the archive",
     "clinic-dicom send {ip} 4242"),
    (2, "lab-analyzer", "emr", 2575, "hl7", "Lab analyzer sends a result to the EMR",
     "clinic-hl7 send {ip} 2575 5"),
    (2, "reception-pc", "printer", 9100, "tcp", "Front desk prints a visit summary",
     "printf '\\033%%-12345X@PJL JOB NAME=\"visit-summary\"\\r\\n' | nc -w 2 {ip} 9100 >/dev/null"),
    (1, "doctor-pc", "internet", 443, "https", "Doctor looks something up on the web",
     "curl -skf -o /dev/null --max-time 5 https://{ip}/"),
    (2, "guest-laptop", "internet", 443, "https", "A patient in the waiting room browses the web",
     "curl -skf -o /dev/null --max-time 5 https://{ip}/"),
    (1, "guest-phone", "internet", 443, "https", "A visitor's phone checks the news",
     "curl -skf -o /dev/null --max-time 5 https://{ip}/"),
]
# Remote access differs: a VPN to the EMR in the segmented clinic, a remote
# desktop port forward to the reception PC in the flat one.
REMOTE = {
    "clinic": (2, "home-doctor", "emr", 443, "https", "Doctor at home opens a chart over the VPN",
               "curl -skf -o /dev/null --max-time 5 https://{ip}/"),
    "flat": (1, "home-doctor", "reception-pc", 3389, "tcp",
             "Doctor at home logs in to the reception PC (remote desktop port forward)",
             "nc -z -w 3 198.51.100.2 3389"),
}


class Pauser:
    """Follows run/events.jsonl and reports whether a test or attack is running."""

    def __init__(self):
        self.path = lab.RUN / "events.jsonl"
        self.offset = 0
        self.running_since = None

    def busy(self):
        try:
            size = self.path.stat().st_size
            if size < self.offset:   # file was emptied (fresh lab): start over
                self.offset = 0
            with open(self.path) as f:
                f.seek(self.offset)
                data = f.read()
        except FileNotFoundError:
            return False
        # Only consume complete lines; a half-written line is read next time.
        complete = data[:data.rfind("\n") + 1]
        self.offset += len(complete.encode())
        for line in complete.splitlines():
            try:
                kind = json.loads(line).get("type")
            except ValueError:
                continue
            if kind in ("test-start", "scenario-start"):
                self.running_since = time.time()
            elif kind in ("test-end", "scenario-end"):
                self.running_since = None
        if self.running_since and time.time() - self.running_since > STALE_RUN:
            self.running_since = None
        return self.running_since is not None


def pacs_credentials(policy):
    code, out = lab.sh(lab.container(policy, "pacs"), "cat /run/clinic/pacs-credentials")
    return out.strip() if code == 0 else ""


def run_action(policy, action):
    _, src, dst, port, kind, what, cmd = action
    dst_ip = lab.ip_of(policy, dst)
    if not dst_ip:
        return
    shell = cmd.format(ip=dst_ip)
    if "$PACS_AUTH" in cmd:
        # The doctor knows the archive's password: read this boot's one.
        shell = f"PACS_AUTH={shlex.quote(pacs_credentials(policy))}; {shell}"
    code, _ = lab.sh(lab.container(policy, src), shell, timeout=20)
    ok = code == 0
    lab.emit({"type": "probe", "source": "traffic", "from": src, "to": dst, "port": port,
              "probe": kind, "dst_ip": dst_ip, "expect": "allow",
              "observed": "allow" if ok else "deny", "pass": ok, "what": what})


def main():
    policy = lab.load_policy()
    net = lab.variant()
    actions = COMMON + [REMOTE[net]] if net in REMOTE else COMMON
    weights = [a[0] for a in actions]
    pauser = Pauser()
    print(f"clinic traffic: {len(actions)} kinds of routine actions on the {net} network", flush=True)
    while True:
        time.sleep(random.uniform(MIN_GAP, MAX_GAP))
        if pauser.busy():
            continue
        action = random.choices(actions, weights)[0]
        # Run in the background so a slow action never stalls the rhythm.
        threading.Thread(target=run_action, args=(policy, action), daemon=True).start()


if __name__ == "__main__":
    main()
