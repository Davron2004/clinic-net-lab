#!/usr/bin/env python3
"""Scenario: ransomware on the imaging workstation tries to reach everything.

Imaging workstations often run old, unpatched Windows, so they are a classic
way in. This scenario plays patient zero: from the imaging workstation it
tries every path an attacker would (file shares, remote desktop, the EMR, the
image archive's admin API, the printer, a command-and-control server on the
internet, DNS). If it reaches the records file share, it encrypts the
records, exactly like the real thing would.

    ./lab attack              # run it, paced for watching on the clinic map
    ./lab attack --fast       # no pauses (tests, CI)

Every attempt is streamed to run/events.jsonl for the clinic map. Before and
after, the EMR's records are fingerprinted to show whether any changed.
"""
import argparse
import json
import sys
import threading
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from labkit import lab  # noqa: E402

PATIENT_ZERO = "imaging"

# What the malware tries, in order. (target, port, what it would get there)
ATTEMPTS = [
    ("emr",          445,  "Patient records file share (SMB)"),
    ("emr",          443,  "EMR web app"),
    ("emr",          22,   "EMR server admin shell (SSH)"),
    ("pacs",         8042, "Image archive admin API (could delete studies)"),
    ("reception-pc", 445,  "Reception PC file sharing (SMB)"),
    ("reception-pc", 3389, "Reception PC remote desktop"),
    ("doctor-pc",    445,  "Doctor's PC file sharing (SMB)"),
    ("doctor-pc",    3389, "Doctor's PC remote desktop"),
    ("lab-analyzer", 22,   "Lab analyzer admin shell"),
    ("printer",      9100, "Printer (JetDirect)"),
    ("internet",     443,  "Command-and-control server on the internet"),
    ("gateway",      53,   "DNS (a covert channel out)"),
    ("pacs",         4242, "Image archive DICOM port (its one allowed job)"),
]


def integrity(policy):
    code, out = lab.sh(lab.container(policy, "emr"), "clinic-integrity")
    return json.loads(out) if code == 0 else None


def attempt(policy, src, target, port, what, results):
    if target == "gateway":
        ip, kind = lab.gateway_of(src), "dns"
    else:
        ip, kind = lab.ip_of(policy, target), "tcp"
    code, _ = lab.sh(src, f"clinic-probe {kind} {ip} {port} 2", timeout=15)
    reached = code == 0
    # Policy view: the only thing this machine may do is DICOM to the archive.
    allowed = target == "pacs" and port == 4242
    results.append((target, port, what, reached, allowed))
    lab.emit({"type": "probe", "source": "attack", "from": PATIENT_ZERO, "to": target,
              "port": port, "probe": kind, "dst_ip": ip, "what": what,
              "expect": "allow" if allowed else "deny",
              "observed": "allow" if reached else "deny",
              "pass": reached == allowed})


def encrypt(policy, src):
    """Run the encryption step against the EMR's records share."""
    emr_ip = lab.ip_of(policy, "emr")
    p = __import__("subprocess").Popen(
        ["docker", "exec", src, "clinic-ransomware", emr_ip],
        stdout=__import__("subprocess").PIPE, text=True)
    count = 0
    for line in p.stdout:
        step = json.loads(line)
        if step["step"] == "encrypt":
            count += 1
            lab.emit({"type": "encrypt", "node": "emr", "file": step["file"], "count": count})
    p.wait()
    return count


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--fast", action="store_true", help="no pauses between attempts")
    args = ap.parse_args()
    pace = 0 if args.fast else 0.6

    policy = lab.load_policy()
    src = lab.container(policy, PATIENT_ZERO)
    net = lab.variant()

    before = integrity(policy)
    lab.emit({"type": "scenario-start", "name": "ransomware", "node": PATIENT_ZERO, "variant": net})
    lab.emit({"type": "integrity", "node": "emr", "phase": "before", **(before or {})})
    print(f"\n  Ransomware on the {policy['nodes'][PATIENT_ZERO]['label'].lower()} [{net} network]\n")
    time.sleep(pace * 2)

    results, threads = [], []
    for target, port, what in ATTEMPTS:
        t = threading.Thread(target=attempt, args=(policy, src, target, port, what, results))
        t.start()
        threads.append(t)
        time.sleep(pace)
    for t in threads:
        t.join()

    smb_open = any(t == "emr" and p == 445 and reached for t, p, _, reached, _ in results)
    encrypted = encrypt(policy, src) if smb_open else 0
    time.sleep(pace)
    after = integrity(policy)
    lab.emit({"type": "integrity", "node": "emr", "phase": "after", **(after or {})})

    blocked = [r for r in results if not r[3]]
    reached_bad = [r for r in results if r[3] and not r[4]]
    for target, port, what, reached, allowed in sorted(results, key=lambda r: ATTEMPTS.index(r[:3])):
        status = "REACHED" if reached else "blocked"
        if reached and allowed:
            status = "open (allowed)"
        print(f"  {status:<15} {target + ':' + str(port):<18} {what}")
    print()
    print(f"  Blocked {len(blocked)} of {len(results)} paths.", end=" ")
    if after:
        print(f"Patient records: {after['intact']} of {after['total']} intact"
              + (f", {encrypted} encrypted." if encrypted else "."))
    lab.emit({"type": "scenario-end", "name": "ransomware", "blocked": len(blocked),
              "attempts": len(results), "breaches": len(reached_bad), "encrypted": encrypted,
              "records": after})
    # Exit status says whether the network contained the attack.
    sys.exit(0 if not reached_bad and not encrypted else 1)


if __name__ == "__main__":
    main()
