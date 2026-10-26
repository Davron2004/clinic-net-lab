#!/usr/bin/env python3
"""Scenario: ransomware on the imaging workstation tries to spread.

Imaging workstations often run old, unpatched Windows, so they are a classic
way in. This scenario plays patient zero: from the imaging workstation it
tries 13 common attack paths (file shares, remote desktop, the EMR, the image
archive's admin API, the printer, a command-and-control server on the
internet, DNS). If it reaches the records file share, it encrypts the
records, exactly like the real thing would.

    ./lab attack              # run it, paced for watching on the clinic map
    ./lab attack --fast       # no pauses (tests, CI)

The attack counts as contained only if all of these hold: the EMR's records
were fingerprinted before and after and are all intact, no forbidden path
was reached, every attempt gave a real answer (reached or blocked), and the
one allowed path (DICOM to the archive) still worked.

Exit status: 0 contained, 1 breached (records changed or a forbidden path
was reached), 2 error (lab not running, a probe failed, integrity unknown,
or the allowed path did not work, so containment is not shown).

Every attempt is streamed to run/events.jsonl for the clinic map, and the
outcome is written to run/results/attack.json.
"""
import argparse
import json
import subprocess
import sys
import threading
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from labkit import lab  # noqa: E402

PATIENT_ZERO = "imaging"
CONTAINED, BREACHED, ERROR = 0, 1, 2
REACHED, BLOCKED = 0, 1    # clinic-probe's answers; anything else is an error

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
# Policy view: the only thing this machine may do is DICOM to the archive.
ALLOWED = ("pacs", 4242)


def integrity(policy):
    code, out = lab.sh(lab.container(policy, "emr"), "clinic-integrity")
    if code != 0:
        return None
    try:
        return json.loads(out)
    except ValueError:
        return None


def all_intact(rec):
    return bool(rec) and rec["intact"] == rec["total"] and not (rec["changed"] or rec["missing"] or rec["added"])


def attempt(policy, src, target, port, what, results):
    if target == "gateway":
        ip, kind = lab.gateway_of(src), "dns"
    else:
        ip, kind = lab.ip_of(policy, target), "tcp"
    if ip:
        code, out = lab.sh(src, f"clinic-probe {kind} {ip} {port} 2", timeout=15)
    else:
        code, out = None, "could not resolve the target's address"
    observed = {REACHED: "allow", BLOCKED: "deny"}.get(code, "error")
    allowed = (target, port) == ALLOWED
    results.append({"target": target, "port": port, "what": what, "observed": observed,
                    "allowed": allowed, "detail": out[-200:] if observed == "error" else ""})
    lab.emit({"type": "probe", "source": "attack", "from": PATIENT_ZERO, "to": target,
              "port": port, "probe": kind, "dst_ip": ip, "what": what,
              "expect": "allow" if allowed else "deny", "observed": observed,
              "pass": observed == ("allow" if allowed else "deny")})


def encrypt(policy, src):
    """Run the encryption step against the EMR's records share."""
    emr_ip = lab.ip_of(policy, "emr")
    p = subprocess.Popen(["docker", "exec", src, "clinic-ransomware", emr_ip],
                         stdout=subprocess.PIPE, text=True)
    count = 0
    for line in p.stdout:
        step = json.loads(line)
        if step["step"] == "encrypt":
            count += 1
            lab.emit({"type": "encrypt", "node": "emr", "file": step["file"], "count": count})
    p.wait()
    return count


def attack(policy, src, net, pace):
    before = integrity(policy)
    lab.emit({"type": "scenario-start", "name": "ransomware", "node": PATIENT_ZERO, "variant": net})
    lab.emit({"type": "integrity", "node": "emr", "phase": "before", **(before or {})})
    print(f"\n  Ransomware on the {policy['nodes'][PATIENT_ZERO]['label'].lower()} [{net} network]")
    print(f"  Trying {len(ATTEMPTS)} common attack paths.\n")
    time.sleep(pace * 2)

    results, threads = [], []
    for target, port, what in ATTEMPTS:
        t = threading.Thread(target=attempt, args=(policy, src, target, port, what, results))
        t.start()
        threads.append(t)
        time.sleep(pace)
    for t in threads:
        t.join()

    smb_open = any(r["target"] == "emr" and r["port"] == 445 and r["observed"] == "allow" for r in results)
    encrypted = encrypt(policy, src) if smb_open else 0
    time.sleep(pace)
    after = integrity(policy)
    lab.emit({"type": "integrity", "node": "emr", "phase": "after", **(after or {})})

    order = [(t, p) for t, p, _ in ATTEMPTS]
    results.sort(key=lambda r: order.index((r["target"], r["port"])))
    blocked = [r for r in results if r["observed"] == "deny"]
    reached_bad = [r for r in results if r["observed"] == "allow" and not r["allowed"]]
    errors = [r for r in results if r["observed"] == "error"]
    allowed_ok = any(r["allowed"] and r["observed"] == "allow" for r in results)

    for r in results:
        status = {"allow": "REACHED", "deny": "blocked", "error": "ERROR"}[r["observed"]]
        if r["observed"] == "allow" and r["allowed"]:
            status = "open (allowed)"
        print(f"  {status:<15} {r['target'] + ':' + str(r['port']):<18} {r['what']}")
        if r["detail"]:
            print(f"                  {r['detail']}")
    print()
    print(f"  Blocked {len(blocked)} of {len(results)} paths.", end=" ")
    if after:
        print(f"Patient records: {after['intact']} of {after['total']} intact"
              + (f", {encrypted} encrypted." if encrypted else "."))
    else:
        print("Patient records: integrity check unavailable.")

    # The verdict. Evidence of a breach wins over everything else.
    problems = []
    if reached_bad or encrypted or (after and not all_intact(after)):
        outcome = BREACHED
    else:
        if not (before and after):
            problems.append("the records' integrity could not be measured before and after")
        elif not all_intact(before):
            problems.append("the records were already changed before the attack (redeploy with ./lab up)")
        if errors:
            problems.append(f"{len(errors)} attempts gave no answer (probe errors)")
        if not allowed_ok:
            problems.append("the one allowed path (DICOM to the archive) did not work")
        outcome = ERROR if problems else CONTAINED
    label = {CONTAINED: "CONTAINED", BREACHED: "BREACHED", ERROR: "ERROR (containment not shown)"}[outcome]
    print(f"  Result: {label}" + (": " + "; ".join(problems) if problems else ""))

    lab.emit({"type": "scenario-end", "name": "ransomware", "blocked": len(blocked),
              "attempts": len(results), "breaches": len(reached_bad), "encrypted": encrypted,
              "errors": len(errors), "records": after})
    out_dir = lab.RUN / "results"
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "attack.json").write_text(json.dumps({
        "variant": net, "outcome": label.split()[0].lower(), "exit_code": outcome,
        "attempts": len(results), "blocked": len(blocked), "breaches": len(reached_bad),
        "errors": len(errors), "allowed_path_worked": allowed_ok, "encrypted": encrypted,
        "records_before": before, "records_after": after, "problems": problems, "results": results,
    }, indent=2))
    return outcome


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--fast", action="store_true", help="no pauses between attempts")
    args = ap.parse_args()

    policy = lab.load_policy()
    src = lab.container(policy, PATIENT_ZERO)
    ok, why = lab.alive(src)
    if not ok:
        print(f"error: the {PATIENT_ZERO} machine is not up ({why}). Is the lab running? ./lab up",
              file=sys.stderr)
        sys.exit(ERROR)
    try:
        with lab.quiet_traffic():
            outcome = attack(policy, src, lab.variant(), 0 if args.fast else 0.6)
    except RuntimeError as e:
        print(f"error: {e}", file=sys.stderr)
        sys.exit(ERROR)
    sys.exit(outcome)


if __name__ == "__main__":
    main()
