#!/usr/bin/env python3
"""Isolation test suite: proves the clinic network only allows what policy allows.

For every flow in policy/clinic.yml it really sends traffic from the source
machine to the target and records whether it got through. A flow passes when
what happened matches what policy expects.

    ./lab test                      # run the matrix against the running lab
    ./lab test --only D01,D02       # run a few flows
    ./lab test --expect-violations  # for the flat "before" network: succeed
                                    # only if the suite catches violations

Writes run/results/latest.json and run/results/report.md, and streams each
result to run/events.jsonl for the clinic map.
"""
import argparse
import datetime
import hashlib
import json
import sys
from concurrent.futures import ThreadPoolExecutor

sys.path.insert(0, str(__import__("pathlib").Path(__file__).resolve().parent.parent))
from labkit import lab  # noqa: E402

TIMEOUT = 3        # seconds to wait for an answer
WORKERS = 12       # probes in flight at once


def resolve_target(policy, flow):
    if flow["to"] == "gateway":
        return lab.gateway_of(lab.container(policy, flow["from"]))
    return lab.ip_of(policy, flow["to"])


def probe(policy, flow):
    kind = flow.get("probe", "tcp")
    src = lab.container(policy, flow["from"])
    dst_ip = resolve_target(policy, flow)
    if not dst_ip:
        return dict(flow, observed="error", detail="could not resolve target address")
    cmd = f"clinic-probe {kind} {dst_ip} {flow['port']} {TIMEOUT}"
    code, out = lab.sh(src, cmd, timeout=TIMEOUT + 10)
    # A packet can be slow on its very first trip (address resolution, a cold
    # service). Allowed flows get one retry; a flow that gets through is never
    # retried, because getting through even once is a finding.
    if code != 0 and flow["expect"] == "allow":
        code, out = lab.sh(src, cmd, timeout=TIMEOUT + 10)
    observed = "allow" if code == 0 else "deny"
    return dict(flow, probe=kind, dst_ip=dst_ip, observed=observed,
                detail=out[-200:] if code not in (0, 1) else "")


def control(policy, flow, dst_ip):
    """Is the target service actually running? Asked from the target itself.

    Without this, a "blocked" result could just mean nothing was listening.
    """
    if flow["to"] == "gateway":
        target = "router"
    else:
        target = flow["to"]
    kind = flow.get("probe", "tcp")
    code, _ = lab.sh(lab.container(policy, target),
                     f"clinic-probe {kind} {dst_ip} {flow['port']} {TIMEOUT}", timeout=TIMEOUT + 10)
    return code == 0


def ruleset_fingerprint(policy):
    code, out = lab.sh(lab.container(policy, "router"), "nft list ruleset")
    return hashlib.sha256(out.encode()).hexdigest()[:12] if code == 0 else "unavailable"


def run(args):
    policy = lab.load_policy()
    flows = policy["flows"]
    if args.only:
        wanted = set(args.only.split(","))
        flows = [f for f in flows if f["id"] in wanted]
    net = lab.variant()
    started = datetime.datetime.now(datetime.timezone.utc)
    lab.emit({"type": "test-start", "variant": net, "total": len(flows)})

    results = []
    with ThreadPoolExecutor(WORKERS) as pool:
        for r in pool.map(lambda f: probe(policy, f), flows):
            r["pass"] = r["observed"] == r["expect"]
            results.append(r)
            lab.emit({"type": "probe", "source": "test", **{k: r.get(k) for k in (
                "id", "from", "to", "port", "probe", "dst_ip", "expect", "observed", "pass", "what")}})
        # Controls only matter for flows that were blocked.
        blocked = [r for r in results if r["observed"] == "deny"]
        for r, up in zip(blocked, pool.map(lambda r: control(policy, r, r["dst_ip"]), blocked)):
            r["service_up"] = up

    summary = {
        "variant": net,
        "started": started.isoformat(timespec="seconds"),
        "ruleset": ruleset_fingerprint(policy),
        "total": len(results),
        "passed": sum(r["pass"] for r in results),
        "violations": [r["id"] for r in results if r["expect"] == "deny" and r["observed"] == "allow"],
        "broken": [r["id"] for r in results if r["expect"] == "allow" and r["observed"] != "allow"],
    }
    lab.emit({"type": "test-end", **summary})
    out_dir = lab.RUN / "results"
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "latest.json").write_text(json.dumps({"summary": summary, "results": results}, indent=2))
    (out_dir / "report.md").write_text(render_markdown(policy, summary, results))
    print_terminal(policy, summary, results)
    return summary


# ---------------------------------------------------------------- reporting

def label(policy, node):
    return "Gateway (router)" if node == "gateway" else policy["nodes"][node]["label"]


def zone_of(policy, node):
    return policy["nodes"][node]["zone"] if node != "gateway" else "core"


def verdict(r):
    if r["pass"]:
        return "PASS"
    return "VIOLATION" if r["expect"] == "deny" else "BROKEN"


def render_markdown(policy, s, results):
    title = "segmented clinic" if s["variant"] == "clinic" else "flat network (before)"
    lines = [
        f"# Network isolation report: {title}",
        "",
        f"- Run: {s['started']}",
        f"- Firewall ruleset fingerprint: `{s['ruleset']}`",
        f"- Flows tested: {s['total']}",
        f"- Passed: {s['passed']} of {s['total']}",
        f"- Violations (forbidden flow got through): {len(s['violations'])}",
        f"- Broken (needed flow was blocked): {len(s['broken'])}",
        "",
        "Every flow below was tested by sending real traffic from the source machine.",
        "",
        "| ID | Result | Flow | Service | Expected | Observed |",
        "|----|--------|------|---------|----------|----------|",
    ]
    order = {"VIOLATION": 0, "BROKEN": 1, "PASS": 2}
    for r in sorted(results, key=lambda r: (order[verdict(r)], r["id"])):
        note = "" if r.get("service_up", True) else " (no listener)"
        lines.append(
            f"| {r['id']} | **{verdict(r)}** | {r['what']} | "
            f"{label(policy, r['from'])} → {label(policy, r['to'])} :{r['port']}/{r['probe']} | "
            f"{r['expect']} | {r['observed']}{note} |")
    lines += ["", "\"(no listener)\": nothing answered on that port even from the target itself, "
              "so the block is not the only thing stopping the flow. Every other blocked flow "
              "was confirmed to have a live service behind it."]
    return "\n".join(lines) + "\n"


def print_terminal(policy, s, results):
    tty = sys.stdout.isatty()
    color = {"PASS": "32", "VIOLATION": "31", "BROKEN": "33"}

    def c(code, text):
        return f"\033[{code}m{text}\033[0m" if tty else text

    print()
    for r in sorted(results, key=lambda r: r["id"]):
        v = verdict(r)
        flow = f"{r['from']} -> {r['to']}:{r['port']}"
        print(f"  {c(color[v], v.ljust(9))} {r['id']}  {flow.ljust(34)} {r['what']}")
    print()
    head = f"{s['passed']}/{s['total']} flows match policy"
    tail = f"{len(s['violations'])} violations, {len(s['broken'])} broken"
    ok = s["passed"] == s["total"]
    print(c("32" if ok else "31", f"  {head}  ({tail})"), f"  [{s['variant']}]")
    print("  Report: run/results/report.md")


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--only", help="comma-separated flow IDs")
    ap.add_argument("--expect-violations", action="store_true",
                    help="exit 0 only if at least one violation was caught (for the flat network)")
    args = ap.parse_args()
    s = run(args)
    if args.expect_violations:
        sys.exit(0 if s["violations"] else 1)
    sys.exit(0 if s["passed"] == s["total"] else 1)


if __name__ == "__main__":
    main()
