#!/usr/bin/env python3
"""Isolation test suite: proves the clinic network only allows what policy allows.

For every flow in policy/clinic.yml it really sends traffic from the source
machine to the target and records whether it got through. A flow passes when
what happened matches what policy expects.

    ./lab test                      # run the matrix against the running lab
    ./lab test --only D01,D02       # run a few flows
    ./lab test --expect-violations  # for the flat "before" network: succeed
                                    # only if the suite finds exactly the
                                    # violations and broken flows policy
                                    # lists for it (flat_known)

Every flow ends with one verdict:
    PASS       what happened matches policy
    VIOLATION  a forbidden flow got through
    BROKEN     a needed flow was blocked
    ERROR      the test could not tell: the source machine is down, a probe
               failed to run, the target could not be resolved, or a flow
               was blocked but the service behind it is not running either
               (so the block proves nothing)
Any verdict but PASS fails the run.

Writes run/results/latest.json and run/results/report.md, and streams each
result to run/events.jsonl for the clinic map.
"""
import argparse
import datetime
import hashlib
import json
import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from labkit import lab  # noqa: E402

TIMEOUT = 3        # seconds to wait for an answer
WORKERS = 12       # probes in flight at once

# clinic-probe's exit codes (images/node/rootfs/usr/local/bin/clinic-probe).
REACHED, BLOCKED = 0, 1

# Some probes force a path (around or through a VPN tunnel) that only makes
# sense from the source machine. The target's self-check only needs to know
# the service is up, so it uses the plain probe.
CONTROL_KIND = {"https-direct": "https", "https-vpn": "https"}


def resolve_target(policy, flow):
    if flow["to"] == "gateway":
        return lab.gateway_of(lab.container(policy, flow["from"]))
    return lab.ip_of(policy, flow["to"])


def error(flow, detail, **extra):
    return dict(flow, probe=flow.get("probe", "tcp"), observed="error", detail=detail, **extra)


def probe(policy, flow, dead):
    """Send the flow's traffic and decide what happened.

    dead: source machines that failed the liveness check, with the reason.
    """
    kind = flow.get("probe", "tcp")
    if flow["from"] in dead:
        return error(flow, f"source machine is not up: {dead[flow['from']]}")
    src = lab.container(policy, flow["from"])
    dst_ip = resolve_target(policy, flow)
    if not dst_ip:
        return error(flow, "could not resolve the target's address")
    cmd = f"clinic-probe {kind} {dst_ip} {flow['port']} {TIMEOUT}"
    code, out = lab.sh(src, cmd, timeout=TIMEOUT + 10)
    # A packet can be slow on its very first trip (address resolution, a cold
    # service). Allowed flows that came back blocked get one retry; a flow
    # that gets through is never retried, because getting through even once
    # is a finding. Errors are not retried: they need a human, not luck.
    if code == BLOCKED and flow["expect"] == "allow":
        code, out = lab.sh(src, cmd, timeout=TIMEOUT + 10)
    if code not in (REACHED, BLOCKED):
        return error(flow, f"probe failed (exit {code}): {out[-200:]}", dst_ip=dst_ip)
    r = dict(flow, probe=kind, dst_ip=dst_ip, observed="allow" if code == REACHED else "deny", detail="")
    if r["observed"] == "deny":
        # A block only proves something if the service behind it is running.
        up, why = control(policy, flow, dst_ip)
        r["service_up"] = up
        # (A needed flow that is blocked is BROKEN either way.)
        if not up and flow["expect"] == "deny" and not flow.get("no_service"):
            r.update(observed="error",
                     detail=f"blocked, but the target service is not running either ({why}), so the block proves nothing")
    return r


def control(policy, flow, dst_ip):
    """Is the target service actually running? Asked from the target itself.

    Without this, a "blocked" result could just mean nothing was listening.
    Returns (up, reason).
    """
    target = "router" if flow["to"] == "gateway" else flow["to"]
    kind = flow.get("probe", "tcp")
    kind = CONTROL_KIND.get(kind, kind)
    code, out = lab.sh(lab.container(policy, target),
                       f"clinic-probe {kind} {dst_ip} {flow['port']} {TIMEOUT}", timeout=TIMEOUT + 10)
    if code == REACHED:
        return True, ""
    if code == BLOCKED:
        return False, "nothing answered even from the target itself"
    return False, f"self-check failed (exit {code}): {out[-120:]}"


def ruleset_fingerprint(policy):
    code, out = lab.sh(lab.container(policy, "router"), "nft list ruleset")
    return hashlib.sha256(out.encode()).hexdigest()[:12] if code == 0 else "unavailable"


def check_sources(policy, flows, pool):
    """Liveness check for every distinct source machine. Returns {node: reason} for dead ones."""
    nodes = sorted({f["from"] for f in flows})
    checks = pool.map(lambda n: lab.alive(lab.container(policy, n)), nodes)
    return {n: why for n, (ok, why) in zip(nodes, checks) if not ok}


def verdict(r):
    if r["observed"] == "error":
        return "ERROR"
    if r["observed"] == r["expect"]:
        return "PASS"
    return "VIOLATION" if r["expect"] == "deny" else "BROKEN"


def run(policy, flows):
    net = lab.variant()
    started = datetime.datetime.now(datetime.timezone.utc)
    lab.emit({"type": "test-start", "variant": net, "total": len(flows)})

    results = []
    with ThreadPoolExecutor(WORKERS) as pool:
        dead = check_sources(policy, flows, pool)
        for node, why in dead.items():
            print(f"  source machine {node} is not up: {why}", file=sys.stderr)
        for r in pool.map(lambda f: probe(policy, f, dead), flows):
            r["verdict"] = verdict(r)
            r["pass"] = r["verdict"] == "PASS"
            results.append(r)
            lab.emit({"type": "probe", "source": "test", **{k: r.get(k) for k in (
                "id", "from", "to", "port", "probe", "dst_ip", "expect", "observed", "pass", "what")}})

    def ids(v):
        return [r["id"] for r in results if r["verdict"] == v]

    summary = {
        "variant": net,
        "started": started.isoformat(timespec="seconds"),
        "ruleset": ruleset_fingerprint(policy),
        "total": len(results),
        "passed": len(ids("PASS")),
        "violations": ids("VIOLATION"),
        "broken": ids("BROKEN"),
        "errors": ids("ERROR"),
    }
    lab.emit({"type": "test-end", **summary})
    out_dir = lab.RUN / "results"
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "latest.json").write_text(json.dumps({"summary": summary, "results": results}, indent=2))
    (out_dir / "report.md").write_text(render_markdown(policy, summary, results))
    print_terminal(summary, results)
    return summary


# ---------------------------------------------------------------- reporting

def label(policy, node):
    return "Gateway (router)" if node == "gateway" else policy["nodes"][node]["label"]


ORDER = {"ERROR": 0, "VIOLATION": 1, "BROKEN": 2, "PASS": 3}


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
        f"- Errors (the test could not tell): {len(s['errors'])}",
        "",
        "Every flow below was tested by sending real traffic from the source machine.",
        "",
        "| ID | Result | Flow | Service | Expected | Observed |",
        "|----|--------|------|---------|----------|----------|",
    ]
    for r in sorted(results, key=lambda r: (ORDER[r["verdict"]], r["id"])):
        observed = r["observed"]
        if r.get("detail"):
            observed += f": {r['detail']}".replace("|", "/").replace("\n", " ")
        elif r.get("no_service") and not r.get("service_up", True):
            observed += " (no service behind it, by design)"
        lines.append(
            f"| {r['id']} | **{r['verdict']}** | {r['what']} | "
            f"{label(policy, r['from'])} → {label(policy, r['to'])} :{r['port']}/{r['probe']} | "
            f"{r['expect']} | {observed} |")
    lines += ["", "Every blocked flow was confirmed to have a live service behind it (asked from the "
              "target itself), unless policy marks the flow as having no service by design."]
    return "\n".join(lines) + "\n"


def print_terminal(s, results):
    tty = sys.stdout.isatty()
    color = {"PASS": "32", "VIOLATION": "31", "BROKEN": "33", "ERROR": "35"}

    def c(code, text):
        return f"\033[{code}m{text}\033[0m" if tty else text

    print()
    for r in sorted(results, key=lambda r: r["id"]):
        v = r["verdict"]
        flow = f"{r['from']} -> {r['to']}:{r['port']}"
        print(f"  {c(color[v], v.ljust(9))} {r['id']}  {flow.ljust(34)} {r['what']}")
        if v == "ERROR":
            print(f"            {r['detail']}")
    print()
    head = f"{s['passed']}/{s['total']} flows match policy"
    tail = f"{len(s['violations'])} violations, {len(s['broken'])} broken, {len(s['errors'])} errors"
    ok = s["passed"] == s["total"]
    print(c("32" if ok else "31", f"  {head}  ({tail})"), f"  [{s['variant']}]")
    print("  Report: run/results/report.md")


def expected_findings_match(policy, s):
    """--expect-violations: the flat network must fail in exactly the known ways."""
    known = policy["flat_known"]
    ok = True
    for key in ("violations", "broken"):
        want, got = set(known[key]), set(s[key])
        if want != got:
            ok = False
            print(f"  expected {key} {sorted(want)}, got {sorted(got)}"
                  f" (missing {sorted(want - got)}, unexpected {sorted(got - want)})", file=sys.stderr)
    if s["errors"]:
        ok = False
        print(f"  errors: {s['errors']}", file=sys.stderr)
    return ok


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--only", help="comma-separated flow IDs")
    ap.add_argument("--expect-violations", action="store_true",
                    help="exit 0 only if the violations and broken flows are exactly the ones "
                         "policy lists under flat_known (for the flat network)")
    args = ap.parse_args()

    policy = lab.load_policy()
    flows = policy["flows"]
    if args.only:
        wanted = set(args.only.split(","))
        unknown = sorted(wanted - {f["id"] for f in flows})
        if unknown:
            sys.exit(f"error: no such flow ID: {', '.join(unknown)}")
        flows = [f for f in flows if f["id"] in wanted]

    try:
        with lab.quiet_traffic():
            s = run(policy, flows)
    except RuntimeError as e:
        sys.exit(f"error: {e}")
    if args.expect_violations:
        sys.exit(0 if expected_findings_match(policy, s) else 1)
    sys.exit(0 if s["passed"] == s["total"] else 1)


if __name__ == "__main__":
    main()
