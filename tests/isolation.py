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

After the named flows, a default-deny sweep tries common ports between every
pair of zones and fails the run if anything policy does not allow gets
through (see "default-deny sweep" below). It is skipped with --only.

Writes run/results/latest.json and run/results/report.md, and streams each
result to run/events.jsonl for the clinic map.
"""
import argparse
import datetime
import hashlib
import json
import random
import subprocess
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
    if kind == "spoofed-syn":
        return spoofed_syn(policy, flow, src, dst_ip)
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
    if code == REACHED and flow.get("seen_as"):
        # The target saw the request coming from some address (the probe
        # prints it); policy says which one it must be.
        seen, want = out.splitlines()[-1].strip() if out else "", lab.ip_of(policy, flow["seen_as"])
        if seen != want:
            r.update(observed="deny", detail=f"reached, but from {seen or 'an unknown address'} "
                                             f"instead of {want}")
        return r
    if r["observed"] == "deny":
        # A block only proves something if the service behind it is running.
        up, why = control(policy, flow, dst_ip)
        r["service_up"] = up
        # (A needed flow that is blocked is BROKEN either way.)
        if not up and flow["expect"] == "deny" and not flow.get("no_service"):
            r.update(observed="error",
                     detail=f"blocked, but the target service is not running either ({why}), so the block proves nothing")
    return r


def spoofed_syn(policy, flow, src, dst_ip):
    """Probe "spoofed-syn": does a packet with a borrowed source address get through?

    The source sends TCP SYNs claiming to be flow["spoof_as"] (clinic-spoof-syn).
    Replies would go to the real owner of that address, so the answer comes
    from the target instead: tcpdump there waits for one such SYN. A unique
    source port tells our packets apart from any other traffic.
    """
    fake = lab.ip_of(policy, flow["spoof_as"])
    sport = random.randint(40000, 60000)
    target = lab.container(policy, flow["to"])
    capture = subprocess.Popen(
        ["docker", "exec", target, "timeout", str(TIMEOUT + 2), "tcpdump", "-n", "-l", "-p", "-i", "any", "-c", "1",
         f"tcp[tcpflags] & tcp-syn != 0 and dst port {flow['port']} and src port {sport}"],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    r = dict(flow, probe="spoofed-syn", dst_ip=dst_ip, detail="")
    # tcpdump says "listening on ..." once it is capturing: only then send.
    started = ""
    for line in capture.stderr:
        started = line
        if "listening on" in line:
            break
    if "listening on" not in started:
        capture.kill()
        return error(flow, f"could not watch the target: {started.strip()}", dst_ip=dst_ip)
    code, out = lab.sh(src, f"clinic-spoof-syn {fake} {dst_ip} {flow['port']} {sport}", timeout=TIMEOUT + 10)
    try:
        seen, _ = capture.communicate(timeout=TIMEOUT + 10)
    except subprocess.TimeoutExpired:
        capture.kill()
        return error(flow, "the capture on the target did not finish", dst_ip=dst_ip)
    if code != 0:
        return error(flow, f"could not send the spoofed packets (exit {code}): {out[-200:]}", dst_ip=dst_ip)
    if capture.returncode == 0 and seen.strip():
        return dict(r, observed="allow")
    if capture.returncode == 124:     # timeout: nothing arrived
        return dict(r, observed="deny", service_up=True)
    return error(flow, f"the capture on the target failed (exit {capture.returncode})", dst_ip=dst_ip)


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


# ---------------------------------------------------------------- default-deny sweep
# The flows above test what policy names. The sweep looks for what nobody
# named: from one machine per zone it tries a list of common ports on one
# machine in every other zone (and on the router), and requires that only
# what policy allows gets through. It uses "reach" semantics (a refused
# connection counts as reached), so a hole shows up even where nothing
# listens today. Configured in policy/clinic.yml under sweep.
OUTSIDE = {"internet", "remote"}   # zones outside the clinic
SWEEP_TIMEOUT = 2


def sweep_targets(policy, src):
    zone = {n: spec["zone"] for n, spec in policy["nodes"].items()}
    inside = zone[src] not in OUTSIDE
    targets = [t for t in policy["sweep"]["targets"]
               if zone[t] != zone[src] and (inside or zone[t] not in OUTSIDE)]
    # The router itself: its inside address for clinic machines, its public
    # address for the internet and the home laptop.
    return targets + (["gateway"] if inside else ["clinic-wan"])


def expected_open(policy):
    """(from, to, proto, port) combinations policy allows."""
    allowed = {(f["from"], f["to"], "udp" if f.get("probe") == "dns" else "tcp", f["port"])
               for f in policy["flows"] if f["expect"] == "allow"}
    allowed |= {(a["from"], a["to"], a["proto"], a["port"]) for a in policy["sweep"]["also_allowed"]}
    return allowed


def sweep_one(policy, src, dead):
    """Run the sweep from one machine. Returns a list of result dicts."""
    cfg = policy["sweep"]
    container = lab.container(policy, src)
    plan = []
    for t in sweep_targets(policy, src):
        ip = lab.gateway_of(container) if t == "gateway" else lab.ip_of(policy, t)
        plan += [(t, proto, port, ip) for proto in ("tcp", "udp") for port in cfg[proto]]
    if src in dead:
        return [dict(zip(("to", "proto", "port"), p[:3]), **{"from": src, "result": "error",
                     "detail": f"source machine is not up: {dead[src]}"}) for p in plan]
    specs = " ".join(f"{proto}:{ip}:{port}" for _, proto, port, ip in plan if ip)
    code, out = lab.sh(container, f"clinic-sweep {SWEEP_TIMEOUT} {specs}", timeout=60)
    seen = {}
    if code == 0:
        for line in out.splitlines():
            try:
                row = json.loads(line)
            except ValueError:
                continue
            seen[row["target"]] = row["result"]
    results = []
    for t, proto, port, ip in plan:
        result = seen.get(f"{proto}:{ip}:{port}", "error")
        detail = "" if result != "error" else (
            "could not resolve the target's address" if not ip else f"sweep failed (exit {code}): {out[-120:]}")
        results.append({"from": src, "to": t, "proto": proto, "port": port, "result": result, "detail": detail})
    return results


def sweep(policy, pool, dead):
    allowed = expected_open(policy)
    rows = [r for batch in pool.map(lambda s: sweep_one(policy, s, dead), policy["sweep"]["sources"])
            for r in batch]
    for r in rows:
        r["allowed"] = (r["from"], r["to"], r["proto"], r["port"]) in allowed

    def name(r):
        return f"{r['from']} -> {r['to']}:{r['port']}/{r['proto']}"
    return {
        "probes": len(rows),
        "holes": [name(r) for r in rows if r["result"] == "reached" and not r["allowed"]],
        "open_as_allowed": [name(r) for r in rows if r["result"] == "reached" and r["allowed"]],
        "errors": [f"{name(r)}: {r['detail']}" for r in rows if r["result"] == "error"],
    }


def run(policy, flows, with_sweep=True):
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

        swept = sweep(policy, pool, dead) if with_sweep else None

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
    if swept:
        summary["sweep"] = {"probes": swept["probes"], "holes": swept["holes"], "errors": len(swept["errors"])}
    lab.emit({"type": "test-end", **summary})
    out_dir = lab.RUN / "results"
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "latest.json").write_text(json.dumps({"summary": summary, "results": results, "sweep": swept},
                                                    indent=2))
    (out_dir / "report.md").write_text(render_markdown(policy, summary, results, swept))
    print_terminal(summary, results, swept)
    return summary, swept


# ---------------------------------------------------------------- reporting

def label(policy, node):
    return "Gateway (router)" if node == "gateway" else policy["nodes"][node]["label"]


ORDER = {"ERROR": 0, "VIOLATION": 1, "BROKEN": 2, "PASS": 3}


def render_markdown(policy, s, results, swept):
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
    if swept:
        lines += ["", "## Default-deny sweep", "",
                  f"From one machine per zone, {swept['probes']} common ports were tried on one machine in "
                  "every other zone and on the router. A refused connection counts as getting through, so "
                  "a hole shows up even where nothing listens.", "",
                  f"- Got through, as policy allows: {len(swept['open_as_allowed'])}",
                  f"- Got through, not allowed by policy (holes): {len(swept['holes'])}",
                  f"- Errors: {len(swept['errors'])}"]
        lines += [""] + [f"- HOLE: {h}" for h in swept["holes"]] if swept["holes"] else []
        lines += [""] + [f"- ERROR: {e}" for e in swept["errors"]] if swept["errors"] else []
    return "\n".join(lines) + "\n"


def print_terminal(s, results, swept):
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
    if swept:
        print()
        for h in swept["holes"]:
            print(f"  {c('31', 'HOLE     ')} {h}")
        for e in swept["errors"]:
            print(f"  {c('35', 'ERROR    ')} {e}")
        ok = not swept["holes"] and not swept["errors"]
        print(c("32" if ok else "31", f"  Default-deny sweep: {swept['probes']} ports tried, "
                                      f"{len(swept['holes'])} holes, {len(swept['errors'])} errors"))
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
            # The sweep is about the whole network, so it runs with the full matrix only.
            s, swept = run(policy, flows, with_sweep=not args.only)
    except RuntimeError as e:
        sys.exit(f"error: {e}")
    sweep_errors = bool(swept and swept["errors"])
    if args.expect_violations:
        # On the flat network the sweep's holes are expected (there is no
        # firewall inside); they are reported, not judged.
        sys.exit(0 if expected_findings_match(policy, s) and not sweep_errors else 1)
    sweep_clean = not swept or not (swept["holes"] or sweep_errors)
    sys.exit(0 if s["passed"] == s["total"] and sweep_clean else 1)


if __name__ == "__main__":
    main()
