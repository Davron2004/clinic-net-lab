"""Turns one Wazuh alert into one line of run/alerts.jsonl for the clinic map.

wazuh-integratord runs this for every alert of level 7 or more:

    custom-clinic <file holding the alert as JSON> [api_key] [hook_url]

and we append one line in the lab's event contract:

    {"ts": 1793049268.77, "level": 12, "rule_id": "100110",
     "title": "Imaging workstation tried to reach the internet (...)",
     "node": "imaging", "src_ip": "10.10.30.10", "dst_ip": "203.0.113.10",
     "dst_port": 443, "category": "network", "source": "wazuh"}

ts is when the thing happened (the firewall's own packet time when there is
one), not when Wazuh got round to it, so the map can place it correctly and
the delay is measurable. Machine names come from policy/clinic.yml.

Repeats are dropped here: Wazuh alerts once per packet, so one blocked
connection (a packet plus its retries) can raise the same alert two or
three times. A person needs to hear about it once, so the same alert for the
same machines within 15 seconds is written only once. Wazuh's own alerts.json
still keeps every one.
"""
import datetime
import fcntl
import ipaddress
import json
import re
import sys

import yaml

RUN = "/clinic-run"
OUT = f"{RUN}/alerts.jsonl"
POLICY = "/etc/clinic/policy/clinic.yml"
REPEAT_WINDOW = 15  # seconds


def load_policy():
    """Machine names and labels by address, for the deployed network."""
    try:
        with open(f"{RUN}/variant") as f:
            net = f.read().strip()
        with open(POLICY) as f:
            policy = yaml.safe_load(f)
    except (OSError, yaml.YAMLError):
        return {}, {}, []
    nodes = policy.get("nodes", {})
    by_ip = {}
    for name, spec in nodes.items():
        ip = spec.get("ip", {}).get(net)
        if ip and ip != "dhcp" and not spec.get("container"):
            by_ip[str(ip)] = name
    labels = {name: spec.get("label", name) for name, spec in nodes.items()}
    # Zone subnets (segmented network only): names a guest's DHCP address.
    zones = [(ipaddress.ip_network(z["subnet"]), z["label"])
             for z in policy.get("zones", {}).values() if net == "clinic" and z.get("subnet")]
    return by_ip, labels, zones


def describe(ip, by_ip, labels, zones):
    """'Imaging workstation', or 'Guest Wi-Fi device 10.10.50.138', or the bare IP."""
    if ip in by_ip:
        return labels[by_ip[ip]]
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return ip
    for net, label in zones:
        if addr in net:
            return f"{label} device {ip}"
    return ip


def event_time(alert):
    data = alert.get("data", {})
    if "oob.time.sec" in data:  # the firewall's timestamp for the packet
        return int(data["oob.time.sec"]) + int(data.get("oob.time.usec", 0)) / 1e6
    # Wazuh's alert time, e.g. 2026-10-26T21:14:28.770+0000
    return datetime.datetime.strptime(alert["timestamp"], "%Y-%m-%dT%H:%M:%S.%f%z").timestamp()


def as_int(value):
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def normalize(alert, by_ip, labels, zones):
    rule = alert["rule"]
    groups = rule.get("groups", [])
    data = alert.get("data", {})
    src, dst = data.get("src_ip"), data.get("dest_ip")
    dst_port = as_int(data.get("dest_port"))
    if "frequency" in rule:
        # "N things in M seconds": the target of the last one says nothing.
        dst = dst_port = None
    title = rule.get("description", "")

    if "firewall" in groups:
        category, node = "network", by_ip.get(src)
    elif {"syscheck", "patient_records", "ransomware"} & set(groups):
        category, node = "integrity", alert.get("agent", {}).get("name")
    else:
        category, node = "other", None
        # "Agent disconnected: 'emr-any'." / "Agent stopped: 'emr->any'."
        # name the machine that went quiet ("any" is its registered address).
        m = re.search(r"Agent (?:disconnected|stopped): '(.+)->?[^-'>]*'", alert.get("full_log", ""))
        if m:
            node = m.group(1)
    if node not in labels:
        node = None
    elif category == "other":
        title = f"{labels[node]}: {title[:1].lower()}{title[1:]}"

    # Say "Imaging workstation" rather than "10.10.30.10" where we can.
    for ip in {data.get("src_ip"), data.get("dest_ip")} - {None}:
        title = re.sub(rf"(?<![\d.]){re.escape(ip)}(?![\d.])", describe(ip, by_ip, labels, zones), title)
    if title[:1].islower():
        title = title[0].upper() + title[1:]

    return {
        "ts": round(event_time(alert), 6),
        "level": rule.get("level"),
        "rule_id": str(rule.get("id")),
        "title": title,
        "node": node,
        "src_ip": src,
        "dst_ip": dst,
        "dst_port": dst_port,
        "category": category,
        "source": "wazuh",
    }


def same(a, b):
    keys = ("rule_id", "title", "node", "src_ip", "dst_ip", "dst_port")
    return all(a.get(k) == b.get(k) for k in keys) and abs(a["ts"] - b["ts"]) < REPEAT_WINDOW


def recent(out):
    """The alerts written in the last part of the file (enough for a minute)."""
    out.seek(0, 2)
    start = max(0, out.tell() - 65536)
    out.seek(start)
    lines = out.read().splitlines()
    if start:
        lines = lines[1:]  # probably cut in half
    for line in lines:
        try:
            yield json.loads(line)
        except ValueError:
            continue


def main():
    with open(sys.argv[1]) as f:
        alert = normalize(json.load(f), *load_policy())
    with open(OUT, "a+") as out:
        fcntl.flock(out, fcntl.LOCK_EX)  # one writer at a time, whole lines
        if any(same(alert, prev) for prev in recent(out)):
            return
        out.write(json.dumps(alert) + "\n")


if __name__ == "__main__":
    main()
