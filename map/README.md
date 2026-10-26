# Clinic map

A live picture of the lab network for people who do not read firewall rules.
`./lab up` starts it at http://localhost:8080 (`MAP_PORT` changes the port).

## What it shows

- **The clinic as rooms.** Each zone (VLAN) is a box with its machines inside.
  The router/firewall sits in the middle with one port per zone; the internet
  and the home office are outside the building on the left.
- **Every connection the lab makes.** Green travels all the way to the target
  (allowed). Red runs into the firewall and stops there (blocked). Hot pink
  reaches a target it should never have reached (a violation), leaves a
  marching dashed trace and makes the target flash. Each result also has its
  own shape (check, cross, warning sign), so colour is never the only signal.
- **Traffic the router never sees.** Two machines in the same zone talk
  through that zone's switch, so their connection turns at the zone's port
  instead of going up to the firewall. In the flat "before" network there are
  no zones and the router sits at the edge, so every connection is drawn
  straight from one machine to the other.
- **Patient records** (sidebar): how many of the EMR's records still match
  the fingerprints taken at boot, and which ones the ransomware encrypted.
- **Isolation tests** (sidebar): one square per flow in `policy/clinic.yml`,
  lit as each result arrives.
- **Alerts** from the security monitor, as a list and a short pop-up, with the
  machines involved marked on the map.

The two buttons run `tests/isolation.py` and `scenarios/ransomware.py` in the
map's container, one at a time. A run started with `./lab test` or
`./lab attack` shows up the same way.

## Where the data comes from

`server.py` (Python standard library plus PyYAML) follows files under `run/`
and streams normalized events to the page over Server-Sent Events:

| File | Used for |
|------|----------|
| `variant` | segmented clinic or flat network |
| `logs/firewall.jsonl` | connections the firewall allowed or dropped, as they happen |
| `events.jsonl` | test and attack results, record fingerprints, encryption |
| `alerts.jsonl` | security monitor alerts (optional) |
| `results/latest.json` | the last test run, when `events.jsonl` has none |

Addresses become machine names through `policy/clinic.yml` (via
`labkit.lab.ip_index`, plus a live lookup for DHCP guests). Two details keep
the picture honest:

- TCP resends an unanswered connection request every second or so, and the
  firewall logs each copy. Copies share a source port, so they are dropped:
  one attempt, one animation.
- A test result usually arrives after the firewall already logged its packet.
  The server pairs the two, so a connection is drawn once, when it happens.
  Connections the firewall does not log (same-zone traffic, the flat network,
  name lookups answered by the router) are drawn from the test result.

A browser that connects, or reconnects, first gets the whole current state,
so refreshing in the middle of a demo shows the same picture.

The layout is computed from `policy/clinic.yml`: zones with a VLAN are rooms
inside the clinic (sorted by VLAN, split above and below the router), zones
without one are outside. New machines and zones appear on the map without
code changes; a machine whose zone is not listed gets a room of its own.

## Files

- `server.py`: file following, event normalization, the buttons, HTTP and SSE.
- `static/index.html`, `static/app.css`: the page.
- `static/js/layout.js`: positions and connection paths, from the policy.
- `static/js/scene.js`: draws the clinic (SVG) and the effects on machines.
- `static/js/flows.js`: animates connections, paced so bursts stay readable.
- `static/js/panels.js`: header, sidebar cards, captions, banner, pop-ups.
- `static/js/words.js`: the plain-English vocabulary (ports to services).
