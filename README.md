# clinic-net-lab

A small medical clinic's network, built as code. It has six segmented zones, a
default-deny firewall, real medical protocols, a VPN for remote doctors and a
security monitor. A test suite sends real traffic to prove that patient data
only flows where it should.

Everything runs in containers on one laptop. You need Docker and nothing else.

**[Watch the 80-second demo](https://github.com/Davron2004/clinic-net-lab/releases/download/v1.0/clinic-net-lab-demo.mp4)**: the same ransomware attack on a flat network and on this one.

![The clinic map during a simulated ransomware attack on the segmented network](docs/img/map-segmented-attack.png)

## The short version

A ransomware-infected imaging workstation tries 13 common attack paths. The
lab runs that attack twice:

| | Flat network (the "before") | Segmented network (this design) |
|---|---|---|
| Attack paths that got through | 13 of 13 | 1 of 13: sending images to the archive, its one job |
| Patient records encrypted | **12 of 12** | **0 of 12** |
| Isolation tests matching policy (61 flows) | 22 (38 violations, 1 broken) | **61** |
| What the security monitor saw | a file-integrity alert for each record, after the damage | "device tried the internet" and "scan" alerts, within about 2 seconds |

![The same attack on the flat network: all 13 paths open, records encrypted](docs/img/map-flat-attack.png)

## Quickstart

```sh
git clone https://github.com/Davron2004/clinic-net-lab.git
cd clinic-net-lab
./lab up            # build and start the clinic, then the map
```

Open http://localhost:8080 and press **Simulate ransomware**, or **Run
isolation tests**. The terminal equivalents:

```sh
./lab test          # 61 flows and a port sweep, report in run/results/report.md
./lab attack        # the ransomware scenario
./lab up flat       # the flat "before" network, for comparison
./lab shell router  # look around: nft list ruleset, ip -br addr, ...
./lab shell switch  # the switch: bridge vlan show, bridge link show
./lab down
```

The first run builds the images, which downloads about 2 GB (mostly the Wazuh
security monitor and the Orthanc image archive) and takes about 6.5 GB of
disk. After that, `./lab up` takes about 25 seconds. `CLINIC_MONITORING=0
./lab up` skips the security monitor (its 2.7 GB image and about 500 MiB of
memory). Docker needs about 1 GB of memory for the lab. Tested on
macOS (Apple silicon, Docker Desktop) and on Ubuntu 24.04 (amd64, in CI).

## The network

```mermaid
flowchart TB
    subgraph outside[Outside the clinic]
        web[Public website<br/>203.0.113.10]
        home[Doctor at home<br/>192.0.2.50]
    end
    isp((Internet))
    web --- isp
    home --- isp
    isp -- "WAN 198.51.100.2<br/>only WireGuard UDP 51820 open" --- fw

    fw["Router / firewall<br/>nftables, default deny<br/>router-on-a-stick"]
    sw["Core switch<br/>VLAN-aware bridge"]
    fw == "802.1Q trunk<br/>VLANs 10,20,30,40,50,90" === sw

    sw --- staff["VLAN 10 · Staff PCs<br/>reception-pc, doctor-pc"]
    sw --- servers["VLAN 20 · Servers<br/>EMR (HTTPS, HL7), PACS (Orthanc, DICOM)"]
    sw --- devices["VLAN 30 · Medical devices<br/>imaging, lab-analyzer<br/>ports isolated, no internet, no DNS"]
    sw --- printers["VLAN 40 · Printers & fax"]
    sw --- guest["VLAN 50 · Guest Wi-Fi<br/>DHCP, client isolation, web only"]
    sw --- security["VLAN 90 · Security<br/>Wazuh manager"]
    home -. "WireGuard tunnel 10.10.60.0/24<br/>reaches the EMR web app only" .-> fw
```

| Zone | VLAN | Subnet | May start connections to |
|---|---|---|---|
| Staff PCs | 10 | 10.10.10.0/24 | EMR web app (443), image viewer (8042), printer (9100, 631), web (80, 443), DNS; not each other |
| Servers | 20 | 10.10.20.0/24 | nothing, except the EMR's security agent to the SIEM; not each other, no DNS |
| Medical devices | 30 | 10.10.30.0/24 | imaging to the archive (DICOM 4242), lab analyzer to the EMR (HL7 2575); nothing else |
| Printers & fax | 40 | 10.10.40.0/24 | nothing |
| Guest Wi-Fi | 50 | 10.10.50.0/24 | web (80, 443) and DNS; not even each other |
| Security | 90 | 10.10.90.0/24 | nothing (agents connect to it) |
| Remote (VPN) | | 10.10.60.0/24 | the EMR web app only |

The firewall policy is in [`config/clinic/router/nftables.nft`](config/clinic/router/nftables.nft).
It's short enough to read in one sitting: one chain per zone, one line per
allowed path. Every new connection between zones and every drop is logged
with the rule's name. Not logged: DNS, DHCP and ping to the router itself,
and traffic inside a zone, which never reaches the router: the switch stops
it instead (staff PC, server, device and guest ports are isolated from each
other).

## How it is tested

[`policy/clinic.yml`](policy/clinic.yml) states the policy as 61 plain
expectations, for example "D08: imaging workstation reaches the patient records
share: deny". It is written separately from the firewall on purpose: if a
firewall rule is wrong, the test catches it instead of inheriting the mistake.

[`tests/isolation.py`](tests/isolation.py) runs each flow by sending real
traffic from the source machine. That covers TCP connects, HTTPS requests, DNS
lookups, DICOM echoes, HL7 messages that must be acknowledged, and tunnel and
non-tunnel paths, address translation (the public website reports the address
it sees) and spoofed source addresses. For every blocked flow it also checks
that the target service is actually running, so a "blocked" result can't just
mean "nothing was listening". A probe that cannot give an answer (a machine
that is down, a missing tool) is an ERROR, never a pass. After the named
flows, a default-deny sweep tries 24 common ports between every pair of zones
and fails if anything policy doesn't allow gets through. It writes a
compliance-style report with a fingerprint of the firewall ruleset it tested.

[CI](.github/workflows/ci.yml) builds the whole clinic on a fresh Ubuntu
runner on every push. It then:

- requires 61/61 and a clean sweep on the segmented network;
- runs the ransomware scenario and requires it to be contained;
- requires the suite to find exactly the flat network's known violations
  (listed in the policy file), and the attack to breach it and encrypt all 12
  records.

The last check proves the tests can fail.

## What's inside

| Piece | What it is |
|---|---|
| [`lab`](lab) | The CLI. It runs [containerlab](https://containerlab.dev) in a container, so macOS and Linux work the same way |
| [`topologies/`](topologies) | The segmented clinic and the flat "before", as containerlab topologies |
| [`config/`](config) | Router (interfaces, nftables, dnsmasq, WireGuard) and switch port maps, per network |
| [`images/node`](images/node) | One Debian image for every simulated machine. `ROLE`/`SERVICES` decide what it becomes |
| [`images/pacs`](images/pacs) | Orthanc, the image archive (PACS) |
| [`images/siem`](images/siem), [`images/agent`](images/agent) | Wazuh manager with the clinic's rules; Wazuh agents for the EMR (file integrity) and the router (firewall log) |
| [`policy/`](policy), [`tests/`](tests) | The 61-flow policy and the isolation test suite |
| [`scenarios/`](scenarios) | The ransomware scenario |
| [`map/`](map) | The live clinic map (Python standard library server and plain JavaScript, no build step) |
| [`learn/`](learn) | One doc per stage: concepts mapped to software ideas, plus "break it" exercises with answers |
| [`docs/phipa.md`](docs/phipa.md) | Each design choice mapped to Ontario's PHIPA, with verified citations |

All patient data is synthetic. Keys and passwords are generated when the lab
starts and are never committed.

## Limits, and what changes with 50 real machines

- **Simulated, not real hardware.** Containers stand in for PCs, and a Linux
  bridge stands in for a managed switch. The concepts carry over: VLANs, trunks,
  stateful filtering, NAT and VPN. Vendor configuration syntax doesn't.
- **Hardware.** A real clinic would use a managed switch with the same VLAN
  plan, Wi-Fi access points mapping SSIDs to VLANs, and a firewall appliance
  or a small Linux/BSD box running the same policy.
- **Addresses.** DHCP reservations for every machine would replace static
  addresses, and the firewall would refer to machines through named sets.
- **Address spoofing inside a zone.** The router drops packets whose source
  address doesn't belong to the network they came from, but a machine could
  still borrow a neighbour's address in its own zone, and some rules trust
  the source address (only the imaging workstation may send to the archive).
  Real switches close that gap with DHCP snooping, IP source guard and
  dynamic ARP inspection, or 802.1X.
- **Remote access.** The VPN would need MFA. A WireGuard key is a device
  credential, not a person's identity.
- **Monitoring.** File-integrity monitoring compares the records against a
  baseline the EMR's agent takes when it starts (a fresh one on every
  `./lab up`), so a change made before that, or while the agent isn't
  running, may go unreported. The map's alert feed writes an identical alert
  for the same machines only once per 15 seconds.
- **Not covered.** There is no admin VLAN, no backups, no endpoint protection
  or patching. The network only limits where an infection can spread; it
  doesn't stop the infection.
- **Not compliance.** The lab is evidence of reasonable technical safeguards,
  not PHIPA compliance; [`docs/phipa.md`](docs/phipa.md) explains the
  difference.
