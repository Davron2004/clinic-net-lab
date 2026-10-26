# Learning guide for the clinic network lab

Written for a software developer who knows web, APIs, processes and OS basics, but not
networking. The aim: you can explain and defend every piece of this lab to a technical
founder with a networking background.

## How to use these pages

Read one stage, then do its exercises in the running lab, then answer its questions out loud
without looking. The questions are the ones you will be asked. Each stage has:

1. **Concept bridge**: each networking idea next to a software idea you know, and where
   the comparison breaks. The "breaks" column is as important as the match.
2. **Where it lives in the lab**: exact files and commands to look at it live.
3. **Break it**: change something, predict what happens, then run the check. Every
   exercise is reversible, and says how. Answers are at the bottom of each page, collapsed.
   Write your prediction down before opening them.
4. **Questions you should be able to answer**: no answers given.

Every answer was produced by running the exercise in the lab. If your output differs in small
ways (addresses of guest devices, interface numbers, counts of retransmitted packets), the
lesson is the same. If the verdict differs, something is different in your lab: stop and find out why.

## Order

| Stage | Page | You will be able to explain |
|---|---|---|
| 00 | [Setup](00-setup.md) | What a container, a namespace and a virtual cable are, and why a laptop can simulate a clinic |
| 01 | [Flat network](01-flat-network.md) | IP, subnet, gateway, DHCP, DNS, ARP, and why a flat network lets anything reach the EMR |
| 02 | [Segmentation](02-segmentation.md) | VLANs, trunk vs access, router on a stick, port isolation |
| 03 | [Firewall](03-firewall.md) | nftables, default deny, stateful filtering, NAT, egress filtering, logging |
| 04 | [Isolation tests](04-isolation-tests.md) | How the lab proves its claims, and what a green run does not prove |
| 05 | [Medical traffic](05-medical-traffic.md) | DICOM and HL7 over MLLP, and why imaging devices are fenced in |
| 06 | [Remote access](06-remote-access.md) | WireGuard, keys, split tunnel, what a remote doctor can reach |
| 07 | [Monitoring](07-monitoring.md) | SIEM, agents, rules, file integrity monitoring, alert fatigue |
| 08 | [Clinic map and demo](08-clinic-map-and-demo.md) | Where the demo's data comes from, and what the ransomware scenario does |

Do 00 to 04 in order. 05 to 07 each stand on 02 and 03. 08 is short and comes last.

## Lab commands you will use

Docker is the only requirement. Run all commands from the repository root.

```bash
./lab up                 # build and start the segmented clinic (the "after")
./lab up flat            # start the flat network instead (the "before")
./lab status             # machines and whether they finished booting
./lab shell router       # a shell inside a machine: router, switch, emr, pacs, imaging, ...
./lab test               # run the isolation suite
./lab test --only D01,A08          # a few flows only
./lab test --expect-violations     # for the flat network: succeed only if violations are caught
./lab attack --fast      # the ransomware scenario (without --fast: paced for the map)
./lab traffic off        # stop the background "normal day" traffic
./lab down               # stop everything
```

Machine names: `router`, `switch`, `internet`, `reception-pc`, `doctor-pc`, `emr`, `pacs`,
`imaging`, `lab-analyzer`, `printer`, `guest-laptop`, `guest-phone`, `siem`, `home-doctor`.

**Run `./lab traffic off` after every `./lab up` when you capture packets or read alerts.**
Otherwise the background traffic is mixed into what you look at.

Inside a machine, the tools you will use most:

```bash
ip -br -4 addr           # addresses, short form
ip route                 # routing table
ip neigh                 # ARP cache
bridge vlan show         # (switch) VLAN membership per port
nft list ruleset         # (router) the firewall
conntrack -L             # (router) the session table
wg show                  # (router, home-doctor) WireGuard
tcpdump -ni eth1 -c 10   # capture 10 packets; -e shows MAC addresses and VLAN tags
```

Capture with a count (`-c`) or stop with Ctrl-C. Quote filters containing `&` or `!=`.

Logs and results appear on the host in `run/`: `run/logs/firewall.jsonl`, `run/events.jsonl`,
`run/alerts.jsonl`, `run/results/report.md`.

## Undoing a change

Every exercise states its own undo. If you are unsure what state a machine is in,
`./lab up` rebuilds everything from scratch (about half a minute once the images are built).
Changes made with `ip`, `nft`, `bridge` or `wg` inside a machine are lost on restart.

## Safety

Everything is simulated and synthetic. The "internet" is a container in the lab. There are no real
patients, no real keys (they are generated at every boot), and no connection to anything outside
your laptop. Do not run the commands in these pages against a real network.
