# 00. Setup: what is actually running

Goal: after this page you can explain what a "machine" is in this lab, what a
"cable" is, and why a laptop with Docker is enough to test a clinic network.

## 1. Concept bridge

| Networking / infra idea | Software idea you know | Where the analogy breaks |
|---|---|---|
| Container | A process with a private view of the OS (own filesystem, own process list, own network). | A container is not a small VM. It shares the host's kernel. Anything the kernel does (bridging, firewalling, WireGuard) is the host kernel's code running. |
| VM | A whole computer with its own kernel, booted from a disk image. | Heavier and slower to start. A VM could run a different OS or kernel version; a container cannot. |
| Network namespace | A separate "localhost + port space + routing table + firewall" per container. Like each service having its own private copy of the network stack. | It is not a security boundary against someone with root on the host. It isolates, it does not defend. |
| Interface (`eth1`) | A network card. | It is virtual here, but the software above it cannot tell. |
| Link / cable | A socket pair or a pipe: what you write into one end comes out of the other. | A pipe carries bytes. This carries Ethernet frames (one packet plus a header with MAC addresses). |
| veth pair | Exactly that pipe: two virtual interfaces, wired together, one end in each container. | Either end can be moved to a different namespace, that is the whole trick. |
| containerlab | `docker compose` for networks: a YAML file lists nodes and links, one command builds it. | Compose wires containers through a shared virtual network. containerlab wires them point to point, like physical cables. |
| Topology file | Infrastructure as code (Terraform/compose file). | Same idea. The file is the diagram. |

Why simulate at all?

- You cannot experiment on a live clinic. A wrong firewall rule stops someone from opening a chart.
- It is repeatable. `./lab up` builds the same network every time, so a test result means something.
- It can run in CI. Every change rebuilds the network from scratch and re-proves the policy.
- You can build the "before" (flat) and the "after" (segmented) side by side and measure the difference.

What the simulation does not give you:

- Real hardware behaviour: switch chips, cable faults, PoE, Wi-Fi radio, speed and duplex problems.
- Vendor firmware bugs. A real firewall appliance has its own software and its own quirks.
- Real timing and load.

What carries over to the real world: the rules and ideas. The switch is a Linux bridge, the
router is a Linux box with `nftables`. Plenty of real routers (OpenWrt, many firewall
appliances) are exactly that. The concepts (VLAN tag, default deny, conntrack) are the same
as on a hardware switch and a commercial firewall.

## 2. How the lab is built

```
 your laptop (macOS)
 └── Docker Desktop's hidden Linux VM          one Linux kernel
      ├── container "clab"  (runs containerlab, exits when done)
      ├── container router      ┐
      ├── container switch      │  each has its own network namespace:
      ├── container emr         │  its own eth1, eth2..., routes, firewall
      ├── ... 14 machines total ┘
      └── veth pairs = the "cables" between those namespaces
```

One image runs almost every machine (`images/node/Dockerfile`). What a machine becomes is
decided by environment variables from the topology file: `ROLE: router`, `ROLE: switch`, or
a plain host with `IP`, `GW`, `DNS`, `SERVICES`. The boot script is
`images/node/rootfs/usr/local/bin/clinic-entrypoint`.

Four details worth knowing:

1. `network-mode: none` (topologies/clinic.clab.yml, under `defaults:`). Docker normally gives every
   container a "management" NIC that reaches the internet. Here there is none. Every packet
   must cross a lab cable, so nothing can sneak around the firewall. The "internet" is
   itself a container (`internet`, 203.0.113.10).
2. containerlab names the cable ends `eth1`, `eth2`, ... in the order of the `links:` list.
   `switch:eth4 <-> emr:eth1` means: switch port 4 is cabled to the EMR's only NIC.
3. containerlab plugs the cables in after the container starts. That is why the entrypoint
   first waits for its interfaces (`wait_for_cables`).
4. The kernel features come from the host VM: WireGuard, 802.1Q VLANs, NFLOG. That is why
   `.github/workflows/ci.yml` runs `modprobe wireguard 8021q nfnetlink_log` on the CI machine.

## 3. Where it lives in the lab

| What | File |
|---|---|
| Machines and cables of the segmented clinic | `topologies/clinic.clab.yml` (`nodes:` and `links:`) |
| Same machines, flat network | `topologies/flat.clab.yml` |
| How containerlab is launched (inside a container, nothing to install) | `lab`, function `clab()` |
| One image for all machines | `images/node/Dockerfile` |
| Boot logic per role | `images/node/rootfs/usr/local/bin/clinic-entrypoint` |

Commands to look at it live:

```bash
./lab status                       # every machine and whether it finished booting
./lab shell emr                    # a shell inside the EMR server
```

Inside `./lab shell emr`:

```bash
ip -br link                        # the interfaces. Only lo and eth1: one cable
ip -br -4 addr                     # eth1 has 10.10.20.10/24
ip route                           # default via 10.10.20.1: everything else goes to the router
readlink /proc/self/ns/net         # the id of this machine's network namespace
cat /sys/class/net/eth1/iflink     # the interface index at the other end of the cable
```

On the host, `docker ps` lists the machines as `clab-clinic-<name>`.

## 4. Break it

Start from a fresh lab: `./lab up`, then `./lab traffic off` (stops the background
"clinic activity", so captures and test results are not mixed with it).
Undo for all of them: `./lab up` rebuilds everything.

**Exercise 0.1. Cut a cable.**
In `./lab shell switch` run `ip link set eth4 down`. Predict which flows of `./lab test` fail
and which ones do not. Then run `./lab test` and compare. Undo: `ip link set eth4 up`.

**Exercise 0.2. Find the other end of a cable.**
Without reading the topology file: in `./lab shell emr` run
`cat /sys/class/net/eth1/iflink`. Take that number and, in `./lab shell switch`, run
`ip -o link | grep '^<number>:'`. Predict which switch port it is, then check against
`links:` in the topology file. Nothing is changed, so there is nothing to undo.

**Exercise 0.3. Two machines, one name, no clash.**
In `./lab shell reception-pc` run
`ip link add dummy0 type dummy; ip addr add 10.99.99.1/24 dev dummy0; ip -br -4 addr`.
Then look at `ip -br -4 addr` on `doctor-pc`. Predict what doctor-pc shows.
Undo: `ip link del dummy0` on reception-pc.

**Exercise 0.4. Who answers for `example.org`?**
In `./lab shell reception-pc` run `dig +short example.org` and
`curl -sk https://example.org`. Which machine in the lab produced that answer? Use
`ip route get 203.0.113.10` and the topology file to explain the path the packets took.
Nothing is changed.

## 5. Questions you should be able to answer

1. Why is a container enough to model a switch or a firewall, and what could it never model?
2. What does containerlab do when it creates a link? What is a veth pair?
3. Why does every node have `network-mode: none`? What would break in the argument "the firewall is the only path" without it?
4. What is a network namespace? How is it different from a VM, and from a Docker image?
5. Why does CI need `modprobe wireguard 8021q nfnetlink_log` before `./lab up`?
6. A founder asks: "This is Linux in containers. Why should I believe it says anything about my hardware switch and my firewall box?" What do you answer, honestly?

<details><summary>Answers</summary>

**Exercise 0.1.** Verified result: 4 flows go BROKEN and 5 go ERROR, nothing else changes.

```
  BROKEN    A01  reception-pc -> emr:443
  BROKEN    A02  doctor-pc -> emr:443
  BROKEN    A06  lab-analyzer -> emr:2575
  BROKEN    R01  home-doctor -> emr:443
  ERROR     D16  emr -> internet:443       source machine is not up: cannot ping its gateway 10.10.20.1
  ERROR     D33  emr -> pacs:8042
  ERROR     D34  emr -> gateway:53
  ERROR     S01  emr -> siem:1514
  ERROR     S02  emr -> siem:1515
  Default-deny sweep: 1344 ports tried, 0 holes, 168 errors
  52/61 flows match policy  (0 violations, 4 broken, 5 errors)
```

Every flow that needs the EMR as a target breaks (BROKEN: the front desk really cannot open
the EMR). Every flow that starts on the EMR is an ERROR: the suite checks each source machine
first, and the EMR cannot even ping its gateway, so the test says "I could not tell" instead
of counting its forbidden flows as blocks (D16, D33, D34). A cut cable also blocks, which is
why "deny" results alone cannot prove a firewall works (see stage 04). On the EMR,
`ip -br -4 addr` shows `eth1 DOWN`: the "cable" is a real interface state. After
`ip link set eth4 up` the suite is fully green again (give the EMR a moment).

**Exercise 0.2.** The EMR's `iflink` is `1209`. On the switch `1209: eth4@if1210` is the
line. So the EMR is cabled to switch port `eth4`, matching `switch:eth4 <-> emr:eth1` in
the topology. The `@if1209` suffix you see in `ip -br link` on the EMR (`eth1@if1209`) is
the same number: "my peer is interface 1209, in another namespace". (Your numbers will
differ, the matching pair will not.)

**Exercise 0.3.** doctor-pc shows only `lo` and `eth1`: no `dummy0`. Each container has its
own set of interfaces. That is what a network namespace is. The same trick lets the
EMR and the printer both listen on port 443 without a conflict.

**Exercise 0.4.** The answer is the lab's own `internet` container:

```
203.0.113.10                               <- dig answer
<!doctype html><title>example.org</title><h1>A public website</h1>
203.0.113.10 via 10.10.10.1 dev eth1 src 10.10.10.11     <- ip route get
```

The reception PC asked its DNS server (the router, 10.10.10.1). The router's dnsmasq
forwarded to `203.0.113.10` (`server=` in `config/clinic/router/dnsmasq.conf`). That is the
`internet` container, which answers every name with its own address
(`--address=/#/203.0.113.10` in `clinic-internet`). Then HTTPS went reception-pc, router,
internet. No packet ever leaves the lab. The real internet is not involved.

</details>
