# 02. Segmentation: VLANs and the router in the middle

Goal: explain how one physical switch becomes six separate networks, how traffic between
them is forced through the router, and why that is the foundation of everything after it.

Use the segmented clinic for this stage: `./lab up`, then `./lab traffic off`.

## 1. Concept bridge

| Networking idea | Software idea you know | Where the analogy breaks |
|---|---|---|
| VLAN | Multi-tenancy. One physical switch behaves like several independent switches. | The separation is structural, not logic you can forget to apply. A frame in VLAN 10 is simply never delivered to a port outside VLAN 10. There is no `if tenant == ...` to get wrong in the data path. |
| 802.1Q tag | A tenant-ID header on every request (`X-Tenant-ID`). It is 4 extra bytes in the Ethernet header: 12 bits of VLAN ID (1 to 4094) and 3 bits of priority. | The client does not set it. The switch adds it when a frame enters a trunk and removes it when it leaves. A PC cannot choose its own tag. |
| Access port | The edge gateway. A PC plugged in has no idea VLANs exist; the switch stamps its frames with the port's VLAN. | If the port is configured with the wrong VLAN, the PC is silently in the wrong tenant. |
| Trunk port | A service-to-service link that carries many tenants. Each frame keeps its tag so the other end knows which tenant it belongs to. | The router on the other end must understand tags and be configured for each VLAN. |
| Broadcast domain | A pub/sub topic where every subscriber hears every message. A VLAN is one broadcast domain. | You cannot "unsubscribe": ARP and DHCP rely on it. All you can do is make the topic smaller. |
| Router on a stick | One gateway process with one listener per tenant, all on a single network cable. | The single cable is a bottleneck, and every cross-VLAN packet crosses it twice (in on one VLAN, out on another). Real clinics often use a layer 3 switch to avoid that. |
| Inter-VLAN routing | Calls between tenants have to go through the API gateway. The gateway is where the policy lives. | Same idea. Nothing about VLANs by themselves allows or blocks anything between them: the router decides. |
| Port isolation | "Client isolation" on hotel Wi-Fi: each device can reach the gateway but not its neighbours. | It only blocks isolated-to-isolated. An isolated port can still talk to a non-isolated port. |

### Why segment a clinic at all?

- **Blast radius.** One infected machine should not be able to reach everything. A flat
  network lets any machine reach any other (stage 01).
- **Unpatchable devices.** The imaging workstation and lab analyzer often run old software
  that the vendor will not let you update. You cannot fix them, so you fence them in.
- **Untrusted devices.** Guest Wi-Fi phones are strangers. They should be treated like the internet.
- **Different rules for different roles.** Staff may open the EMR in a browser. A printer
  needs nothing outbound. Only a zone boundary lets you write different rules.

## 2. How the lab does it

```
                         router  (eth2 is a trunk, one cable)
                           │ eth2.10 eth2.20 eth2.30 eth2.40 eth2.50 eth2.90   <- 6 virtual interfaces
                           │
                  ┌────────┴────────┐
                  │  switch (br0)   │  VLAN-aware bridge
                  └─┬──┬──┬──┬──┬─┬─┘
        VLAN 10 ────┘  │  │  │  │ └──── VLAN 90 (SIEM)
        reception-pc,  │  │  │  └─ VLAN 50 guests  (isolated ports)
        doctor-pc      │  │  └──── VLAN 40 printer
                       │  └─────── VLAN 30 imaging, lab analyzer (isolated ports)
                       └────────── VLAN 20 EMR, PACS
```

The switch (`images/node/rootfs/usr/local/bin/clinic-switch`) is a Linux bridge created with
`vlan_filtering 1`. Its ports come from `config/clinic/switch/ports.conf`:

- `access 10` becomes `bridge vlan add dev ethN vid 10 pvid untagged`. Frames from the PC
  get tagged 10 on entry and untagged on exit.
- `trunk 10,20,30,40,50,90` becomes one `bridge vlan add` per VLAN, tagged. This is
  `eth1`, the cable to the router.
<!-- REVERIFY (main fix 2): the list of isolated ports changes. -->
- `isolated` becomes `bridge link set dev ethN isolated on`.

The router (`config/clinic/router/interfaces.sh`) creates `eth2.10` ... `eth2.90` on top of
`eth2` and gives each the gateway address `10.10.N0.1`. `ip_forward=1` is set in
`clinic-router`. When `doctor-pc` (10.10.10.12) talks to `emr` (10.10.20.10):

1. The destination is in a different subnet, so doctor-pc sends the frame to its gateway
   MAC (the router, `10.10.10.1`).
2. The switch tags it VLAN 10 and sends it up the trunk.
3. The router receives it on `eth2.10`, so the firewall knows the packet came from the
   staff zone. It checks the rules (stage 03).
4. If allowed, the router routes it out of `eth2.20`. The switch delivers the frame, tag
   removed, to the EMR's access port.

Notice: **the firewall decides the zone by which interface the packet arrived on**, not by
the source IP address in the packet. The VLAN is the identity.

## 3. Where it lives in the lab

| What | File |
|---|---|
| Port map: VLAN per port, trunk, isolated | `config/clinic/switch/ports.conf` |
| Turning that file into bridge settings | `images/node/rootfs/usr/local/bin/clinic-switch` |
| VLAN sub-interfaces and gateway addresses | `config/clinic/router/interfaces.sh` |
| Subnet per zone | `policy/clinic.yml`, `zones:` |

Commands, in `./lab shell switch`:

```bash
bridge vlan show                      # VLAN membership per port. eth1 has all, others one (PVID Egress Untagged)
bridge -d link show dev eth9          # look for "isolated on"
bridge fdb show br br0 | grep -v permanent   # the MAC table: which MAC lives behind which port, per VLAN
tcpdump -eni eth1 vlan                # the trunk: every frame shows "vlan 10" etc. (-e prints MACs and tags)
tcpdump -eni eth4                     # the EMR's access port: untagged
```

In `./lab shell router`:

```bash
ip -br -4 addr | grep eth2            # one address per VLAN sub-interface
ip -d link show eth2.20               # "vlan protocol 802.1Q id 20"
```

## 4. Break it

Undo for all of them is stated per exercise. `./lab up` always restores everything.

**Exercise 2.1. See the tags.**
Open two shells on `switch`: one with
`tcpdump -eni eth1 "tcp port 443 and tcp[tcpflags] & tcp-syn != 0"`, one with the same on
`eth4`. In `doctor-pc` run `curl -sk -o /dev/null https://10.10.20.10/`. Predict: how many
packets show up on the trunk (eth1), what VLAN tags, and what do the MAC addresses do?
What does the EMR's port eth4 show? Nothing is changed.

<!-- REVERIFY (main fix 2: staff-PC and server ports become isolated): this section only lists guest and device ports as isolated; the port list in section 2 and the diagram need updating. -->
**Exercise 2.2. Take isolation away.**
First `./lab test --only D06,D23` (both pass). Then on `switch`:

```bash
bridge link set dev eth9 isolated off     # guest-laptop
bridge link set dev eth10 isolated off    # guest-phone
bridge link set dev eth6 isolated off     # imaging
bridge link set dev eth7 isolated off     # lab-analyzer
```

Run `./lab test --only D06,D23` again. Then switch isolation back on for `eth10`, `eth6`
and `eth7` but leave `eth9` off, and run once more. Predict both results.
Undo: `bridge link set dev eth9 isolated on` (and the other three).

**Exercise 2.3. Plug the EMR into the wrong VLAN.**
On `switch`: `bridge vlan del dev eth4 vid 20; bridge vlan add dev eth4 vid 10 pvid untagged`.
In `emr`: `ping -c1 -W2 10.10.20.1; ip neigh`. Then `./lab test`. Predict: does the EMR
get an ARP answer for its gateway `10.10.20.1`? Which flows break? Read the last
`deny:` lines in `run/logs/firewall.jsonl` that mention `10.10.20.10`: which zone does the
firewall think the EMR is in?
Undo: `bridge vlan del dev eth4 vid 10; bridge vlan add dev eth4 vid 20 pvid untagged`
and `ip neigh flush all` on the EMR.

**Exercise 2.4. Forget a VLAN on the trunk.**
On `switch`: `bridge vlan del dev eth1 vid 50`. Run `./lab test --only A01,A08,A09,D06`,
then in `guest-laptop` `ip neigh flush all; ping -c1 -W2 10.10.50.1; ip neigh`.
Predict which flows break and what `ip neigh` shows.
Undo: `bridge vlan add dev eth1 vid 50`.

<!-- REVERIFY (main fix 2): reception-pc and doctor-pc ports will be isolated, so doctor-pc will probably no longer see the broadcast ping. Re-run and rewrite prediction/answer (choose two non-isolated machines or explain the new result). -->
**Exercise 2.5. How far does a broadcast go?**
Run `tcpdump -ni eth1 icmp` on `doctor-pc` (same VLAN as reception-pc), on `emr` and on
`printer`. In `reception-pc` run `ping -b -c 2 -W 1 10.10.10.255`. Predict which of the three
machines sees the packet. Nothing is changed.

## 5. Questions you should be able to answer

1. What does 802.1Q add to an Ethernet frame, who adds it, and who removes it?
2. What is the difference between an access port and a trunk port? Which one is the router's port, and why?
3. Walk a packet from `doctor-pc` to `emr`. At which points is the MAC address looked at, and at which the IP address?
4. What is router-on-a-stick, and what is its main technical downside?
5. Two guest devices sit in the same VLAN. How is port isolation different from a firewall rule, and when does it fail?
6. "VLANs are security." Is that right? What stops traffic between VLANs, and what could go wrong with a VLAN configuration?

<details><summary>Answers</summary>

**Exercise 2.1.** Verified. Four packets on the trunk, none of them tagged on the EMR's
port. The IP addresses stay the same on both legs; the MAC addresses and the tag change.

```
eth1 (trunk):
 doctor-pc MAC > router MAC   vlan 10   10.10.10.12.36872 > 10.10.20.10.443  Flags [S]
 router MAC    > emr MAC      vlan 20   10.10.10.12.36872 > 10.10.20.10.443  Flags [S]
 emr MAC       > router MAC   vlan 20   10.10.20.10.443   > 10.10.10.12...  Flags [S.]
 router MAC    > doctor MAC   vlan 10   10.10.20.10.443   > 10.10.10.12...  Flags [S.]
eth4 (EMR's access port):  2 packets, no "vlan" in the header, source MAC of the router
```

The same packet appears twice on the one cable (in as VLAN 10, out as VLAN 20). That is
router-on-a-stick, and why it is a bottleneck. The IP header is untouched (no NAT between
internal zones). The MAC rewrite is what "routing" means at layer 2: each hop addresses
the frame to the next hop. A first ping from doctor-pc to the EMR (try `ping` instead of
`curl`) shows 100% loss. ICMP to the EMR is not an allowed flow, the firewall drops it.

**Exercise 2.2.** Verified.

```
all four off:
  VIOLATION D06  guest-laptop -> guest-phone:8080
  VIOLATION D23  imaging -> lab-analyzer:22
only eth9 (guest-laptop) off, eth10 back on:
  VIOLATION D06   (still!)
  PASS      D23
```

Without isolation the two machines are in the same VLAN, so frames go straight between
them. The router is never involved, the same story as the flat network in stage 01. The
firewall cannot help here. Isolation is the only control between machines in one VLAN.

The second result is the surprise: the Linux bridge only blocks traffic between two
isolated ports. `eth10` was isolated, `eth9` was not, and traffic between them is allowed
in both directions. One un-isolated port opens the whole group. In a real clinic, check
every port in the group.

**Exercise 2.3.** Verified. The EMR does get an ARP answer for `10.10.20.1`:

```
10.10.20.1 dev eth1 lladdr aa:c1:ab:f9:b1:f1 REACHABLE      <- the router's MAC
```

The router owns `10.10.20.1` on another interface (`eth2.20`), and Linux answers ARP for
any of its addresses on any interface. So the EMR thinks the gateway is reachable, sends
its packets, and they arrive at the router tagged VLAN 10. The ping still fails (100% packet
loss): the reply goes out of `eth2.20`, where the EMR no longer is. `./lab test` shows
the same six flows as the cut cable in stage 00:

```
BROKEN A01, A02, A06, R01, S01, S02     (0 violations, 6 broken)
```

The firewall log shows how the router sees it:

```
deny:staff   eth2.10 -> eth2.90   10.10.20.10 -> 10.10.90.10:1514
```

The packets claim to come from the EMR (10.10.20.10), but they entered on `eth2.10`, so the
firewall judges them as **staff-zone** traffic, and the EMR's rule `allow:emr-siem` never
matches. The zone is the interface, not the source address. Lessons: a mis-patched port
is a silent failure, and the source IP is not the identity.

**Exercise 2.4.** Verified.

```
PASS   A01  reception-pc -> emr:443
BROKEN A08  guest-laptop -> internet:443
BROKEN A09  guest-laptop -> gateway:53
PASS   D06  guest-laptop -> guest-phone:8080
```

The guest's frames are tagged VLAN 50 by the access port, but the trunk no longer carries
VLAN 50, so the switch has nowhere to send them. `ip neigh` shows
`10.10.50.1 dev eth1 INCOMPLETE`: ARP got no answer. Other VLANs are unaffected. The guests
keep their address and their isolation, but lose the router. Compare with 2.3: here nothing
leaks, the zone just goes dark.

**Exercise 2.5.** Verified. Only `doctor-pc` sees the request:

```
doctor-pc:  IP 10.10.10.11 > 10.10.10.255: ICMP echo request   (2 packets)
emr:        0 packets captured
printer:    0 packets captured
```

A broadcast reaches every port in the VLAN and nothing outside it. That is what "broadcast
domain" means. On the flat network (stage 01) the same ping would reach every machine.
(Doctor-pc does not reply: Linux ignores broadcast pings by default. The point is who hears it.)

</details>
