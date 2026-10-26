# 01. The flat network: why the "before" is dangerous

Goal: understand IP, subnets, gateways, DHCP, DNS and ARP well enough to explain, in one
minute, why a guest laptop can reach the patient records on a flat network and why the
firewall never even sees it.

Start the flat network for this stage: `./lab up flat`, then `./lab traffic off`.

## 1. Concept bridge

| Networking idea | Software idea you know | Where the analogy breaks |
|---|---|---|
| IP address | The host part of a URL, but numeric. A port is the other half (`10.10.0.10:443`). | An IP names a network interface, not a machine or a person. One machine can have many, and a laptop's IP changes. |
| Subnet / CIDR (`10.10.0.0/24`) | A prefix match, like a route pattern `/api/*` or a CIDR allowlist. `/24` means "the first 24 bits must match", i.e. the first three numbers. | A subnet is also a physical fact: "everything in it can be reached directly, without asking anyone". |
| Netmask | The pattern in that prefix match. | Hosts use it for one decision only: "is the destination on my own wire, or do I hand it to the gateway?" |
| Routing table | An ordered list of rules, most specific match wins ("longest prefix"). Like a URL router. | Every hop decides on its own. There is no session and no end-to-end plan. |
| Default gateway | The catch-all route, the `*` handler, which forwards to something that knows more. | It is just the next hop. It does not know the internet either, it knows the next router. |
| DHCP | A tiny service registry that hands out leases with a TTL. A client asks "who am I?" and gets address, gateway and DNS server. | The client does not know the server's address yet, so it shouts to everyone on the wire (broadcast). |
| DNS | A name to value lookup. The router's `dnsmasq` is the resolver. | Plain DNS is unauthenticated and unencrypted, and the answer can be cached anywhere. |
| ARP | A cache lookup "which instance serves this address?", answered by asking everyone on the wire: "who has 10.10.0.10?" | Anyone can answer and nobody verifies it. There is no auth. (This is how ARP spoofing works.) |
| Layer 2 (Ethernet, MAC) vs layer 3 (IP) | L2 is like an in-process call: sender and receiver on the same wire, nothing in the middle. L3 is like a call through an API gateway: hops that can look at, rewrite or reject the request. | Real, but loose. L2 frames never cross a router: each router strips the frame and builds a new one. |

The key sentence: **a firewall can only judge traffic that passes through it.**

## 2. How a packet decides where to go

A machine with address `10.10.0.102/24` wants to reach `10.10.0.10`.

1. Same subnet? `10.10.0.10` matches the first 24 bits of `10.10.0.102`. Yes.
2. So it does not use the gateway. It needs the MAC address of `10.10.0.10`: it broadcasts
   an ARP request, "who has 10.10.0.10?", to every port of the switch.
3. The EMR answers "10.10.0.10 is at aa:c1:ab:a6:6c:a4". The guest caches it (`ip neigh`).
4. The guest sends the packet inside an Ethernet frame addressed to that MAC.
5. The switch looks the MAC up in its table and delivers the frame to the EMR's port only.

The router is plugged into the same switch, but nothing in this path involves it. The
switch is a layer 2 device: it moves frames by MAC address and has no rules.

If the destination is **not** on the same subnet (`203.0.113.10`), step 1 says no. The
machine sends the frame to the gateway's MAC instead. Only now does the router see the
traffic and can apply firewall rules.

```
 same subnet:                         different subnet:
 guest ──switch──► emr                guest ──switch──► router ──► internet
 (router never involved)              (router sees it, firewall can say no)
```

### What the flat network does

- One subnet `10.10.0.0/24` for everything: staff, servers, devices, printers, guests, SIEM.
- The switch has every port in VLAN 1 (`config/flat/switch/ports.conf`): one big broadcast domain.
- The router firewall (`config/flat/router/nftables.nft`) only has two jobs: let the LAN
  out (`allow:lan-internet`) and block the internet from coming in. Between machines in the
  same subnet there is nothing to configure, because the router is never asked.
- Remote access is a port forward: public port 3389 goes straight to the reception PC's
  remote desktop. Scanners find it within minutes. That is how a lot of ransomware gets in.

## 3. Where it lives in the lab

| What | File |
|---|---|
| All machines in one subnet | `topologies/flat.clab.yml` (IPs `10.10.0.x`) |
| Router address and uplink | `config/flat/router/interfaces.sh` |
| Switch: all ports in VLAN 1 | `config/flat/switch/ports.conf` |
| DHCP pool and DNS names | `config/flat/router/dnsmasq.conf` |
| Firewall: LAN out, nothing in, one port forward | `config/flat/router/nftables.nft` |
| How a host gets its address | `clinic-entrypoint`, function `configure_address` |

Commands (in `./lab shell reception-pc` unless noted):

```bash
ip -br -4 addr                  # my address, e.g. 10.10.0.11/24
ip route                        # default via 10.10.0.1, and the local subnet
ip neigh                        # the ARP cache: IP, MAC, state
cat /etc/resolv.conf            # which DNS server I ask
dig +short emr.clinic.internal  # a name the router answers itself
ip route get 10.10.0.10         # "dev eth1": direct, no gateway
ip route get 203.0.113.10       # "via 10.10.0.1": through the router
```

In `./lab shell router`:

```bash
cat /var/lib/misc/dnsmasq.leases   # who has a DHCP lease
nft list ruleset                   # the flat firewall: 2 chains, short
```

## 4. Break it

All exercises run on the flat network. Undo for all: `./lab up flat`.

**Exercise 1.1. The router does not see it.**
Open two shells. In `router`: `tcpdump -ni eth2 "port 445 or arp"`. In `emr`:
`tcpdump -ni eth1 "port 445 or arp"`. In `guest-laptop` run `ip neigh flush all` and then
`nc -zv -w 3 10.10.0.10 445`. Predict what each capture shows, and whether the connection
succeeds. Stop captures with Ctrl-C.

**Exercise 1.2. The netmask decides who the router sees.**
In `./lab shell reception-pc` first confirm `nc -zv -w 2 10.10.0.20 4242` works (PACS).
Then shrink the subnet:

```bash
ip addr del 10.10.0.11/24 dev eth1
ip addr add 10.10.0.11/28 dev eth1
ip route add default via 10.10.0.1
ip route get 10.10.0.20
nc -zv -w 2 10.10.0.20 4242
```

Predict: which of `10.10.0.10` (EMR) and `10.10.0.20` (PACS) is still reachable? Why?
Also read the last line of `run/logs/firewall.jsonl` on the host. Undo:
`ip addr del 10.10.0.11/28 dev eth1; ip addr add 10.10.0.11/24 dev eth1; ip route add default via 10.10.0.1`.

**Exercise 1.3. Take away the default route.**
On reception-pc: `ip route del default`. Predict whether `nc -zv -w 2 10.10.0.10 443`
(EMR) and `curl -sk -m 3 https://203.0.113.10/` (internet) still work.
Undo: `ip route add default via 10.10.0.1`.

**Exercise 1.4. Kill DNS and DHCP.**
In `router`: `pkill dnsmasq`. Then predict the result of: `dig +time=2 +tries=1 +short emr.clinic.internal`
on reception-pc, `curl -sk https://10.10.0.10/` (by IP) on reception-pc, and
`ip addr flush dev eth1; udhcpc -i eth1 -n -q -t 3 -T 1` on guest-phone.
Undo: in `router` run `dnsmasq --conf-file=/etc/clinic/router/dnsmasq.conf`, then
`udhcpc -i eth1 -n -q` on guest-phone.

**Exercise 1.5. Watch DHCP.**
On guest-laptop start `tcpdump -nei eth1 -c 4 "udp port 67 or udp port 68"` in one shell.
In a second shell on guest-laptop run `ip addr flush dev eth1; udhcpc -i eth1 -n -q`.
Predict how many packets you see and whether they are broadcast or unicast.
Undo: nothing, the machine ends with a lease again.

**Exercise 1.6. The score.**
Run `./lab test --expect-violations; echo "exit=$?"` and `./lab attack --fast`. Predict which
kinds of flows match policy (the allowed ones, or the forbidden ones?), which flow is "BROKEN" instead of "VIOLATION", and how many
records the ransomware encrypts.

## 5. Questions you should be able to answer

1. A guest laptop and the EMR are in the same /24. Walk through, step by step, how a packet gets from one to the other. Which devices handle it?
2. Why can the router's firewall not stop that traffic? What are the two ways to put a router (and its firewall) in the path?
3. What does `/24` mean? How many hosts fit? How does a host use the mask?
4. What is ARP, why is it a broadcast, and why is it a security weakness?
5. What does a DHCP client get from the server besides an IP address? Why does it use broadcast?
6. "We have a firewall, so we are protected." Respond using the flat network as the example.

<details><summary>Answers</summary>

**Exercise 1.1.** Verified. The router sees only the ARP broadcast. The EMR sees the ARP
request, its own reply, and the whole TCP conversation. The connection succeeds
(`Connection to 10.10.0.10 445 port [tcp/microsoft-ds] succeeded!`).

```
router eth2:   ARP, Request who-has 10.10.0.10 tell 10.10.0.102        (1 packet)
emr eth1:      ARP request, ARP reply, SYN, SYN-ACK, ACK, FIN... (9 packets)
```

Everything after the ARP exchange is a frame addressed straight to the EMR's MAC. The
switch delivers it to the EMR's port only. The router has no chance to say no. Broadcasts
(ARP, DHCP) are the only traffic that reaches everybody.

**Exercise 1.2.** Verified. With a /28 the subnet is `10.10.0.0` to `10.10.0.15`.

- EMR `10.10.0.10` is inside, still reachable directly (`Connection ... succeeded`).
- PACS `10.10.0.20` is outside. Deleting the /24 address also removed the default route
  (the gateway was no longer "on my wire"), so first you get `Network is unreachable`.
  After you add the default route back, `ip route get 10.10.0.20` says
  `via 10.10.0.1`, and the connection times out.

The packets now reach the router (tcpdump on `router eth2` shows the SYN, twice, because
of TCP retransmission). The router's forward chain only allows `eth2 -> eth1`, so it drops
and logs them:

```
"oob.prefix": "deny:inbound", "oob.in": "eth2", "oob.out": "eth2",
"src_ip": "10.10.0.11", "dest_ip": "10.10.0.20", "dest_port": 4242
```

Lesson: the firewall works fine. Traffic just never reaches it unless the sender's own
routing table sends it there. One host with a wrong mask suddenly gets policed; all the
others do not. (The log label `deny:inbound` is misleading here: this is LAN-to-LAN, not
from the internet.)

**Exercise 1.3.** The EMR still works: same subnet, no gateway needed
(`Connection ... succeeded`). The internet fails: `curl` prints `000`, exit code 7, and
`ip route get 203.0.113.10` says `RTNETLINK answers: Network is unreachable`. The kernel
refuses immediately because no route matches. After `ip route add default via 10.10.0.1`
curl returns `200` again.

**Exercise 1.4.** Verified.

- `dig`: `communications error to 10.10.0.1#53: connection refused`, exit 9. The names
  stop working. (Refused, not timed out: the router's kernel answers with a TCP/UDP reset
  because nothing listens on port 53 any more.)
- `curl https://10.10.0.10/` by IP: still works. DNS is only needed for names.
- `udhcpc`: `broadcasting discover` three times, then `no lease, failing`. The phone ends
  with no address (`ip -br -4 addr` shows only `lo`).

Restarting dnsmasq restores both.
Real-world lesson: DNS and DHCP on one box are a single point of failure for "the network
is down" complaints.

**Exercise 1.5.** Verified: 4 packets (Discover, Offer, Request, Ack; tcpdump labels both
client packets "Request" and both server packets "Reply").

```
aa:c1:ab:49:e8:69 > ff:ff:ff:ff:ff:ff  0.0.0.0.68 > 255.255.255.255.67: BOOTP/DHCP, Request
aa:c1:ab:cf:6e:9f > aa:c1:ab:49:e8:69  10.10.0.1.67 > 10.10.0.102.68: BOOTP/DHCP, Reply
(and the same pair again for the Request/Ack)
```

The client packets are broadcast (destination MAC `ff:ff:ff:ff:ff:ff`, source IP `0.0.0.0`):
it has no address and does not know the server. The server replies directly to the
client's MAC. The lease (`udhcpc: lease of 10.10.0.102 obtained from 10.10.0.1, lease
time 3600`) includes router and DNS server, which is why the guest ends up with
`default via 10.10.0.1` and `nameserver 10.10.0.1`.

**Exercise 1.6.** Verified on the flat network: `22/61 flows match policy (38 violations,
1 broken, 0 errors)`. Almost every forbidden flow is a VIOLATION (D01 to D19, D23 to D35, the
port forward R07, and the SIEM flows S04 to S08). Only the internet-side flows D20 to D22 and
the VPN-only R02 to R06 hold. The allowed flow that depends on the segmentation is the only
BROKEN one: R01, because the flat network has no VPN. The exact lists are `flat_known` in
`policy/clinic.yml`.

```
BROKEN    R01  home-doctor -> emr:443            (no VPN in the flat network)
VIOLATION R07  internet -> clinic-wan:3389       (the port forward)
Default-deny sweep: 1344 ports tried, 985 holes, 0 errors
```

`--expect-violations` exits 0 here only because the violations and broken flows are
*exactly* the `flat_known` list, with no errors: this is the CI check that proves the test
suite can actually fail. The ransomware scenario exits 1 (breached):

```
Blocked 0 of 13 paths. Patient records: 0 of 12 intact, 12 encrypted.
Result: BREACHED
```

Patient zero is the imaging workstation. It reaches the records share (`emr:445`), the
reception PC's remote desktop, the printer and the internet. Not one packet to another clinic machine needed the router.

</details>
