# 03. The firewall: reading `nftables.nft` line by line

Goal: read `config/clinic/router/nftables.nft` without help, predict what any packet
does, and explain the words default deny, stateful, NAT, egress filtering and least privilege.

Use the segmented clinic: `./lab up`, then `./lab traffic off`.

## 1. Concept bridge

| Networking idea | Software idea you know | Where the analogy breaks |
|---|---|---|
| Firewall rule list | An allowlist middleware: a list of checks, first match wins, and the last rule is "reject everything else". | It judges packets, not requests. It sees addresses, ports and protocol. It never sees a URL, a user, or the body. |
| Chain | A function. `jump from_staff` is a function call; falling off the end returns to the caller. | A packet is judged by a chain of rules in order. Order matters: a broad `accept` above a narrow `drop` wins. |
| `iifname vmap { ... }` | A dispatch table: `handlers[interface](packet)`. | The key is the interface the packet arrived on, which is how the router knows the zone. |
| `input` vs `forward` chain | `input`: requests addressed to the gateway itself (its admin API). `forward`: requests the gateway proxies to someone else. | There is a third chain, `output` (traffic the router originates). This lab does not filter it. |
| Default deny (`policy drop`) | A permissions system where no role means no access. | The policy only applies if no rule matched. See exercise 3.3: here the explicit `drop` rules mean it is rarely reached. |
| Stateful filtering, conntrack | A session table. The first packet of a connection is checked against the rules and recorded; replies match the table. | The key is the 5-tuple (protocol, source IP, source port, destination IP, destination port), not a login. UDP has no real sessions; conntrack fakes them with timeouts. |
| TCP vs UDP | TCP: a call with a handshake and delivery guarantees (like HTTP). UDP: fire-and-forget datagrams (like a log shipper over UDP). | The firewall treats both by port number. A port number is a convention, not a guarantee of what runs there. |
| Port | The "method" part of an address. 443 means HTTPS by convention. | Nothing stops SSH from running on 443. A port-based firewall cannot tell. |
| NAT (masquerade) | A forward proxy: many internal clients all appear to the outside as one address. The router remembers who asked, and sends replies back. | Not a security feature. It exists because private addresses (10.x) cannot be routed on the internet. |
| Egress filtering | Restricting outbound calls from a service (no arbitrary outbound HTTP from the payments service). | Most firewalls only think about inbound traffic. Attackers need outbound to steal data and to receive commands. |
| Least privilege | Minimal IAM policy: a service gets only the exact actions it needs. | Same idea. In this lab, "exact" means one source, one destination, one port. |

## 2. Reading the file

### 2.1 The frame

```
table inet clinic {                      # a namespace for chains ("inet" = IPv4 and IPv6)
    chain input   { ... policy drop; }   # packets for the router itself
    chain forward { ... policy drop; }   # packets passing through
    chain from_staff { ... }             # one chain per zone: the policy
    ...
}
table ip nat { chain postrouting { ... masquerade } }   # address translation
```

`define` lines (lines 15 to 29) are constants: zone names and server addresses. `$EMR` means
`10.10.20.10`. They make the rules read like sentences.

### 2.2 The `input` chain (lines 34 to 53): who may talk to the router

```
type filter hook input priority filter; policy drop;
iif "lo" accept                                  # the router talking to itself
ct state established,related accept              # replies to things we allowed
ct state invalid drop                            # malformed or out-of-state packets
iifname { ...zones } icmp type echo-request accept        # ping the gateway
iifname { $STAFF, $SERVERS, $GUEST } meta l4proto { tcp, udp } th dport 53 accept   # DNS
iifname $GUEST udp dport 67 accept               # DHCP
iifname $WAN udp dport 51820 log group 0 prefix "allow:vpn-handshake" accept   # VPN
log group 0 prefix "deny:to-router" drop         # anything else
```

<!-- REVERIFY (main fix 3): servers will lose DNS to the router; update this paragraph, the sentence in the input-chain snippet, and the from_servers row/answers if they mention DNS. -->
DNS is allowed from staff, servers and guests, but **not** from devices and printers. A
device does not need names, and DNS can smuggle data out (a lookup for
`stolen-data.attacker.example` reaches the attacker's DNS server). Policy D12 tests this.
The only thing the internet may send the router is UDP 51820, the VPN handshake.

### 2.3 The `forward` chain (lines 56 to 73): the dispatcher

```
type filter hook forward priority filter; policy drop;
ct state established,related accept
ct state invalid drop
iifname vmap { $STAFF : jump from_staff, $SERVERS : jump from_servers, ... $VPN : jump from_remote }
log group 0 prefix "deny:default" drop
```

Order of events for the first packet of "doctor-pc opens the EMR in the browser":

1. Arrives on `eth2.10`. Is it part of an existing connection? No (it is a SYN).
2. Not invalid. The `vmap` sends it to `from_staff`.
3. `from_staff` rule 1: `ip daddr $EMR tcp dport 443 log ... prefix "allow:staff-emr-https" accept`. Match. Logged as a new connection. Accepted.
4. conntrack records the connection. The EMR's replies come back on `eth2.20`, hit rule 1 (`established`), and are accepted without being checked again.

### 2.4 Zone chains (lines 75 to 135)

Each chain lists what that zone may do, then a final `drop` with a log line.

| Chain | Allows | Everything else |
|---|---|---|
| `from_staff` | EMR 443, PACS 8042, printer 631/9100, web 80/443 to the internet | `deny:staff` |
| `from_servers` | EMR to SIEM 1514/1515 (the security agent) | `deny:server-internet`, `deny:servers` |
| `from_devices` | imaging to PACS 4242 (DICOM), lab analyzer to EMR 2575 (HL7) | `deny:device-internet`, `deny:devices` |
| `from_printers` | nothing | `deny:printer-internet`, `deny:printers` |
| `from_guest` | web 80/443 to the internet | `deny:guest` |
| `from_remote` (VPN) | EMR 443 | `deny:remote-internet`, `deny:remote` |
| `from_security` | nothing | `deny:siem-internet`, `deny:security` |
| `from_internet` | nothing | `deny:inbound` |

Two details. First, `oifname $WAN ... drop` rules come before the generic drop and have their
own names. They produce the "this device tried to leave the building" log line the SIEM
reacts to (stage 07). Second, every rule names source, destination and port. `from_devices`
does not say "allow imaging". It says imaging, to the PACS, on 4242.

### 2.5 NAT (lines 138 to 142)

```
table ip nat { chain postrouting {
    type nat hook postrouting priority srcnat;
    oifname "eth1" ip saddr { 10.10.10.0/24, 10.10.50.0/24 } masquerade } }
```

Packets leaving the WAN port from staff or guest get their source address replaced by
the router's public address (`198.51.100.2`). The internet only sees one address. conntrack
remembers the mapping and rewrites the replies. Servers, devices and printers are not in the
list: even if a rule allowed them out, their replies would have nowhere to go.

### 2.6 Logging

`log group 0 prefix "..."` hands a copy of the packet to the kernel's NFLOG facility.
`ulogd` (started in `clinic-router`) reads it and appends one JSON line to
`/var/log/clinic/firewall.jsonl`, which the host sees as `run/logs/firewall.jsonl`.
Only packets that reach a rule with `log` are logged. Because replies are accepted earlier
by `ct state established`, **only new connections are logged**. A blocked connection is
never established, so each retransmitted SYN counts as new: in the lab, one blocked
`nc -z -w 8` from a guest produced 7 log lines, while one allowed `curl` produced 1.

## 3. Where it lives in the lab

| What | Where |
|---|---|
| The rules | `config/clinic/router/nftables.nft` |
| Loaded at boot | `clinic-router`: `nft -f "$cfg/nftables.nft"` |
| Log pipeline | `clinic-router`: the `ulogd.conf` block, then `run/logs/firewall.jsonl` on the host |
| The same ideas in the "before" | `config/flat/router/nftables.nft` (42 lines) |

Commands in `./lab shell router`:

```bash
nft list ruleset                           # everything, as loaded
nft -a list chain inet clinic from_guest   # one chain, with rule handles (-a)
nft list table ip nat                      # the masquerade rule
conntrack -L                               # the session table
conntrack -L | grep 203.0.113.10           # NAT: look for src=10.10.10.x ... dst=198.51.100.2
```

On the host, the log (every JSON line is one packet):

```bash
tail -f run/logs/firewall.jsonl
tail -n 20 run/logs/firewall.jsonl | python3 -c '
import sys,json
for l in sys.stdin:
    d=json.loads(l); print(d["oob.prefix"], d["oob.in"], "->", d["oob.out"], d["src_ip"], "->", d["dest_ip"], d["dest_port"])'
```

## 4. Break it

All changes are made live with `nft` on the router. **Undo for all:** in `./lab shell
router` run `nft -f /etc/clinic/router/nftables.nft`. The file starts with `flush ruleset`
and `nft -f` applies it as one atomic step, so there is no moment without rules.

**Exercise 3.1. Order matters.**
Allow the staff network to talk DICOM to the PACS, using `add` first:

```bash
nft add rule inet clinic from_staff ip daddr 10.10.20.20 tcp dport 4242 accept
```

Run `./lab test --only D24` (doctor-pc to PACS port 4242, expected deny). Predict. Reload the
file, then try again with `insert` instead of `add`. Predict. Use
`nft -a list chain inet clinic from_staff` to see where each landed.

**Exercise 3.2. Delete the "established" rule.**
Find the handle: `nft -a list chain inet clinic forward | grep established`. Then
`nft delete rule inet clinic forward handle <n>`. Predict which flows of `./lab test`
break. Then, from `reception-pc`, run `curl -sk -m 3 https://10.10.20.10/` and read the
last lines of `run/logs/firewall.jsonl`. Which `oob.prefix` values appear, and
for which packets?

**Exercise 3.3. How many layers of default deny?**
(a) `nft 'chain inet clinic forward { policy accept; }'` then `./lab test`.
(b) Reload, then delete only the last rule of `from_guest` (`deny:guest`; find its handle
with `-a`) and run `./lab test --only D01,D02,A08`, and count the `oob.prefix` values in the
log. (c) Also delete the `deny:default` rule in `forward` and set `policy accept`; run
`./lab test --only D01,D02,A08`. Predict each time.

**Exercise 3.4. Remove NAT.**
`nft flush chain ip nat postrouting`. Then, in a second shell on `internet`, run
`tcpdump -ni eth1 "tcp port 443 and tcp[tcpflags] & tcp-syn != 0"` and from `reception-pc`
run `curl -sk -o /dev/null -w "%{http_code}\n" https://203.0.113.10/`. Predict the source
address the internet sees, and whether A07 and A08 still pass. Then reload and repeat.

**Exercise 3.5. Give the imaging workstation DNS.**
In `imaging`: `dig +time=2 +tries=1 +short @10.10.30.1 example.org` (times out). In `router`:

```bash
nft insert rule inet clinic input iifname eth2.30 meta l4proto { tcp, udp } th dport 53 accept
```

Repeat the `dig`, then run `./lab test --only D12`. Predict. Reload to undo.

**Exercise 3.6. Pretend to be the EMR.**
In `guest-laptop` run:

```bash
ip addr add 10.10.20.10/32 dev eth1
curl -sk -m 3 --interface 10.10.20.10 -o /dev/null -w "http=%{http_code}\n" https://203.0.113.10/
ip addr del 10.10.20.10/32 dev eth1
```

While it runs, capture on `internet`: `tcpdump -ni eth1 "tcp port 443"`. Predict whether the
firewall lets the guest's packet out, which source address the internet sees, and what
`run/logs/firewall.jsonl` says about who did it. Undo: the last command above removes the address.

## 5. Questions you should be able to answer

1. What happens to a packet that no rule matches? Is that exactly what happens in this firewall? (Exercise 3.3.)
2. Explain `ct state established,related accept`. What breaks without it, and why does it not need a rule per reply?
3. What is the difference between the `input` and `forward` chains? Give one rule from each.
4. What does NAT do, and why is it not a security control? Which zones are masqueraded and why those?
5. Why block outbound traffic from the EMR server and the imaging workstation? Name two things an attacker needs outbound access for.
6. How do TCP and UDP differ for a stateful firewall? How can a firewall track a "connection" for DNS, which is UDP?
7. A packet arrives on the guest interface with the source address `10.10.20.10` (the EMR). What does this firewall do with it, and why? What would you add to stop it?

<details><summary>Answers</summary>

**Exercise 3.1.** Verified.

```
after "add":     PASS      D24
after "insert":  VIOLATION D24  doctor-pc -> pacs:4242
```

`add` puts the rule at the end of the chain, after `log ... prefix "deny:staff" drop`. A
packet is dropped before it gets there, so the new rule is dead code. `insert` puts it at
the top (handle 53 above handle 27 in `nft -a list chain`), so it matches first. A rule
that "is in the config" is not necessarily doing anything, and the test suite is how
you find out. Also note the new rule has no `log` statement, so the hole is invisible in
the firewall log.

**Exercise 3.2.** Verified. 11 flows break:

```
BROKEN A01 A02 A03 A04 A05 A06 A07 A08 R01 S01 S02    (0 violations, 11 broken)
```

A09 and A10 (DNS) still pass: they go to the router's `input` chain, which has its own
`established` rule. The log shows why:

```
allow:staff-emr-https  eth2.10 -> eth2.20  10.10.10.11:53088 -> 10.10.20.10:443   (SYN, goes through)
deny:servers           eth2.20 -> eth2.10  10.10.20.10:443 -> 10.10.10.11:53088   (SYN-ACK, dropped)
```

The request is allowed, but the EMR's reply is a new packet in the opposite direction coming
from the servers zone, and `from_servers` has no rule for it. Without state, you need a
rule for every reply path, which is exactly what a stateful firewall avoids. `curl` times
out (http code `000`). The SYN is logged again at every retransmission, because no connection
is ever established. Undo: reload the file.

**Exercise 3.3.** Verified.

```
(a) policy accept:                            all flows match policy
(b) deny:guest deleted:                       A08 PASS, D01 PASS, D02 PASS
    log prefixes: deny:default x6, allow:guest-web x1
(c) policy accept AND deny:default deleted:   A08 PASS, D01 VIOLATION, D02 VIOLATION
```

There are three layers: the zone chain's own `drop`, the `deny:default` rule at the end of
`forward`, and `policy drop`. Removing one changes nothing you can see except the log name
(`deny:guest` becomes `deny:default`). All three must go before a guest reaches the EMR.
The explicit drops exist so that every block is logged under a name that says what it was.
The policy is the last safety net if someone deletes those rules by mistake (case c shows
what that looks like). A test suite that checks the result, not the config, tells you
whether the protection is still real.

**Exercise 3.4.** Verified. The internet sees the private source address:

```
without NAT:  10.10.10.11.52798 > 203.0.113.10.443   and the SYN-ACK goes back to 10.10.10.11
with NAT:     198.51.100.2.51020 > 203.0.113.10.443
```

`http=200` in both cases, and A07 and A08 PASS even without NAT. This is a limit of the
lab, not of NAT: the simulated `internet` machine has a route
`10.10.0.0/16 via 198.51.100.2` (`clinic-internet`, deliberately, to model a hostile
internet that would route private addresses toward the clinic). A real ISP drops private
addresses, so without masquerade real browsing would break. So the suite does not guard
the NAT rule: if someone deleted it, all tests would still pass. A good thing to say in an
interview before someone else finds it.

**Exercise 3.5.** Verified. Before: `communications error to 10.10.30.1#53: timed out`
(dropped, no reply at all). After the `insert`: `203.0.113.10` (an answer), and
`VIOLATION D12  imaging -> gateway:53`. The DNS server on the router (`dnsmasq`) listens on
every inside interface, so the firewall is the only thing keeping the device away. That is
a deliberate choice, written down in `config/clinic/router/dnsmasq.conf`: the tests check
the firewall rather than a quirk of the DNS config. After reloading, DNS from the
imaging workstation fails again, over UDP and over TCP (`dig +tcp`), and still works from
the staff zone.

**Exercise 3.6.** Verified. The firewall lets it out, and blames the EMR.

```
firewall log:  allow:guest-web  eth2.50 -> eth1   10.10.20.10 -> 203.0.113.10:443
internet side: IP 10.10.20.10.39190 > 203.0.113.10.443 [S]        <- private source, not NATed
               IP 203.0.113.10.443 > 10.10.20.10.39190 [S.]       <- the reply
               IP 10.10.20.10.39190 > 203.0.113.10.443 [R]        <- the real EMR resets it
curl: http=000
```

The `from_guest` chain checks the interface it arrived on and the destination, but never
the source address. The router also has `rp_filter = 0` (no reverse-path check), so nothing
else catches a source address that does not belong to the guest subnet. The connection
does not complete (the reply is routed to the real EMR, which sends a reset), but the packet
got out, and the log names the EMR as the sender. NAT does not rescue it either: the
masquerade rule only matches the staff and guest subnets, so the spoofed packet leaves
unchanged. Fix, if you want one: in each zone chain, accept only the zone's own source
subnet, or turn on `rp_filter`. This is a real limit of the lab, and a good example of "the
zone is the interface, not the source IP" from stage 02.

</details>
