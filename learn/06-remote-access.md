# 06. Remote access: a VPN for the doctor at home

Goal: explain what a VPN is, how WireGuard identifies a laptop with keys, what split and
full tunnels are, exactly what the firewall lets a remote doctor do, and what the design
does not protect against (a stolen laptop, no second factor).

Use the segmented clinic: `./lab up`, then `./lab traffic off`.
(The flat network has no VPN. Its "remote access" is a port forward, see stage 01.)

## 1. Concept bridge

| Networking idea | Software idea you know | Where the analogy breaks |
|---|---|---|
| VPN | An authenticated, encrypted connection that carries *IP packets*, so the laptop behaves as if it were plugged into the clinic. Like TLS, but for the whole network layer instead of one application. | An application-level proxy only exposes one app. A VPN exposes a whole network path, so what the firewall allows through it matters a lot. |
| WireGuard | A very small VPN, built into the Linux kernel. UDP only. | The configuration is just keys and addresses. There is no username, no password and no certificate authority. |
| Private / public key pair | An SSH key pair or a JWT signing key. The private key stays on the machine. | There is no passphrase on it here. Whoever copies the file is that laptop. |
| Router's list of peers | `authorized_keys`: the allowlist of public keys that may connect. | Removing a line revokes access immediately (exercise 6.2). There is no expiry unless you build one. |
| `allowed-ips` | A per-key ACL on source addresses ("cryptokey routing"). The router accepts from this key only packets whose source is `10.10.60.2`. | On the laptop the same setting means something else: which destinations the tunnel is allowed to carry. |
| Handshake | A TLS-like key exchange. | WireGuard stays silent unless the first packet is valid for a known key. A scanner sees a closed port. |
| Split tunnel | Only calls to the clinic go through the proxy. Everything else uses the home connection. | The doctor's other traffic (and the DNS queries here) is unprotected and unseen. |
| Full tunnel | All traffic goes through the proxy, which can then filter and log everything. | The clinic carries the doctor's personal traffic and must have an internet path for it. This clinic refuses to do that. |
| "The tunnel proves who. The firewall decides what." | Authentication vs authorization. | A VPN gives only the first. Without a firewall rule after it, a connected laptop would reach everything. |

## 2. How it works in the lab

```
 home-doctor (192.0.2.50)                                   router
 wg0 10.10.60.2/24                                          wg0 10.10.60.1/24
   │  encrypted UDP, laptop port (random) → 198.51.100.2:51820   │
   └────────────────── internet (the "internet" node) ───────────┘
```

1. Each side makes its own key pair when it boots (`clinic-wg init`). The private key
   is in `/run/clinic/wg/private.key` (root only) and never leaves the machine. The public
   key goes to a shared folder `run/wg/` on the host. That folder stands for "the administrator
   copies the laptop's public key into the router". Nothing is committed to git.
2. The router (`wireguard.sh`) lists one peer: `home-doctor`'s public key with
   `allowed-ips 10.10.60.2/32`. WireGuard drops any packet from that key with another source.
3. The laptop (`post-up.sh`) has the router as peer, endpoint `198.51.100.2:51820`, a
   keepalive every 25 s, and one route: `10.10.0.0/16 dev wg0`. **That route is the split
   tunnel.** Only clinic addresses go into the tunnel. The default route stays the home internet.
4. The firewall's `input` chain lets the internet send the router exactly one thing:
   UDP 51820 (`allow:vpn-handshake`). Traffic out of the tunnel comes in on interface
   `wg0` and is judged by chain `from_remote`:

```
chain from_remote {
    ip daddr $EMR tcp dport 443 log group 0 prefix "allow:remote-emr-https" accept
    oifname $WAN log group 0 prefix "deny:remote-internet" drop
    log group 0 prefix "deny:remote" drop
}
```

The doctor gets the EMR web app and nothing else: no file shares (R03), no admin shell (R04),
no staff PCs (R05), no image archive (R02), and the clinic is not an exit to the internet (R06).

### What this does not protect against

- **No second factor.** The only thing proving identity is possession of the private key.
  A real deployment adds a second factor (many VPN products do, WireGuard itself does not),
  or an identity-aware proxy in front of the EMR. The Ontario privacy commissioner's ransomware
  guidance recommends strong multi-factor authentication for remote access (see `docs/phipa.md`).
- **A stolen laptop is the doctor.** With the key file, a thief gets the same access: the EMR web
  app, whatever the EMR's own login then allows. The network cannot tell them apart. Defences:
  full-disk encryption on the laptop, a login on the EMR itself, revoking the key quickly (6.2),
  and alerts for odd use.
- **Split tunnel leaks.** The laptop's DNS queries go to the home resolver and its web traffic
  to the home internet. If the laptop is infected at home, the VPN is a bridge from the home network.
- **The firewall only sees the tunnel address** (`10.10.60.2`), which is why the logs say
  `remote-emr-https` from that address.

## 3. Where it lives in the lab

| What | File |
|---|---|
| Key generation, peers, handshake wait | `images/node/rootfs/usr/local/bin/clinic-wg` |
| Router side | `config/clinic/router/wireguard.sh` |
| Laptop side, split tunnel | `config/clinic/home-doctor/post-up.sh` |
| Door and policy | `nftables.nft`: `allow:vpn-handshake` (input), chain `from_remote` |
| Tests | `policy/clinic.yml`: R01 to R07, D22 |

Commands:

```bash
./lab shell router
  wg show                              # peer, endpoint, allowed ips, "latest handshake", transfer
  ip route | grep wg0
./lab shell home-doctor
  wg show
  ip route                             # note: 10.10.0.0/16 dev wg0, default via the home router
  ip route get 10.10.20.10             # dev wg0
  ip route get 203.0.113.10            # via 192.0.2.1 dev eth1, not the tunnel
  ls -l /run/clinic/wg                 # private.key is mode 600
cat run/wg/*.pub                       # on the host: public keys only
```

## 4. Break it

**Exercise 6.1. What does the internet see?**
Open three shells. In `router`: `tcpdump -ni eth1 -X udp port 51820 -c 4`. In `router`
(second shell): `tcpdump -ni wg0 -c 4 tcp`. In `home-doctor`:
`curl -sk -o /dev/null -w "%{http_code}\n" https://10.10.20.10/`.
Predict what each capture shows. Then, from `internet`, run
`nc -zv -w 2 198.51.100.2 22`, `nc -zvu -w 2 198.51.100.2 51820`, `nc -zvu -w 2 198.51.100.2 51821`.
Predict what a scanner would learn, then read the last lines of `run/logs/firewall.jsonl`.

**Exercise 6.2. Revoke the laptop.**
In `router`:

```bash
KEY=$(cat /var/lib/clinic/wg-pubkeys/home-doctor.pub)
wg set wg0 peer $KEY remove
```

Run `./lab test --only R01,R02,D22,A01`. Predict. Undo, still in `router`:
`wg set wg0 peer $KEY allowed-ips 10.10.60.2/32`, wait about 6 seconds, run `./lab test --only R01`.
What did the laptop have to do to come back?

**Exercise 6.3. A thief with the wrong key.**
In `home-doctor`:

```bash
umask 077; wg genkey > /tmp/thief.key
wg set wg0 private-key /tmp/thief.key
curl -sk -m 5 -o /dev/null -w "http=%{http_code} exit=%{exitcode}\n" https://10.10.20.10/
```

While it runs, capture on `router`: `tcpdump -ni eth1 -c 6 udp port 51820`, then `wg show wg0`.
Predict what the router answers, and what `latest handshake` says. Undo, in `home-doctor`:
`wg set wg0 private-key /run/clinic/wg/private.key; rm /tmp/thief.key`.

**Exercise 6.4. Turn the split tunnel into a full tunnel.**
In `home-doctor`:

```bash
ip route add 198.51.100.2/32 via 192.0.2.1     # keep the tunnel's own packets off the tunnel
ip route replace default dev wg0
curl -sk -m 3 -o /dev/null -w "internet: http=%{http_code}\n" https://203.0.113.10/
dig +time=2 +tries=1 +short example.org
curl -sk -m 3 -o /dev/null -w "emr: http=%{http_code}\n" https://10.10.20.10/
```

Predict all three, and what `tail run/logs/firewall.jsonl` shows. Undo, in `home-doctor`:
`ip route replace default via 192.0.2.1; ip route del 198.51.100.2/32`.
(Without the first route the tunnel's own packets would be routed into the tunnel, and it
would die in a loop. Real VPN clients solve this with firewall marks.)

**Exercise 6.5. The tunnel is not permission.**
In `router`: `nft insert rule inet clinic from_remote ip daddr 10.10.20.20 tcp dport 8042 accept`.
Run `./lab test --only R01,R02`. Predict. Undo: `nft -f /etc/clinic/router/nftables.nft`.

**Exercise 6.6. Claim another tunnel address.**
In `home-doctor`:

```bash
ip addr add 10.10.60.3/24 dev wg0
curl -sk -m 3 --interface 10.10.60.3 -o /dev/null -w "as .3: http=%{http_code}\n" https://10.10.20.10/
curl -sk -m 3 --interface 10.10.60.2 -o /dev/null -w "as .2: http=%{http_code}\n" https://10.10.20.10/
ip addr del 10.10.60.3/24 dev wg0
```

While it runs, capture on `router`: `tcpdump -ni wg0 -c 3`. Predict.

## 5. Questions you should be able to answer

1. What are a public key and a private key in WireGuard? Which one is secret? Who has which?
2. How does the router know that a packet comes from the doctor's laptop? What does `allowed-ips` do on each side?
3. Split tunnel vs full tunnel: what is each, what are the trade-offs, and which does this clinic use?
4. Walk through what happens, step by step, when the doctor opens the EMR from home. What does `from_remote` allow?
5. A doctor's laptop is stolen. What can the thief do? What do you do in the next 10 minutes? What would you want in place beforehand?
6. Why is "the VPN is on" not enough, and where is the MFA gap?
7. Why does a port scan of the clinic's public address show nothing useful? What does UDP scanning tell you?

<details><summary>Answers</summary>

**Exercise 6.1.** Verified. On the WAN side the router sees only UDP datagrams between
`192.0.2.50` and `198.51.100.2:51820`, with random-looking bytes (the first ones are 32-byte
keepalives and 96-byte data packets). No IP address, port or text from inside is visible. On
`wg0` the same exchange appears decrypted:

```
10.10.20.10.443 > 10.10.60.2.40244: Flags [S.]
10.10.60.2.40244 > 10.10.20.10.443: Flags [P.], length 1551      <- the TLS hello
```

A scanner from `internet` learns almost nothing:

```
nc -zv  198.51.100.2 22          timed out          (dropped; logged as deny:to-router)
nc -zvu 198.51.100.2 51820       "succeeded"        (logged as allow:vpn-handshake)
nc -zvu 198.51.100.2 51821       "succeeded"        (logged as deny:to-router)
```

UDP gives no reply for a closed or a filtered port, so `nc -zu` says "succeeded" for both. It
cannot tell them apart, and WireGuard does not answer junk (zero bytes came back from a
junk datagram to 51820). The firewall log knows the difference; the scanner does not. The
`allow:vpn-handshake` line appears for any datagram to that port, valid or not, so that log line
is not evidence of a real VPN login (stage 07).

**Exercise 6.2.** Verified.

```
PASS   A01  reception-pc -> emr:443
PASS   D22  home-doctor -> emr:443           (the direct path was always blocked)
BROKEN R01  home-doctor -> emr:443
PASS   R02  home-doctor -> pacs:8042
```

The router now ignores that key silently. No error, no reply: the laptop just times out.
After `wg set ... allowed-ips ...` and about 6 seconds, `R01` passes and `wg show` says
`latest handshake: 1 second ago`. The laptop did nothing: it keeps retrying the handshake
by itself, so revoking and re-enrolling on the router side is enough. In a real clinic, this
is the answer to "the laptop was stolen": remove its line on the router. It takes effect at
once. (This works because the router's peer list is the only authority.)

**Exercise 6.3.** Verified.

```
curl: http=000 exit=28
router eth1:  192.0.2.50.35485 > 198.51.100.2.51820: UDP, length 148      (every ~5 seconds)
              (no packet back)
wg show on the router: latest handshake: 14 seconds ago      <- from the old, valid key
```

The 148-byte packets are handshake initiations for a public key the router does not know.
It does not answer, not even with an error. For an outsider that is indistinguishable from
a closed port. A different key is a different identity, so the laptop's IP address or its
"being a laptop" gives no access, only the registered key does. After restoring the key, the
tunnel re-forms within a few seconds and the EMR answers `200`.

**Exercise 6.4.** Verified.

```
internet:  http=000          (times out)
dig:       communications error to 203.0.113.10#53: timed out
emr:       http=200
firewall log:
  deny:remote-internet  wg0 -> eth1   10.10.60.2 -> 203.0.113.10:443  (tcp, 3 times: SYN retries)
  deny:remote-internet  wg0 -> eth1   10.10.60.2 -> 203.0.113.10:53   (udp)
  allow:remote-emr-https wg0 -> eth2.20  10.10.60.2 -> 10.10.20.10:443
```

Forcing everything into the tunnel works for the clinic's addresses and fails for the rest:
`from_remote` has no way out. Even the laptop's DNS lookups die, because its resolver
(`203.0.113.10`) is on the internet side. That is test R06. It is the clinic saying "I am a
door to the EMR, not a proxy for your personal browsing". If you wanted full-tunnel with
filtering, you would need DNS and a web proxy for the remote zone, plus NAT for it. Today's
design avoids it with the split tunnel.

**Exercise 6.5.** Verified: `PASS R01`, `VIOLATION R02 home-doctor -> pacs:8042`. The VPN
authenticated the laptop in exactly the same way before and after; one rule changed what that
identity may reach. The tunnel proves who. The chain decides what. The new rule has no `log`
clause either, so it would not show in the firewall log.

**Exercise 6.6.** Verified.

```
as .3: http=000        (times out)
as .2: http=200
router wg0 capture:  only the packet with source 10.10.60.2 appears
```

`allowed-ips 10.10.60.2/32` on the router means WireGuard accepts, from this key, only packets
whose source address is `10.10.60.2`. The packet from `.3` is dropped inside WireGuard, before
the firewall. So a person with the laptop cannot invent other tunnel addresses, and the firewall
can trust that source address in `from_remote`. Compare with the other zones in stage 03: there the
router checks the source address itself (reverse-path check, exercises 3.6 and 3.7), but cannot
tell two machines of one subnet apart.

</details>
