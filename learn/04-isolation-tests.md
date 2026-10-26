# 04. Isolation tests: proving the network does what we say

Goal: explain how the test suite works, why it is written separately from the firewall,
what a green run proves, and what it can never prove. This is the part a skeptical founder
will push on hardest.

Use the segmented clinic: `./lab up`, then `./lab traffic off`.

## 1. Concept bridge

| Idea in this stage | Software idea you know | Where the analogy breaks |
|---|---|---|
| `policy/clinic.yml` | The spec: acceptance criteria written as a table of "who may call what". | It is also read by the clinic map and by the Wazuh integration (names and zones), so it is more than test data. |
| `nftables.nft` | The implementation under test. | The same person wrote both. Independence here comes from the mechanism (the test sends real packets and never reads the rules), not from a second author. |
| A probe | An end-to-end test step that really performs the action: `curl`, a DNS query, a DICOM C-ECHO. | The probe runs inside the source container, so the packet takes the path a real program there would take. |
| Test matrix (dozens of flows) | An enumerated test list. Not exhaustive. | The input space is every source, destination, port, protocol (about 14 x 14 x 65535 x 3). We sample the flows that matter. |
| PASS / VIOLATION / BROKEN / ERROR | A forbidden thing worked (security bug), a required thing did not (outage), or the test itself could not tell (a flaky or broken test). Three different failures. | A plain "FAIL" would hide which one it is. ERROR is the one test frameworks usually lump with "fail" or, worse, with "pass". |
| Positive control | In a test that asserts "this call is rejected", also check the happy path exists. Otherwise the test passes when the service is simply down. | The control asks the target machine itself ("do you answer on this port, locally?"). It does not prove the packet could have got there. |
| Default-deny sweep | Fuzzing or a port scan as a test: instead of testing the cases someone thought of, try many and demand that only the known-good ones work. | It samples 24 ports, one machine per zone. A port outside the list, or a service that stays silent, can still hide. |
| `--expect-violations` on the flat network | Mutation testing: break the code on purpose and check that the tests notice. | Here we do not mutate the firewall, we use a network that is known to be bad. |
| CI | Same as any CI: rebuild from scratch on every change. | It builds a virtual network, so it needs kernel modules (stage 00). |

## 2. How the suite works

For every flow in `policy/clinic.yml` (`tests/isolation.py`, function `probe`):

1. Find the source machine's container and the target's address (from DHCP for guests).
2. Check that the source machine is alive (see "Details" below). A dead source is an ERROR.
3. `docker exec` into the source and run `clinic-probe <kind> <ip> <port> 3`. The kinds are in
   `images/node/rootfs/usr/local/bin/clinic-probe*`.
4. Read the exit code. Every probe uses the same three: **0 reached** (`observed: allow`),
   **1 blocked** (`observed: deny`, what a firewall drop looks like) and **2 error** (the probe
   could not give an answer: bad arguments, a missing tool, a name that does not resolve, a
   service that answered in a way it does not understand). An error is never read as blocked.
5. Compare with `expect:`. PASS is `observed == expect`. A forbidden flow that got through is
   a VIOLATION, a needed flow that did not is BROKEN, and anything that ended in `error` is an
   ERROR. **Any verdict but PASS fails the run**, and so does a hole in the sweep.

| Probe | What it proves when it succeeds |
|---|---|
| `tcp` | A TCP connection opens. (`nc -z`.) |
| `https` | An HTTPS page loads. |
| `dns` | The DNS server answers a lookup. |
| `dicom` | A real DICOM service answers a C-ECHO (stage 05). More than an open port. |
| `hl7` | An HL7 receiver acknowledges a message with `MSA\|AA` (stage 05). |
| `pacs-web` | The image archive answers with its login prompt (Orthanc's `401`). The network let us reach it. The password is a second lock. |
| `reach` | The TCP packet got an answer, even a refusal ("nothing listens here" still proves the path is open). Used for the SIEM so tests pass while Wazuh is still starting, and for the clinic's public address, where nothing listens. |
| `https-direct` / `https-vpn` | HTTPS forced out of the cable / forced into the VPN tunnel (stage 06). |
| `whoami` | The public website says which source address it saw; the flow's `seen_as` says which one it must be (NAT, A11). |
| `spoofed-syn` | SYNs that claim another machine's address. The reply would go to that machine, so the answer comes from tcpdump on the target instead (D35). |

`tcp` and `reach` are one small Python program, `clinic-probe-tcp`. It replaced the older
`clinic-probe-reach` script.

Details that matter:

- **Source health check.** Before any probe, every source machine must have finished booting
  and be able to ping its own gateway. Otherwise all its flows are ERRORs ("source machine is
  not up"). Without it, a machine with a cut cable would "block" every forbidden flow it starts.
  A machine configured with a gateway must also still have its default route: after
  `ip link set eth1 down` and back up on the printer the route is gone, and D14/D15 come back
  ERROR ("has lost its default route"). Only the simulated internet has no default route by
  design; it is checked for having booted.
- **Retry asymmetry.** An allowed flow that comes back blocked is retried once (a first packet
  can be slow). A forbidden flow is never retried, because getting through even once is a
  finding. Errors are not retried either: they need a human, not luck.
- **Controls.** For every blocked flow, the suite then runs the same probe from the *target*
  machine to itself (`control()`). If the service does not answer there either, a `deny` flow
  is an ERROR ("blocked, but the target service is not running either"): the block proves
  nothing. A flow marked `no_service: true` in the policy is exempt, for the rare case where
  nothing runs behind the port by design.
- **Default-deny sweep.** After the named flows, `clinic-sweep` runs from one machine per zone
  and tries 20 TCP and 4 UDP ports on one machine in every other zone and on the router (1344
  probes). A refused connection (or a UDP "port unreachable") counts as getting through, so a
  hole shows up even where nothing listens today. Anything that gets through must be an
  allowed flow in the policy or listed under `sweep.also_allowed`; otherwise it is a HOLE and
  the run fails. It is skipped with `--only`.
- **Unknown IDs.** `--only D99` is an error, not an empty run.
- **Fingerprint.** `ruleset` is the first 12 characters of a SHA-256 of `nft list ruleset`.
  It says which firewall was tested. Two reports with different fingerprints tested different rules.
- **Parallel.** 12 probes at a time. Routine traffic (`labkit/traffic.py`) pauses itself
  while a test runs (it watches `test-start` / `test-end` in `run/events.jsonl`).
- **Outputs.** `run/results/latest.json`, `run/results/report.md` (with a sweep section), and one
  event per probe in `run/events.jsonl` (which the clinic map follows).

### What "green" means

A fully green run means: *for each of the specific flows in the table, a real packet from the real source
behaved as the policy says, on this firewall, at this moment.* It does not mean "the
network is secure". It does not cover:

- Anything not in the table or the sweep: ports outside the sweep's 24, IPv6, source machines the sweep does not start from, one spoofed address (D35) rather than all of them, borrowing a neighbour's address inside one subnet (stage 03, exercise 3.7).
- UDP services that stay silent. The sweep only sees a UDP port as open if something answers or the host says "port unreachable" (exercise 4.3).
- Weaknesses behind an allowed port (the EMR web app has a bug, the file share is open to guests).
- Machines being compromised in ways that need no network (a USB stick).
- Timing: a flow might work only for the first minute, or only under load.
- A probe tool that lies. The health check proves the source machine is up, not that its `clinic-probe` tells the truth (exercise 4.4).

### CI (`.github/workflows/ci.yml`)

```
lint (shellcheck, ruff)
./lab up              ->  ./lab test                      must be fully green
                      ->  ./lab attack --fast             must be contained, exit 0
./lab up flat          ->  ./lab test --expect-violations  must find exactly the known violations
                      ->  ./lab attack --fast             must breach (exit 1) and encrypt 12 records
```

The last two steps test the tests: if the flat network ever "passed", the suite would be broken.
"Exactly the known violations" means the policy's `flat_known` list: 38 violations and 1 broken
flow (R01). `--expect-violations` fails if one is missing (the test lost its teeth), if an
unexpected one appears, or if there is any ERROR. A scenario exit code of 2 (the attack itself
failed) does not count as a breach. Exit codes of `./lab attack`: 0 contained, 1 breached, 2 error.

## 3. Where it lives in the lab

| What | File |
|---|---|
| Expectations, one line per flow | `policy/clinic.yml`, `flows:` |
| Runner, verdicts, report | `tests/isolation.py` |
| Probe implementations | `images/node/rootfs/usr/local/bin/clinic-probe` and `clinic-probe-*` |
| Running commands in containers | `labkit/lab.py`, function `sh` |
| Pipeline | `.github/workflows/ci.yml` |

Commands:

```bash
./lab test                                   # everything
./lab test --only D01,D02,A08                # a few flows
./lab test --expect-violations; echo $?      # for the flat network
less run/results/report.md                   # the table of flows, then the sweep section
python3 -m json.tool run/results/latest.json | less   # includes "service_up" per blocked flow
tail -f run/events.jsonl                     # what the map receives
```

## 4. Break it

**Exercise 4.1. Make a "pass" for the wrong reason.**
Stop the EMR's web server: `pkill -f clinic-emr-web` in `./lab shell emr`. Then run
`./lab test --only A01,D01,D21,D22` and read the terminal output and `run/results/report.md`.
Predict the verdict of each flow.
Undo: `docker exec -d clab-clinic-emr clinic-emr-web` from the host (or `./lab up`). Give it
a few seconds before the next test.

**Exercise 4.2. A typo in the policy.**
Edit `policy/clinic.yml` and change D01's `port: 443` to `port: 4443`. Run
`./lab test --only D01`. Predict the verdict, then check the report.
Undo: `git checkout policy/clinic.yml`.

**Exercise 4.3. A hole outside the matrix.**
Run `./lab test --only A01` and note the `ruleset` value in `run/results/latest.json`. Then:

```bash
# in ./lab shell emr: a UDP listener that writes what it receives and never answers
python3 -u -c 'import socket; s=socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.bind(("0.0.0.0",5353))
while True: print(s.recvfrom(100)[0], flush=True)' > /tmp/udp.txt &
# in ./lab shell router: open a hole from the guest zone
nft insert rule inet clinic from_guest ip daddr 10.10.20.10 udp dport 5353 accept
```

Run the full `./lab test`. Predict the result and the fingerprint. Then in
`./lab shell guest-laptop` run `echo hello | nc -u -w1 10.10.20.10 5353` and look at
`/tmp/udp.txt` on the EMR.
Undo: `nft -f /etc/clinic/router/nftables.nft` on the router, and `pkill -f socket.socket` on the EMR.

**Exercise 4.4. Break the tester, not the network.**
In `./lab shell printer`, first make the probe tool lie:

```bash
mv /usr/local/bin/clinic-probe /usr/local/bin/clinic-probe.orig
printf '#!/bin/bash\nexit 1\n' > /usr/local/bin/clinic-probe; chmod +x /usr/local/bin/clinic-probe
```

Run `./lab test --only A04,D14,D15,D16` (D14 and D15 start from the printer). Then replace the
liar with nothing: `rm /usr/local/bin/clinic-probe` and run the same command again. Predict both.
Undo: `mv /usr/local/bin/clinic-probe.orig /usr/local/bin/clinic-probe`.

**Exercise 4.5. See the suite catch the flat network.**
`./lab up flat`, then `./lab test --expect-violations; echo "exit=$?"`, then
`./lab test; echo "exit=$?"`, then `./lab attack --fast; echo "exit=$?"`. Predict all three exit codes
and the headline numbers, including what the sweep says. Undo: `./lab up`.

**Exercise 4.6. Open a port the sweep knows about, then one it does not.**
Start the segmented clinic and run `./lab test` once (green). In `router`:

```bash
nft insert rule inet clinic from_guest ip daddr 10.10.20.10 tcp dport 3306 accept
```

Nothing listens on 3306 on the EMR. Run the full `./lab test` and read the end of the
output. Predict the verdict of the 61 flows, the sweep, and the exit code. Reload the file,
then repeat with port `6000` instead of `3306`. Predict again.
Undo: `nft -f /etc/clinic/router/nftables.nft`.

## 5. Questions you should be able to answer

1. Why is the policy file separate from the firewall config? What mistake does this catch, and what mistake does it not?
2. What is the difference between VIOLATION and BROKEN? Which one is worse for a clinic, and why must the report separate them?
3. What is a positive control and why does a blocked flow need one?
4. A security reviewer says "a timeout does not prove a firewall block". Do you agree? What does the suite do about it, and what does it not do?
5. Every flow in the report passes. What can you claim, and what can't you claim?
6. Why does CI also run the suite against the flat network and expect it to fail?
7. Why are forbidden flows never retried, while allowed flows get one retry?
8. What is the difference between ERROR and BROKEN, and why does ERROR fail the run?
9. What does the default-deny sweep find that the flow table cannot? What can still hide from it?

<details><summary>Answers</summary>

**Exercise 4.1.** Verified.

```
terminal:   BROKEN A01   ERROR D01   ERROR D21   ERROR D22     0/4 flows match policy (1 broken, 3 errors)
            D01: blocked, but the target service is not running either
                 (nothing answered even from the target itself), so the block proves nothing
latest.json: "service_up": false for A01, D01, D21, D22
```

A01 is broken, correctly: the front desk really cannot open the EMR now. D01, D21 and D22
used to PASS here, because "blocked" and "nobody is home" look the same from outside. The
control (the same probe run on the EMR against itself) now turns them into ERRORs, and the
run fails. Take away: a block is only proven if the service is up behind it. If the firewall
rule were broken as well, these tests could not tell you until the service came back.
(The web server needs a few seconds after you restart it before A01 passes again.)

**Exercise 4.2.** Verified. D01 is an `ERROR guest-laptop -> emr:4443`: "blocked, but the
target service is not running either". Nothing listens on 4443, so the guest is trivially
"blocked", and the control notices. The typo used to hide behind a PASS with a
"(no listener)" note. Mistyped `deny` tests are silent unless something checks that the
target is up; mistyped `allow` tests are loud (they go BROKEN). That asymmetry is why the
controls exist.

**Exercise 4.3.** Verified.

```
./lab test   ->   61/61 flows match policy, Default-deny sweep: 1344 ports tried, 0 holes   (exit 0)
fingerprint: 29dcd5e4d818 (clean)  ->  ca6058591567 (with the hole)  ->  29dcd5e4d818 (after reload)
/tmp/udp.txt on the EMR:  b'clinic-sweep\n'  b'hello\n'   (the sweep's own probe got in as well)
```

The guest zone now reaches the EMR over UDP, and the suite is fully green. No flow in the
table uses UDP to the EMR, and the sweep's UDP probe to 5353 got no answer back from the silent
listener, which looks exactly like a drop. A green suite proves the listed flows and what the
sweep can see, nothing else. The fingerprint is the only signal: it changed. A review process
that compares the fingerprint to the approved one would catch this. The inserted rule also
has no `log` clause, so it leaves no trace in the firewall log.

If nothing listens on the port (stop the listener first), the host answers "port unreachable"
and the sweep does report `HOLE guest-laptop -> emr:5353/udp`, exit 1. So the hole is only
hidden because the service never answers. Exercise 4.6 shows the TCP case.

**Exercise 4.4.** Verified.

```
(a) probe tool always exits 1:                  (b) probe tool missing:
PASS  A04  reception-pc -> printer:9100         PASS   A04
PASS  D14  printer -> internet:443   deny       ERROR  D14  probe failed (exit 127): clinic-probe: command not found
PASS  D15  printer -> reception-pc:445 deny     ERROR  D15  (same)
PASS  D16  emr -> internet:443                  PASS   D16
4/4 flows match policy                          2/4 flows match policy (2 errors), exit 1
```

(b) is the improvement: a probe that cannot run says so, instead of being read as "blocked".
(a) is the limit that remains. A probe tool that lies with exit 1 reads as a block, and the
controls only check the target side. The source health check proves the printer is up and can
reach its gateway, not that its `clinic-probe` tells the truth. A flow that expects `allow`
from that machine would go BROKEN and expose it, but the printer has none (it only
receives, A04). The real fix would be a "source can send at all" control: before trusting a
deny from machine X, probe something X is known to reach.

**Exercise 4.5.** Verified.

```
./lab test --expect-violations   exit=0   22/61 match policy: 38 violations, 1 broken (R01), 0 errors
./lab test                       exit=1   (same numbers; sweep: 985 holes)
./lab attack --fast              exit=1   Blocked 0 of 13 paths. Patient records: 0 of 12 intact, 12 encrypted.
```

`--expect-violations` inverts the meaning: success means the violations and broken flows
are exactly the policy's `flat_known` list (38 and 1) with no errors. If the suite stopped
catching one of them, or caught a new one, the check fails. The sweep reports its holes (985
of 1344 probes got through, there is no firewall inside the flat network) but does not judge
them there. Together with `attack` exiting 1 on the flat network, this is what CI checks to
make sure the tests are capable of failing. R01 is BROKEN there (no VPN exists in the flat
network, so a flow marked `allow` fails).

**Exercise 4.6.** Verified.

```
port 3306:  HOLE      guest-laptop -> emr:3306/tcp
            Default-deny sweep: 1344 ports tried, 1 holes, 0 errors
            61/61 flows match policy  (0 violations, 0 broken, 0 errors)     exit=1
port 6000:  Default-deny sweep: 1344 ports tried, 0 holes, 0 errors
            61/61 flows match policy                                        exit=0
```

The headline "61/61 flows match policy" is still green with the hole in: no flow in the table
mentions 3306. Only the sweep sees it, and the exit code is 1. A refused connection
(`nc: Connection refused`) counts as getting through, so the hole shows even though nothing
listens. Check the `HOLE` lines or the exit code, not just the headline. Port 6000 is not in the
sweep's list, so the hole is invisible, and the exit code is 0. The sweep is a sample, not a
proof. Its port list is under `sweep:` in `policy/clinic.yml`.

</details>
