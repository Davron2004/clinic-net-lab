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
| PASS / VIOLATION / BROKEN | A forbidden thing worked (security bug) vs. a required thing did not (outage). They are different failures. | A plain "FAIL" would hide which one it is. |
| Positive control, "(no listener)" | In a test that asserts "this call is rejected", also check the happy path exists. Otherwise the test passes when the service is simply down. | The control asks the target machine itself ("do you answer on this port, locally?"). It does not prove the packet could have got there. |
| `--expect-violations` on the flat network | Mutation testing: break the code on purpose and check that the tests notice. | Here we do not mutate the firewall, we use a network that is known to be bad. |
| CI | Same as any CI: rebuild from scratch on every change. | It builds a virtual network, so it needs kernel modules (stage 00). |

## 2. How the suite works

For every flow in `policy/clinic.yml` (`tests/isolation.py`, function `probe`):

1. Find the source machine's container and the target's address (from DHCP for guests).
2. `docker exec` into the source and run `clinic-probe <kind> <ip> <port> 3`. The kinds are in
   `images/node/rootfs/usr/local/bin/clinic-probe*`.
<!-- REVERIFY (main fix 5): probe results become three-state (allow/deny/error) and errors fail the run. Update this step, the PASS/VIOLATION/BROKEN table row, and Exercise 4.4 (a probe that always exits 1 may now be an error, not a deny). -->
3. Exit code 0 means `observed: allow`. Anything else means `observed: deny`.
4. Compare with `expect:`. `pass` is `observed == expect`.

| Probe | What it proves when it succeeds |
|---|---|
| `tcp` | A TCP connection opens. (`nc -z`.) |
| `https` | An HTTPS page loads. |
| `dns` | The DNS server answers a lookup. |
| `dicom` | A real DICOM service answers a C-ECHO (stage 05). More than an open port. |
| `hl7` | An HL7 receiver acknowledges a message with `MSA\|AA` (stage 05). |
| `pacs-web` | The image archive answers with its login prompt (Orthanc's `401`). The network let us reach it. The password is a second lock. |
| `reach` | The TCP packet got an answer, even a refusal. Used for the SIEM so tests pass while Wazuh is still starting. |
| `https-direct` / `https-vpn` | HTTPS forced out of the cable / forced into the VPN tunnel (stage 06). |

Details that matter:

- **Retry asymmetry.** An allowed flow that fails once is retried once (a first packet can be
  slow). A forbidden flow is never retried, because getting through even once is a finding.
- **Controls.** For every blocked flow, the suite then runs the same probe from the *target*
  machine to itself (`control()`). If the service does not answer there either, the result
  is marked "(no listener)" in the report: the block may not be the real reason.
- **Fingerprint.** `ruleset` is the first 12 characters of a SHA-256 of `nft list ruleset`.
  It says which firewall was tested. Two reports with different fingerprints tested different rules.
- **Parallel.** 12 probes at a time. Routine traffic (`labkit/traffic.py`) pauses itself
  while a test runs (it watches `test-start` / `test-end` in `run/events.jsonl`).
- **Outputs.** `run/results/latest.json`, `run/results/report.md`, and one event per probe
  in `run/events.jsonl` (which the clinic map follows).

### What "green" means

A fully green run means: *for each of the specific flows in the table, a real packet from the real source
behaved as the policy says, on this firewall, at this moment.* It does not mean "the
network is secure". It does not cover:

- Anything not in the table: other ports, UDP in general, IPv6, other source machines, spoofed source addresses (stage 03, exercise 3.6).
- Weaknesses behind an allowed port (the EMR web app has a bug, the file share is open to guests).
- Machines being compromised in ways that need no network (a USB stick).
- Timing: a flow might work only for the first minute, or only under load.
- The NAT rule (stage 03, exercise 3.4): the simulated internet routes private addresses, so removing masquerade breaks nothing.

### CI (`.github/workflows/ci.yml`)

```
lint (shellcheck, ruff)
./lab up              ->  ./lab test                      must be fully green
                      ->  ./lab attack --fast             must be contained, exit 0
./lab up flat         ->  ./lab test --expect-violations  must catch violations
                      ->  ./lab attack --fast             must NOT be contained (exit 1)
```

The last two steps test the tests: if the flat network ever "passed", the suite would be broken.

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
less run/results/report.md                   # the table, with "(no listener)" notes
python3 -m json.tool run/results/latest.json | less   # includes "service_up" per blocked flow
tail -f run/events.jsonl                     # what the map receives
```

## 4. Break it

**Exercise 4.1. Make a "pass" for the wrong reason.**
Stop the EMR's web server: `pkill -f clinic-emr-web` in `./lab shell emr`. Then run
`./lab test --only A01,D01,D21,D22` and read both the terminal output and `run/results/report.md`.
Predict which flows pass and what differs between the two outputs.
Undo: `docker exec -d clab-clinic-emr clinic-emr-web` from the host (or `./lab up`).

**Exercise 4.2. A typo in the policy.**
Edit `policy/clinic.yml` and change D01's `port: 443` to `port: 4443`. Run
`./lab test --only D01`. Predict the verdict, then check the report.
Undo: `git checkout policy/clinic.yml`.

**Exercise 4.3. A hole outside the matrix.**
Run `./lab test --only A01` and note the `ruleset` value in `run/results/latest.json`. Then:

```bash
# in ./lab shell emr: a UDP listener that writes what it receives
(timeout 120 nc -u -l -p 5353 > /tmp/udp.txt &)
# in ./lab shell router: open a hole from the guest zone
nft insert rule inet clinic from_guest ip daddr 10.10.20.10 udp dport 5353 accept
```

Run the full `./lab test`. Predict the result and the fingerprint. Then in
`./lab shell guest-laptop` run `echo hello | nc -u -w1 10.10.20.10 5353` and look at
`/tmp/udp.txt` on the EMR.
Undo: `nft -f /etc/clinic/router/nftables.nft` on the router.

<!-- REVERIFY (main fix 5): with three-state probes, a broken probe tool may now produce errors that fail the run. Re-run and rewrite prediction/answer. -->
**Exercise 4.4. Break the tester, not the network.**
In `./lab shell printer` break the probe tool:

```bash
mv /usr/local/bin/clinic-probe /usr/local/bin/clinic-probe.orig
printf '#!/bin/bash\nexit 1\n' > /usr/local/bin/clinic-probe; chmod +x /usr/local/bin/clinic-probe
```

Run `./lab test --only A04,D14,D15,D16`. D14 and D15 start from the printer. Predict.
Undo: `mv /usr/local/bin/clinic-probe.orig /usr/local/bin/clinic-probe`.

**Exercise 4.5. See the suite catch the flat network.**
`./lab up flat`, then `./lab test --expect-violations; echo "exit=$?"`, then
`./lab test; echo "exit=$?"`, then `./lab attack --fast; echo "exit=$?"`. Predict all three exit codes
and the headline numbers. Undo: `./lab up`.

## 5. Questions you should be able to answer

1. Why is the policy file separate from the firewall config? What mistake does this catch, and what mistake does it not?
2. What is the difference between VIOLATION and BROKEN? Which one is worse for a clinic, and why must the report separate them?
3. What is a positive control and why does a blocked flow need one?
4. A security reviewer says "a timeout does not prove a firewall block". Do you agree? What does the suite do about it, and what does it not do?
5. Every flow in the report passes. What can you claim, and what can't you claim?
6. Why does CI also run the suite against the flat network and expect it to fail?
7. Why are forbidden flows never retried, while allowed flows get one retry?

<details><summary>Answers</summary>

**Exercise 4.1.** Verified.

```
terminal:   BROKEN A01   PASS D01   PASS D21   PASS D22     3/4 flows match policy (1 broken)
report.md:  | D01 | PASS | ... | deny | deny (no listener) |
            | D21 | PASS | ... | deny | deny (no listener) |
latest.json: "service_up": false for A01, D01, D21, D22
```

A01 is broken, correctly: the front desk really cannot open the EMR now. D01 and D21 still
pass, because "blocked" and "nobody is home" look the same from outside. The terminal view
hides that; `report.md` and `latest.json` carry the "(no listener)" mark. Take away: a
block is only proven if the service is up behind it. If the firewall rule were broken
as well, these tests would not tell you until the service came back. (Observation about the
lab: the terminal summary prints PASS for these. If you present results, show `report.md`.)

**Exercise 4.2.** Verified. D01 reports `PASS ... guest-laptop -> emr:4443` and the report
says `deny (no listener)`. Nothing listens on 4443, so the guest is trivially "blocked".
The test checks something that was never allowed to work. The typo is only visible in the
"(no listener)" note and the port number. Mistyped `deny` tests are silent, mistyped `allow`
tests are loud (they go BROKEN). That asymmetry is why the controls exist.

**Exercise 4.3.** Verified.

```
./lab test   ->   all flows match policy  (0 violations, 0 broken)
fingerprint: aa0f63a95d20 (clean)  ->  4ffacbaf5c9b (with the hole)  ->  aa0f63a95d20 (after reload)
/tmp/udp.txt on the EMR:  hello-from-guest      (before the hole it was empty)
```

The guest zone now reaches the EMR over UDP, and the suite is fully green, because no
flow in the table uses UDP to the EMR. A green suite proves the listed flows, nothing
else. The fingerprint is the only signal: it changed. A review process that compares the
fingerprint to the one that was approved would catch this. So would an extra sweep test
("from every zone, nothing may reach the EMR except the allowed ports"), which is not
in the suite yet. The inserted rule also has no `log` clause, so it leaves no trace in the firewall log.

**Exercise 4.4.** Verified.

```
PASS  A04  reception-pc -> printer:9100
PASS  D14  printer -> internet:443       deny
PASS  D15  printer -> reception-pc:445   deny
PASS  D16  emr -> internet:443
4/4 flows match policy
```

D14 and D15 pass vacuously: the printer's probe tool always says "no", which reads as
"blocked". The controls only check the target side. A source machine that cannot send at all
passes every forbidden flow it starts. A flow that expects `allow` from that machine would
go BROKEN and expose it, but the printer has none (it only receives, A04), and neither does
the internet node. A "source can send at all" control is the missing piece. The real fix:
before trusting a deny from machine X, probe something X is known to reach.

**Exercise 4.5.** Verified.

```
./lab test --expect-violations   exit=0   many violations, 1 broken (R01)
./lab test                       exit=1   (same numbers, but "success" now means every flow matches)
./lab attack --fast              exit=1   Blocked 0 of 13 paths. Patient records: 0 of 12 intact, 12 encrypted.
```

`--expect-violations` inverts the meaning: success means the suite saw at least one
violation. Together with `attack` exiting 1 on the flat network, this is what CI checks
to make sure the tests are capable of failing. R01 is BROKEN there (no VPN exists in the flat
network, so a flow marked `allow` fails).

</details>
