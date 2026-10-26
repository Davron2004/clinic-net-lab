# 08. The clinic map and the demo: where the data comes from

Goal: know exactly which file feeds which part of the demo, and what the ransomware scenario
does step by step. The map's user interface is built separately. This page describes the data
only.

## 1. Concept bridge

| Idea | Software idea you know | Where the analogy breaks |
|---|---|---|
| The three feeds | Three append-only log files that a UI tails. An event-sourcing setup with files instead of a broker. | There is no schema registry. The "contract" is a list of field names (below). |
| `run/events.jsonl` | An application event stream the lab itself writes. | It is written by test code, not by the network. It states what the test *saw*. |
| `run/logs/firewall.jsonl` | Access logs from the gateway. | It is written by the kernel's firewall, so it is the evidence of what really crossed zones. |
| `run/alerts.jsonl` | The alerting system's output (PagerDuty's feed). | Already filtered: level 7 and up, deduplicated. |

The point of having three feeds: the map can show *what was attempted* (events), *what the
firewall decided and why* (firewall log), and *what the security system thought of it* (alerts).

## 2. Data flow

```
 ./lab test, ./lab attack, labkit/traffic.py
        │  lab.emit(...)                                   labkit/lab.py
        ▼
   run/events.jsonl ────────────────────────────┐
                                                │
 router firewall (nft log → ulogd)              ▼
        │                                   the clinic map
        ▼                                  (reads all three files)
   run/logs/firewall.jsonl ─────────────────────┤
        │ router's Wazuh agent                  │
        ▼                                       │
   siem (Wazuh) ── custom-clinic.py ──► run/alerts.jsonl
```

All three are plain files in `run/` (git-ignored, emptied by every `./lab up`).

### `run/events.jsonl` (written by `labkit.lab.emit`)

| `type` | When | Main fields |
|---|---|---|
| `probe` | One attempt at a flow | `source` (`test`, `attack`, `traffic`), `from`, `to`, `port`, `probe`, `dst_ip`, `expect`, `observed`, `pass`, `what`, `id` (tests only) |
| `test-start`, `test-end` | A test run | `variant`, `total`; at the end `started`, `ruleset`, `passed`, `violations`, `broken`, `errors`, and `sweep` (probes, holes, errors) after a full run |
| `scenario-start`, `scenario-end` | The attack | `name`, `node`, `variant`; at the end `blocked`, `attempts`, `breaches`, `encrypted`, `errors`, `records` |
| `integrity` | Before and after the attack | `node`, `phase`, `total`, `intact`, `changed`, `missing`, `added` |
| `encrypt` | One file encrypted | `node`, `file`, `count` |

### `run/logs/firewall.jsonl`

One JSON object per logged packet (stage 03). Fields the map uses: `oob.prefix`
(`allow:<rule>` or `deny:<rule>`), `src_ip`, `dest_ip`, `dest_port`, `ip.protocol`, `oob.in`,
`oob.out`, `timestamp`. Only new connections are logged.

### `run/alerts.jsonl`

One alert per line (stage 07): `ts`, `level`, `rule_id`, `title` (plain English), `node`
(machine name from the policy or null), `src_ip`, `dst_ip`, `dst_port`, `category`
(`network`, `integrity`, `other`), `source` (`wazuh`).

Other small files: `run/variant` (`clinic` or `flat`, so the map knows which picture to draw)
and `policy/clinic.yml` (zones, machines, labels and addresses for both variants).

### Routine traffic

`labkit/traffic.py` runs in its own container started by `./lab up`. Every 2.5 to 7 seconds it
performs one ordinary allowed action (the front desk opens a chart, the imaging workstation sends
a study, a guest browses) on a real machine, and writes a `probe` event with `source: "traffic"`.
Real firewall log lines are produced as well. It pauses itself while a test or the
attack runs, so their events are not mixed with it. `./lab traffic off|on` or
`CLINIC_TRAFFIC=0` controls it.

## 3. The ransomware scenario

`scenarios/ransomware.py`, run with `./lab attack` (paced, 0.6 s between steps, for watching)
or `./lab attack --fast` (tests, CI).

1. **Patient zero** is the imaging workstation, a classic way in (old Windows, vendor remote support).
2. It fingerprints the 12 synthetic patient records on the EMR (`clinic-integrity`, event
   `integrity` phase `before`).
3. It tries 13 paths, in order: the EMR's file share, web app and admin shell, the PACS admin
   API, the SMB and remote desktop ports of both staff PCs, the lab analyzer, the printer, an
   internet command-and-control server, DNS as a covert channel, and finally the PACS
   DICOM port, which is its one allowed job. Each is a `probe` event with `source: "attack"`.
4. **If the SMB port on the EMR opens**, it encrypts the records (`clinic-ransomware`: download
   each file, encrypt with a throwaway key, upload `.locked`, delete the original, leave a ransom
   note) and emits an `encrypt` event per file.
5. It fingerprints the records again (`integrity` phase `after`) and emits `scenario-end`.
   The exit code is 0 (contained) only if nothing got through, nothing was encrypted, every
   attempt got a real answer and the one allowed path still worked. 1 means breached, 2 means
   the scenario could not tell (an error). The outcome is also written to `run/results/attack.json`.

| | Segmented clinic | Flat network |
|---|---|---|
| Paths blocked | 12 of 13 (the 13th is allowed) | 0 of 13 |
| Records encrypted | 0, 12 of 12 intact | 12 of 12 |
| Firewall log | `deny:devices` (many), `deny:device-internet`, `allow:imaging-pacs-dicom` | nothing (the router is never involved) |
| Alerts | network: 100110, 100120 | integrity: 100202, 100201, 100210; no network alerts |
| Exit code | 0 (contained) | 1 (breached) |

## 4. Break it

**Exercise 8.1. Watch the stream.**
In a terminal on the host: `tail -f run/events.jsonl`. In another: `./lab test --only A01,D01`.
Predict the event types and their order.

**Exercise 8.2. Events vs the firewall log.**
Note the line counts of `run/events.jsonl` and `run/logs/firewall.jsonl`. Run
`./lab attack --fast`. Predict how many `probe` events with `source: "attack"` there are
and how many firewall log lines the attack produced. Group the log lines by `oob.prefix`.

**Exercise 8.3. The map's "alive" feeling.**
`./lab traffic on`. After 25 seconds, count new events by `type` and `source`. Then run
`./lab test` and count the events during the run. Predict both. `./lab traffic off` afterwards.

**Exercise 8.4. Replay the flat network.**
`./lab up flat`, `./lab attack --fast`, read `run/events.jsonl`. Which events say how much
damage was done, and which field tells the map which picture to show?
Undo: `./lab up`.

## 5. Questions you should be able to answer

1. Where does the map get "what was attempted", "what the firewall decided" and "what the security system thought"?
2. Why does the scenario's last attempt (PACS DICOM port) succeed on purpose?
3. How do you know the ransomware was contained, and how do you know it was *noticed*? Which files prove each?
4. Why does the routine traffic pause during a test?
5. What does the attack do differently on the flat network, and why does the exit code differ?

<details><summary>Answers</summary>

**Exercise 8.1.** Verified. Four events, in this order:

```
test-start   {"variant":"clinic","total":2}
probe        source test, id A01, reception-pc -> emr:443, expect allow, observed allow, pass true
probe        source test, id D01, guest-laptop -> emr:443, expect deny, observed deny, pass true
test-end     {"ruleset":"<12 hex chars>","passed":2,"violations":[],"broken":[],"errors":[]}
```

The probes arrive as they finish, not in the order of the policy file (the suite runs
12 at a time). A01 comes first here because the allowed probe finished fast. D01 takes the
full 3-second timeout, since a blocked connection never answers.

**Exercise 8.2.** Verified. 13 `probe` events with `source: attack`, plus `scenario-start`, two
`integrity` events and `scenario-end` (17 lines in total). The firewall log has more lines than
there were attempts: 22 in the run I did.

```
18  deny:devices            10.10.30.10   <- the 10 blocked attempts to other machines, with retransmitted SYNs
 2  deny:device-internet    10.10.30.10   <- the command-and-control attempt (its SYN sent twice)
 1  deny:to-router          10.10.30.10   <- the DNS query: it is addressed to the router itself
 1  allow:imaging-pacs-dicom 10.10.30.10  <- the one allowed job
```

(The exact counts vary by a few lines with retransmissions.)
Events say what the test code tried and what it concluded. The log says what the kernel did, packet
by packet. One attempt can be several log lines. The events are in finishing order, not
the order of the list, because the attempts run in threads.

**Exercise 8.3.** Verified.

```
traffic on, 25 s:      about 5 events, all probe / source traffic (one every 2.5 to 7 s)
./lab test:            61 probe events (source test) + test-start + test-end, none from traffic
```

The test and the attack drop a flag file in `run/` and wait until the generator confirms it has
paused and finished anything in flight (`lab.quiet_traffic`). The generator starts nothing while a
flag exists. That keeps test results clean and keeps the map's replay of them honest. The
cost: while a test runs, the map shows no "normal day" traffic.

**Exercise 8.4.** On the flat network `scenario-end` reads
`"blocked":0,"attempts":13,"breaches":12,"encrypted":12`, and the `integrity` event with
`phase: "after"` says `"intact":0,"missing":12,"added":13` (12 originals gone, 12 `.locked`
files and 1 ransom note added). There are 12 `encrypt` events. `scenario-start` has
`"variant":"flat"`, and `run/variant` contains `flat`, which is how the map knows to draw the
single-network picture.

</details>
