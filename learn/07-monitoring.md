# 07. Monitoring: the SIEM, the agents and the alerts

Goal: explain what a SIEM does, what the two agents watch, what each alert in this lab
means, why most events are deliberately hidden (alert fatigue), and where the monitoring
is blind.

Use the segmented clinic: `./lab up`, then `./lab traffic off`. The first `./lab up` pulls
the Wazuh image (about 2.7 GB). `CLINIC_MONITORING=0 ./lab up` runs without it.

## 1. Concept bridge

| Security idea | Software idea you know | Where the analogy breaks |
|---|---|---|
| SIEM (security information and event management) | Log aggregation plus alerting: Datadog or Sentry for security events. Collect from many machines, normalise, apply rules, notify. | Its rules look for *bad behaviour*, not errors. Nobody has written the bug yet. |
| Wazuh manager | The backend: receives events, runs rules, writes alerts. Runs on the `siem` machine. | |
| Agent | A log shipper / sidecar (Fluent Bit, Datadog agent) installed on a machine. Here on `router` and `emr`. | An agent on a machine an attacker controls can be stopped by the attacker. |
| Decoder and rule | A parser plus an alert definition. A rule says "if an event has these fields, raise this alert at this level". | Rules can build on other rules (`if_sid`) and count (`frequency` in a `timeframe`), like a rate-limit check. |
| Level (0 to 15) | Log severity. | Here it is also a policy: below 3 ignored, 3 to 6 recorded only, 7 and up shown to people. |
| FIM (file integrity monitoring) | A checksum watcher on a folder: "tell me when a file changes". Like a git status on `/srv/emr/records` that never sleeps. | It sees that a file changed, not who or why. A legitimate edit looks the same. |
| Alert fatigue | Pager noise. If the pager goes off 50 times a day, on-call mutes it, and misses the real one. | The security cost is worse: the one event that mattered was in the noise. |
| Log retention | A retention policy on logs: how long, where, who can delete. | The evidence must outlive the machine that produced it, or an attacker deletes it first. |

### What the SIEM sees in this lab

```
 router ── firewall.jsonl (every logged packet) ──► agent ─┐   TCP 1514, encrypted
 emr    ── /srv/emr/records/ file changes (FIM)  ──► agent ─┤   (enrol: TCP 1515 + password)
                                                            ▼
                                                  siem (Wazuh manager)
                                       rules (clinic_rules.xml) → alerts.json  (level 3 and up: the record)
                                                            │ level 7 and up
                                              custom-clinic.py → run/alerts.jsonl → the clinic map
```

Only two sources are connected, on purpose: the firewall log (what crossed zones) and the
patient records folder. A SIEM that collects everything buries the two things that matter.

## 2. The rules, in plain words

All in `images/siem/wazuh/etc/rules/clinic_rules.xml`. IDs starting `100` are local rules.

| Rule | Level | When it fires | What it means |
|---|---|---|---|
| 100100 / 100101 | 0 | Any firewall event / an allowed connection | Normal work. Counted, never shown. |
| 100102 | 3 | Any blocked connection | Recorded in `alerts.json`, never shown. One block means little. |
| 100103 | 0 | Blocked connection from the internet (`deny:inbound`) | Background noise. Every public address gets it. |
| 100110 | 12 | `deny:device-internet`: a medical device tried to leave | Infected, or set up to phone home. Devices have no reason to use the internet. |
| 100111 | 12 | `deny:server-internet`: a server tried to leave | Could be data theft. |
| 100112 | 5 | `deny:printer-internet` | Printers phone home for updates all day. Recorded, not shown. |
| 100120 | 12 | 10 blocked connections from one `10.10.x.x` address in 30 s | A machine probing the network: ransomware looking for its next target. |
| 100200 | 12 | A patient record modified | Records are written by the EMR app, so any other change is a mistake or an attack. |
| 100201 | 12 | A patient record deleted | Same. |
| 100202 | 9 | A new file in the records folder | A new chart, or a ransom note. |
| 100210 | 15 | 5 or more record events within 60 s | What ransomware encrypting a folder looks like. Raised at most once a minute. |
| 100300 | 9 | An agent stopped or went silent for a minute | A blind spot: the SIEM can no longer see that machine. |

Plus the integration `custom-clinic.py`: for every alert at level 7 or more, it writes one line to
`run/alerts.jsonl` with a plain-English title (machine names from `policy/clinic.yml`),
the firewall's own timestamp, and a category. **It drops a repeat of the same alert for the same
machines within 15 seconds**, since one blocked connection produces several packets. `alerts.json`
keeps every one.

### Retention

The lab keeps what Wazuh keeps (`alerts.json` in the `siem` container) and what the host
files hold (`run/logs/firewall.jsonl`, `run/alerts.jsonl`). `./lab up` empties `run/` and
rebuilds the containers, so nothing lives longer than a deployment. That suits a lab, not a
clinic. A real clinic decides: how many months (the privacy commissioner's guidance expects network logs to be
available for analysis after a breach, see `docs/phipa.md`), where (off the machines that produce
them, with write access closed to anyone who might be the attacker), and who may delete.

## 3. Where it lives in the lab

| What | File |
|---|---|
| Manager config (levels, integration, what is off) | `images/siem/wazuh/etc/ossec.conf` |
| Our rules | `images/siem/wazuh/etc/rules/clinic_rules.xml` |
| Alert to map line | `images/siem/wazuh/integrations/custom-clinic.py` |
| Agent: shared settings | `images/agent/rootfs/etc/clinic/wazuh-agent/common.xml` |
| Agent: watch the records / ship the firewall log | `.../emr.xml`, `.../router.xml` |
| Agent boot | `images/agent/rootfs/usr/local/bin/clinic-svc-wazuh-agent` |
| Firewall rules that feed it | `nftables.nft` prefixes: `deny:device-internet`, `deny:server-internet`, ... |
| Policy tests | `policy/clinic.yml`: S01 to S08 (the agents may talk to the SIEM, nobody else) |

Commands:

```bash
./lab status                                  # last line: monitoring (SIEM) ready
./lab shell siem
  /var/ossec/bin/agent_control -l             # agents: router, emr (Active)
  /var/ossec/bin/wazuh-control status | grep running
  tail -n 3 /var/ossec/logs/alerts/alerts.json     # the record
tail -f run/alerts.jsonl                      # on the host: what the map receives
./lab shell emr
  clinic-integrity                            # sha256 check of the records against the boot-time list
```

A quick way to read the alert file on the host:

```bash
python3 - <<'EOF'
import json
for line in open('run/alerts.jsonl'):
    d = json.loads(line); print(d['level'], d['rule_id'], d['node'], d['title'])
EOF
```

## 4. Break it

Wait about 20 seconds between exercises so the 15-second repeat filter and the "10 in 30
seconds" counter do not mix them up. Note the line count of `run/alerts.jsonl` before each
(`wc -l`) and read the new lines after.

**Exercise 7.1. One blocked packet, and one that matters.**
In `guest-laptop`: `nc -zv -w 2 10.10.20.10 443`. Then in `imaging`:
`curl -sk -m 3 -o /dev/null https://203.0.113.10/`. Predict what each puts into
`run/alerts.jsonl`. Then compare the number of lines added to
`/var/ossec/logs/alerts/alerts.json` in the `siem` container (`wc -l` before and after).

**Exercise 7.2. Behave like a scanner.**
In `guest-laptop` run:

```bash
for p in 21 22 23 25 80 110 135 139 445 1433 3306 3389; do nc -z -w 1 10.10.20.10 $p; done
```

Predict the alert: rule, level, and which `node` it names. Why that node?

**Exercise 7.3. Tamper with a patient record.**
In `emr`, make a backup, wait a minute (so the "5 in 60 s" counter is empty), then edit files:

```bash
cp -a /srv/emr/records /root/records.bak
cd /srv/emr/records
for i in 1 2 3 4 5 6; do echo x >> patient-000$i.json; sleep 1; done
clinic-integrity
```

Predict the alerts: which rules, and what is special about the fifth change?
Undo: `cp /root/records.bak/* /srv/emr/records/` and check with `clinic-integrity`.

**Exercise 7.4. Blind the agent.**
In `emr`: `/var/ossec/bin/wazuh-control stop`. After 15 seconds read the new alerts and run
`agent_control -l` in `siem`. Then, with the agent still stopped, change a record
(`echo x >> /srv/emr/records/patient-0007.json`) and start the agent
(`/var/ossec/bin/wazuh-control start`). Wait about 80 seconds. Predict what the SIEM says
about the change. Undo: restore the file from the backup of 7.3 (or `./lab up`).

**Exercise 7.5. The same attack on both networks.**
Run `./lab attack --fast` on the segmented clinic, wait 10 seconds, read `run/alerts.jsonl`.
Then `./lab up flat`, `./lab attack --fast`, wait 10 seconds, read it again. Predict, for each
network, which kinds of alerts (network or integrity) appear, and how the SIEM's view
differs from the test suite's (stage 04). Undo: `./lab up`.

## 5. Questions you should be able to answer

1. What is a SIEM? What does an agent do and what does the manager do? What two sources feed it here, and why not more?
2. Why are most firewall blocks hidden? What would happen to the person watching if they were all shown?
3. Explain rule 100120. Why does it name a *source* machine and not a destination? Why 10 in 30 seconds?
4. What is FIM, and what is rule 100210 detecting? Why can it fire on the fifth change and not the first?
5. If an attacker with admin rights stops the agent on the EMR, what does the SIEM show, and what does it not show?
6. What would be wrong with keeping logs only on the machine that produced them?
7. Does the SIEM replace the firewall? Does the firewall make the SIEM unnecessary? (Use exercise 7.5.)

<details><summary>Answers</summary>

**Exercise 7.1.** Verified.

```
guest probe to the EMR (blocked):  alerts.jsonl: +0 lines.  alerts.json: +2 lines, rule 100102 level 3
                                   ("Firewall blocked 10.10.50.118 from reaching 10.10.20.10:443")
imaging to the internet:           alerts.jsonl: +1 line
  12 100110 "Imaging workstation tried to reach the internet (medical devices never should)"
```

The guest block is recorded twice (two SYN packets) and shown to nobody. The imaging line has
a human title: the integration replaced `10.10.30.10` with the machine's name from the policy.
The first blocked connection does nothing visible; the pattern or the *kind* of block does.

**Exercise 7.2.** Verified. One alert, no more:

```
12 100120 "Guest Wi-Fi device 10.10.50.118 was blocked 10 times in 30 seconds: scanning the network or malware spreading"
node: null
```

`node` is null because a DHCP guest is not a named machine in the policy; the title uses
the zone's label instead. The rule counts blocked events per *source address*: a scan hits many
targets or ports, so the thing that repeats is the attacker, not the victim. The threshold
10 in 30 s sits above what a healthy machine does. A mis-set application retries a few times.
(In the lab, a *single* blocked `nc -w 8` already produced 7 log lines, stage 03; so retries
are not free.) Careful: because the test suite itself runs forbidden probes from machines like
`imaging`, a `./lab test` makes `100110` and sometimes `100120` fire for real. In
the logs, a test run looks like a small attack.

**Exercise 7.3.** Verified.

```
12 100200 Patient record modified: /srv/emr/records/patient-0001.json
12 100200 ... patient-0002.json
12 100200 ... patient-0003.json
12 100200 ... patient-0004.json
15 100210 Many patient records changed within a minute: looks like ransomware     <- 5th change
12 100200 ... patient-0006.json
```

The fifth change shows up as 100210 *instead of* its own 100200 alert (that is how Wazuh
frequency rules work, and the comment in `clinic_rules.xml` says so). `clinic-integrity`
reports `"intact":6,"changed":6`. It is an independent check on the same question, using
plain `sha256sum` and no agent, so it does not depend on Wazuh. The alerts arrive within about
a second, since the folder is watched in real time (inotify), not by a nightly scan.

**Exercise 7.4.** Verified.

```
9 100300 emr  "EMR server: security agent stopped reporting (the SIEM is blind on this machine)"
agent_control -l:  ID: 002, Name: emr, IP: any, Disconnected
change a record while the agent is stopped, then start it:  no alert at all (80 seconds waited)
```

The stop is noticed at once, and a person is told. But the change made while the agent was
down is **never reported**: when the agent starts, it rebuilds its baseline from the folder as it
is now, so the tampered file becomes "normal". (Observed: no alert after 80 s. The agent's
log shows the start-up scan finishing within a second. I did not verify the internal reason.)
The blind window is a real hole. Two mitigations: treat 100300 as "go and look at the records
now" (run `clinic-integrity`, which compares against the list made at boot), and keep the
baseline off the machine. Note the stop required root on the EMR: an attacker who already has
root there is also past the network controls, which is why the network layers exist.

**Exercise 7.5.** Verified.

```
segmented clinic:  Blocked 12 of 13 paths. Patient records: 12 of 12 intact.
  alerts: 12 100110 Imaging workstation tried to reach the internet
          12 100120 Imaging workstation was blocked 10 times in 30 seconds: scanning the network or malware spreading
flat network:      Blocked 0 of 13 paths. 12 of 12 encrypted.
  alerts: 100202 / 100201 for each file (new .locked file, original deleted), then
          15 100210 Many patient records changed within a minute: looks like ransomware
          9 100202 New file in the patient records folder: .../README-RESTORE-FILES.txt
          (no network alerts at all)
```

On the segmented network the firewall stops the attack and the SIEM *tells you someone
tried*. On the flat network the traffic never touches the router, so the firewall log is
empty, and only the host-based file monitor on the EMR notices, after the damage has started
(all 12 files were gone within about a second). That is the argument for both: segmentation
prevents, monitoring detects, and each covers the other's blind spot. The suite in stage 04
shows the network was contained, the SIEM shows that someone knew.

</details>
