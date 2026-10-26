# 05. Medical traffic: DICOM and HL7

Goal: explain what the two medical protocols in this lab are, what they look like on the
wire, why they are unauthenticated and unencrypted, and why the machines that speak them are
fenced in.

Use the segmented clinic: `./lab up`, then `./lab traffic off`.
All patients, images and results are synthetic.

## 1. Concept bridge

| Medical / protocol idea | Software idea you know | Where the analogy breaks |
|---|---|---|
| DICOM | Two things with one name: a file format for images (pixels plus a bag of typed metadata) and a network protocol to move them. | The protocol is binary and stateful, with its own connection handshake on top of TCP. It is not HTTP. |
| Modality | An IoT client: an X-ray or ultrasound machine that produces images. In the lab, `imaging`. | It is a full PC (often old Windows) wired to a scanner, so it is also a computer that gets infected. |
| PACS | Blob storage plus an index (S3 plus a database) for images. Here, Orthanc. | It must keep every study for years and answer queries from doctors' viewers. |
| Association | A session: connect, say who you are, agree what you can exchange, then send requests. Like a TLS handshake plus capability negotiation, without the encryption. | After the association, requests are cheap, so one association can carry many images. |
| AE title (Application Entity title) | A client ID or service name (max 16 characters): "I am IMAGING, I am calling PACS". | It is not authentication. Anyone can claim any calling AE title (exercise 5.1). The *called* title is only a name check. |
| Presentation context | Content-type negotiation: "I want to send CR images, in this encoding." | The server can refuse a type it does not support. |
| C-ECHO | `GET /health`. DICOM's ping. | It proves a real DICOM service answered, which an open TCP port alone does not. |
| C-STORE | `POST /images`. "Store this image." | It returns a status code. `0x0000` is success. |
| HL7 v2 | A 1990s message format: plain text, one record per line, fields split by `\|`. A flat, positional CSV-with-types, not JSON. | Meaning depends on position (field 5 of PID is the name). Both sides must agree on the version and local conventions. |
| `ORU^R01` | An event type name, like `lab.result.created`. `ORU` is "observation result", `R01` is the trigger (an unsolicited result). | |
| MLLP | A framing layer. TCP is a stream of bytes with no message boundaries, so the sender wraps each message in start/end bytes. Like newline-delimited JSON, but with `0x0B ... 0x1C 0x0D`. | A receiver must handle half a message in one read and two messages in another (`clinic-hl7` does). |
| ACK / `MSA\|AA` | An application-level response: `200 OK` plus a correlation ID. `AA` accepted, `AE` application error, `AR` rejected. | A TCP-level success is not an ACK. A sender has to read the `MSA` code and check it carries the original message's control ID. |
| Control ID (MSH-10) | Idempotency / correlation key. | |

### Why the imaging devices are old and unpatched

- They are expensive (tens to hundreds of thousands of dollars) and last 10 to 15 years. The
  software on the attached PC is often from the day the scanner was installed.
- The vendor validates the whole system as a medical device. Patching Windows, or installing
  antivirus, can invalidate that or void support. Often the clinic is not allowed to change it.
- Vendors often keep remote-access tools on them for support.
- So the PC is old and cannot be fixed. The only control left is the network: put it in its own
  zone, let it do exactly one job (send to PACS), give it no internet, no DNS, no way to reach
  other devices. This is what stages 02 and 03 do. It is the clinic version of "if you cannot
  patch it, isolate it".

### Why the protocols are open, and what that means

Neither DICOM nor HL7 v2 over MLLP has encryption or real authentication by default. They
were designed for closed hospital networks. Anyone who can reach the port can send a
message, and anyone on the path can read it (exercise 5.3). The network is the access control.
That is the reason for D24 to D28 in `policy/clinic.yml`: **each medical protocol only
between the machines that need it**. If the guest Wi-Fi could reach 2575, it could inject
fake lab results.

## 2. What the protocols look like

### DICOM: one image sent by the imaging workstation

```
imaging                                           PACS (AE title "PACS", TCP 4242)
   │ ── TCP connect ───────────────────────────────►│
   │ ── A-ASSOCIATE-RQ  calling "IMAGING"           │
   │                    called  "PACS"              │  (called title must match: Orthanc checks it)
   │                    contexts: CR image storage  │
   │ ◄─ A-ASSOCIATE-AC  (accepted)                  │
   │ ── C-STORE  (the image: patient, study, pixels)│
   │ ◄─ C-STORE response, status 0x0000             │
   │ ── A-RELEASE ─────────────────────────────────►│
```

`clinic-dicom send` makes a synthetic study (generated pixels, one of the lab's invented
patients) and does exactly this with the `pynetdicom` library. `clinic-dicom echo` does the
same with a C-ECHO. The PACS is Orthanc (`images/pacs`), with AE title `PACS`, port 4242
(DICOM) and 8042 (web viewer and REST API, login required).

### HL7: one lab result sent by the analyzer

On the wire it is plain text. This is a real message the lab produced, with `\r` shown as new lines:

```
<0x0B>MSH|^~\&|ANALYZER|CLINIC-LAB|EMR|CLINIC|20261026222411||ORU^R01^ORU_R01|LAB038302822|P|2.5.1
PID|1||SYN-100001^^^CLINIC^MR||Holt^Avery||19610412
OBR|1||LAB038302822|51990-0^Basic metabolic panel^LN|||20261026222411|||||||||||||||20261026222411|||F
OBX|1|NM|2823-3^Potassium^LN||4.2|mmol/L|3.5-5.1|N|||F|||20261026222411
OBX|3|NM|2160-0^Creatinine^LN||1.8|mg/dL|0.6-1.3|H|||F|||20261026222411
<0x1C><0x0D>
```

| Segment | Meaning | Notes |
|---|---|---|
| `MSH` | Header: sender, receiver, time, message type (field 9: `ORU^R01`), control ID (10), processing ID (11), version (12) | `^~\&` are the separators for components, repeats, escape, subcomponents. Processing ID `P` = production, `T` = test. |
| `PID` | Patient: ID (3), name `Last^First` (5), birth date (7) | |
| `OBR` | The order: which panel (here a basic metabolic panel, LOINC code `51990-0`) | |
| `OBX` | One result each: code, value, units, reference range, flag (`L`, `H`, `N`) | Here creatinine `1.8` is `H` (high). |

The EMR answers with an ACK in the same frame format:

```
<0x0B>MSH|^~\&|EMR|CLINIC|ANALYZER|CLINIC-LAB|20261026220249||ACK^R01^ACK|ACK742163037|P|2.5.1
MSA|AA|CTRL0001
<0x1C><0x0D>
```

`AA` plus the *original* control ID. A sender that gets `AR` (rejected) or `AE` (error) must
not assume the result was stored. The lab's isolation test (`hl7` probe) sends a **test**
message (`MSH-11 = T`). The EMR validates and acknowledges it but does not file it, as a real
interface would.

## 3. Where it lives in the lab

| What | File |
|---|---|
| DICOM sender, echo probe | `images/node/rootfs/usr/local/bin/clinic-dicom` |
| HL7 listener, sender, probe | `images/node/rootfs/usr/local/bin/clinic-hl7` (service: `clinic-svc-hl7`) |
| PACS (Orthanc) settings: AE title, called-AE check, login | `images/pacs/rootfs/usr/local/bin/clinic-svc-orthanc` |
| Synthetic patients | `images/node/rootfs/usr/local/share/clinic/patients.json` |
| Firewall rules | `nftables.nft`: `allow:imaging-pacs-dicom`, `allow:lab-emr-hl7` (chain `from_devices`) |
| Policy and tests | `policy/clinic.yml`: A05, A06, D24 to D28, probes `dicom` and `hl7` |

Commands:

```bash
./lab shell imaging
  clinic-dicom echo 10.10.20.20            # exit 0 = a DICOM service answered
  clinic-dicom send 10.10.20.20            # sends one synthetic study, prints JSON
./lab shell lab-analyzer
  clinic-hl7 send 10.10.20.10 2575         # prints {"control_id": ..., "ack": "AA"}
./lab shell emr
  tail -n 3 /srv/emr/lab-results/results.jsonl     # one JSON line per result
  ls /srv/emr/lab-results/messages                 # the raw HL7 as received
```

Reading what the PACS stored (the password is made new at every boot, never committed):

```bash
docker exec clab-clinic-pacs cat /run/clinic/pacs-credentials        # prints doctor:<password>
./lab shell doctor-pc
  curl -s -u doctor:<password> http://10.10.20.20:8042/studies            # list of study IDs
  curl -s -u doctor:<password> "http://10.10.20.20:8042/studies?expand" | grep -E 'PatientName|StudyDescription'
```

## 4. Break it

**Exercise 5.1. Names are not passwords.**
In `./lab shell imaging` save this as `ae.py` (with `cat > ae.py`):

```python
import sys
from pynetdicom import AE
from pynetdicom.sop_class import Verification
calling, called = sys.argv[1], sys.argv[2]
ae = AE(ae_title=calling)
ae.add_requested_context(Verification)
assoc = ae.associate("10.10.20.20", 4242, ae_title=called)
print("calling", calling, "called", called, "->", "ESTABLISHED" if assoc.is_established else "REFUSED")
if assoc.is_established:
    assoc.release()
```

Run `python3 ae.py IMAGING PACS`, `python3 ae.py EVIL_LAPTOP PACS` and `python3 ae.py IMAGING WRONGNAME`.
Predict all three. Then read `docker logs --tail 5 clab-clinic-pacs`. Nothing is changed.

**Exercise 5.2. Speak HL7 by hand.**
In `./lab shell lab-analyzer` run this (`\v` is 0x0B, `\034` is 0x1C, `\r` is the segment end):

```bash
send() { printf "$1" | nc -w 3 10.10.20.10 2575 | tr '\r' '\n' | cat -v; echo "[done]"; }
H='MSH|^~\\&|ANALYZER|CLINIC-LAB|EMR|CLINIC|20261026120000||'
send "\v${H}ORU^R01^ORU_R01|CTRL0001|T|2.5.1\rPID|1||SYN-100011^^^CLINIC^MR||Doe^Jane||19800101\rOBX|1|NM|718-7^Hemoglobin^LN||13.2|g/dL|12.0-17.5|N|||F\r\034\r"
send "\v${H}ADT^A01|CTRL0002|T|2.5.1\rPID|1||SYN-100011\r\034\r"
send "\v${H}ORU^R01|CTRL0003|T|2.5.1\rPID|1||SYN-100011\r\034\r"
send "\vhello\r\034\r"
send "\v${H}ORU^R01|CTRL0004|T|2.5.1\rPID|1||SYN-100011\rOBX|1|NM|718-7^Hemoglobin^LN||13.2|g/dL|12.0-17.5|N|||F\r"
```

Predict the `MSA` code (or lack of reply) for each of the five. `cat -v` shows 0x0B as `^K` and
0x1C as `^\`. Nothing is stored (processing ID `T`).

**Exercise 5.3. Read the patient's lab results off the wire.**
In `./lab shell switch` run `tcpdump -ni eth7 -A -s0 "tcp port 2575 and tcp[tcpflags] & tcp-push != 0"`
(eth7 is the analyzer's port). In `lab-analyzer` run `clinic-hl7 send 10.10.20.10 2575`.
Predict what you can read. Who could do this in a real clinic?

**Exercise 5.4. Store an image and fetch it.**
Count the studies in the PACS:
`curl -s -u doctor:<password> http://10.10.20.20:8042/studies | grep -c '"'` from `doctor-pc`.
Run `clinic-dicom send 10.10.20.20` in `imaging`, then count again and run the `?expand`
query. Then, from `imaging`, try `curl -s -m 3 http://10.10.20.20:8042/studies` and
`nc -zv -w 2 10.10.20.10 2575`. Predict. Nothing to undo (a synthetic study is added).

**Exercise 5.5. An open port is not a DICOM service.**
In `imaging`: `nc -zv -w 2 10.10.20.20 4242`, then
`echo hello | nc -w 3 10.10.20.20 4242 | wc -c`, then `clinic-dicom echo 10.10.20.20; echo $?`.
In `doctor-pc` run the first and third. Predict all five, then check
`docker logs --tail 3 clab-clinic-pacs`.

## 5. Questions you should be able to answer

1. What is DICOM? What are an AE title, an association, C-ECHO and C-STORE? Is an AE title authentication?
2. What is HL7 v2 and what is MLLP? Why does MLLP exist (what does TCP not give you)?
3. In an ORU^R01 message, what are MSH, PID, OBR, OBX? What does `MSA|AA` mean, and what should a sender do on `AE` or `AR`?
4. Why do imaging machines run old software, and what does the network do about it?
5. Neither protocol encrypts. What does that imply for who may reach ports 4242 and 2575?
6. Why does the lab's DICOM probe use C-ECHO and the HL7 probe use a test message instead of just opening the port?
7. What would you do to bring a real clinic's DICOM traffic under TLS, and what are the obstacles?

<details><summary>Answers</summary>

**Exercise 5.1.** Verified.

```
calling IMAGING      called PACS        -> ESTABLISHED
calling EVIL_LAPTOP  called PACS        -> ESTABLISHED
calling IMAGING      called WRONGNAME   -> REFUSED
```

Orthanc logs for the third: `Rejected association, because of a bad called AET in the
request (WRONGNAME)`. The lab sets `DicomCheckCalledAet=true`, so a modality that is
configured for the wrong archive fails loudly. But the *calling* title is not checked at all:
an unknown laptop calling itself `EVIL_LAPTOP` gets in. That is Orthanc's default (it accepts
unknown modalities unless you list them). You can configure Orthanc to accept only
known `(AE title, IP)` pairs, which helps a little, since an IP can be spoofed too. The real
control is the firewall rule `allow:imaging-pacs-dicom`: only the imaging workstation's address
can reach port 4242.

**Exercise 5.2.** Verified.

```
1  valid ORU^R01 (processing id T):   MSA|AA|CTRL0001
2  ADT^A01 (an admit, not a result):  MSA|AR|CTRL0002|unsupported message type ADT^A01
                                      ERR|||200^Unsupported message type^HL70357|E|||...
3  ORU^R01 with no OBX:               MSA|AE|CTRL0003|ORU^R01 needs a PID and at least one OBX
                                      ERR|||101^Required field missing^HL70357|E|||...
4  "hello" (no MSH header):           MSA|AR||not an HL7 v2 message (no MSH header)
                                      ERR|||100^Segment sequence error^HL70357|E|||...
5  valid but no 0x1C 0x0D at the end: no reply at all (nc gives up after 3 seconds)
```

Cases 1 to 4 show the three outcomes: accepted, rejected (the message is not something this
interface handles), error (right type, missing data). The `MSA` always echoes the control ID
the sender used, so the sender can match reply to request. In case 5 the receiver is waiting
for the end-of-message bytes. TCP gives it bytes, not messages, and MLLP is the only thing
that says "this message is finished". A sender that does not read the ACK, or has no
timeout, hangs here. In the EMR, the read timeout is 30 seconds
(`asyncio.wait_for(reader.read(65536), 30)` in `clinic-hl7`).

**Exercise 5.3.** Verified. The whole message is readable text, including the patient's
name, birth date and results:

```
MSH|^~\&|ANALYZER|CLINIC-LAB|EMR|CLINIC|20261026220323||ORU^R01^ORU_R01|LAB377779375|P|2.5.1
PID|1||SYN-100005^^^CLINIC^MR||Whitlow^Casey||19721103
OBX|1|NM|2093-3^Cholesterol^LN||195.9|mg/dL|0-199|N|||F|||...
OBX|3|NM|13457-7^LDL cholesterol^LN||100.1|mg/dL|0-99|H|||F|||...
```

(`Whitlow^Casey` is an invented patient.) Anyone on the path can read this: someone who
has taken over the lab analyzer, someone plugged into the wall port, or a compromised
switch. In a real clinic this is the reason lab interfaces are placed in a locked-down zone,
or sent through a VPN or TLS tunnel (a "stunnel"). Here, only the analyzer and the EMR
are on the path and no other machine can see this VLAN's traffic (stage 02).

**Exercise 5.4.** Verified. The study count goes from 1 to 2, and the new entry appears:

```
"StudyDescription" : "XR ankle, 2 views",   "PatientName" : "Danvers^Riley"
```

From `imaging`: the web request to port 8042 times out (`curl` exit 28, firewall rule
`deny:devices`, policy D11), and the HL7 port on the EMR times out (D25). The modality can
only push to port 4242 (A05). The doctor's PC can read via 8042 with the password (A03),
but gets nothing on 4242 (D24: it cannot push images). Without the password,
`curl` from `doctor-pc` gets `401`. Two locks: the network decides who can *reach* the login,
the password decides who gets *in*.

**Exercise 5.5.** Verified.

```
imaging:   nc -zv  ...4242            Connection ... succeeded!       (TCP port open)
imaging:   echo hello | nc ...        0 bytes back                    (not a DICOM client: PACS drops it)
imaging:   clinic-dicom echo          exit 0                          (real DICOM)
doctor-pc: nc -zv  ...4242            timed out                       (blocked: D24)
doctor-pc: clinic-dicom echo          exit 1
```

Orthanc logs the garbage: `Receiving Association failed: Unrecognized PDU type: 68`
(68 = the ASCII code of `h`). An open TCP port only proves something is listening. That is
why the isolation test uses `dicom` (C-ECHO) and `hl7` (a test message and `MSA|AA`): a pass
means the real application answered, so a "block" result can be trusted to mean the firewall
and not a dead service.

</details>
