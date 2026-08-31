# Where PFCP would plug in

The pipeline fakes the control plane with a CSV file. This is what the real
thing would replace, and where.

## What PFCP actually installs

On N4 (5G) or Sxb (4G), the SMF installs rules into the UPF for each PDU
session:

| Rule | Carries | What this pipeline uses it for |
|---|---|---|
| **PDR** (Packet Detection Rule) | F-TEID (TEID + UPF IP), UE IP, SDF filters, precedence | the TEID → subscriber binding, and its direction |
| **FAR** (Forwarding Action Rule) | forward / drop / buffer, outer header creation | nothing — this component meters, it does not forward |
| **URR** (Usage Reporting Rule) | measurement method (volume/time/event), reporting triggers, thresholds, quotas | the reporting interval and volume threshold |
| **QER** (QoS Enforcement Rule) | QFI, MBR/GBR, gate status | the QFI accounting bucket |

The CSV columns map onto that directly:

```csv
imsi,ul_teid,dl_teid,rating_group,msisdn,apn
310150000000001,65536,65537,10,15551234567,internet
```

- `ul_teid` / `dl_teid` are the F-TEIDs a pair of PDRs would carry. Direction
  comes from which side allocated the TEID — uplink from the UPF, downlink from
  the gNB/eNB — which is exactly what a PDR tells you and what the packet itself
  does not.
- `rating_group` is the URR's accounting bucket.
- `imsi` is the subscriber identity, which in a real core arrives over N4 or is
  correlated from Gy.

## The seams

Three functions are the entire control-plane surface. A PFCP agent would drive
these and nothing else:

```cpp
size_t MeterEngine::install_session(const SessionSpec&, uint64_t now_ns);
bool   MeterEngine::release_session(uint64_t imsi, uint64_t now_ns);
void   MeterEngine::apply_gy(const GyEvent&);
```

`install_session` is idempotent per IMSI and handles re-installation (a session
modification) without resetting counters. `release_session` emits a final usage
record with reason `release` and unbinds the TEIDs, so a packet arriving on a
released tunnel is counted as unknown-TEID rather than billed to a subscriber
who has gone.

## What a real integration would add

1. **A PFCP agent thread.** Session Establishment / Modification / Deletion
   Request handling, heartbeats, association setup, and recovery timestamp
   tracking. It would call the three functions above; it must not touch
   `MeterEngine` state directly, because the metering thread owns it.
2. **A control ring for session events**, mirroring the existing Gy ring, so the
   PFCP thread never touches metering state on its own thread. The Gy ring is
   the template: POD events, single producer, drop-and-count on overflow.
3. **Usage reports back over PFCP.** Today usage records go to NDJSON. A real
   UPF sends a Session Report Request carrying the URR's Usage Report when a
   trigger fires. `UsageRecord` already carries everything such a report needs —
   volume by direction, the measurement interval, the trigger reason, and a
   gapless sequence number.
4. **Quota enforcement.** A URR can carry a volume quota; exhausting it means
   gating traffic and asking the OCS for more via a Gy CCR-Update. The pipeline
   detects the threshold crossing already (that is what `RecordReason::kVolume`
   is); acting on it is a policy decision this component deliberately does not
   make.
5. **SDF filters and precedence.** Multiple PDRs can match one tunnel, selected
   by precedence and 5-tuple filters, which is how per-application charging
   works. The flow table already keys on the 5-tuple; matching it against filter
   rules is the missing piece.

## Why fake it at all

PFCP is a large protocol with a lot of surface and very little of it is
interesting for the question this project answers, which is whether the data
plane can meter at line rate without dropping a byte. Stubbing the control plane
keeps the measured thing measurable. The seams above are narrow on purpose so
that "add PFCP" is an additive change, not a rewrite.
