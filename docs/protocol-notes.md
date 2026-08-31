# Protocol notes

Details of GTP-U and Diameter that the code depends on, and the places where the
specs are easy to get wrong. Written down because a metering pipeline that
misreads a length field bills the wrong subscriber.

## GTP-U (3GPP TS 29.281)

### The Length field does not mean what it looks like

The 16-bit Length at offset 2 counts every byte **after the mandatory 8**, which
includes the optional sequence/N-PDU block and the entire extension-header
chain — not just the payload. So:

```
payload_len = length - (optional_fields_present ? 4 : 0) - extension_chain_bytes
```

Getting this wrong means charging for the extension headers, which is a
per-packet overcount of 4-8 bytes: small, systematic, and exactly the kind of
error that shows up as a billing dispute rather than a crash. The golden test
compares byte totals exactly for this reason.

### The optional block is all-or-nothing

If *any* of E, S, or PN is set, all four optional bytes are present — sequence
number (2), N-PDU number (1), next extension header type (1). A packet with only
the S bit set still carries the next-extension-header byte; it is just zero.

### Extension headers

Each header is `[length in 4-byte units][content][next type]`, where the length
covers the whole header including its own length byte and the trailing next-type
byte. Content is therefore `length * 4 - 2` bytes.

Two failure modes the parser refuses explicitly:

- **Length zero.** Would advance the cursor by nothing and loop forever. This is
  the classic malformed-GTP hang.
- **An unbounded chain.** Capped at 16 links. A conformant packet never
  approaches that.

### PDU Session Container (TS 38.415)

Extension type `0x85`, and the reason 5G QoS flows are visible at all. The first
content octet's high nibble is the PDU type: 0 for downlink PDU Session
Information, 1 for uplink. The QFI is the low 6 bits of the second octet in both
directions. RQI (Reflective QoS Indicator) is bit 6 of that octet — **downlink
only**; the uplink structure has no RQI field, so reading it there is reading a
spare bit.

### Message types

| Type | Meaning | Metered? |
|---|---|---|
| 1 / 2 | Echo Request / Response | no — control |
| 26 | Error Indication | no — control |
| 31 | Supported Extension Headers Notification | no — control |
| 254 | End Marker | no — control |
| 255 | G-PDU (carries user data) | **yes** |

Charging an Echo Request to a subscriber is a bug that a byte-exact golden test
catches and an eyeball does not.

### Direction

Not derivable from the packet in general. Uplink TEIDs are allocated by the
UPF/SGW-U and downlink TEIDs by the gNB/eNB, so direction is a property of the
tunnel, learned at session setup. The PDU Session Container's PDU type gives a
hint for 5G traffic, which the pipeline uses only as a fallback when no session
binding exists.

## Diameter (RFC 6733)

### Length is 24 bits and always 4-byte aligned

The message length includes the 20-byte header and is a multiple of 4. A length
that is not a multiple of 4, or is below 20, is malformed — checking this cheaply
rejects a large class of garbage before any AVP is touched.

### AVP padding is not in the length

An AVP's Length field covers header plus value and **excludes** the padding that
aligns the next AVP to a 4-byte boundary. So:

```
value_len = avp_length - (vendor_specific ? 12 : 8)
next_avp  = current + ((avp_length + 3) & ~3)
```

Using the padded length as the value length is the most common Diameter parsing
bug; it appends up to three garbage bytes to every odd-length string, which for
Session-Id and Subscription-Id-Data means silently corrupted subscriber
identities.

### Grouped AVPs

A grouped AVP's value is simply a sequence of AVPs. Nesting is bounded here at 8
levels — deep enough for any real Gy message (MSCC → Used-Service-Unit →
CC-Total-Octets is three), shallow enough that a malicious message cannot
recurse the stack away.

### Vendor-specific AVPs

The V bit means a 4-byte Vendor-Id follows the length, making the header 12
bytes instead of 8. 3GPP AVPs use vendor 10415. The parser handles them
generically; the Gy extraction ignores them, because everything it needs is
base-protocol or RFC 4006.

## Gy credit control (RFC 4006)

The AVPs that matter for metering, and what the pipeline does with each:

| AVP | Code | Use |
|---|---:|---|
| Session-Id | 263 | correlate CCR/CCA pairs |
| CC-Request-Type | 416 | 1 INITIAL, 2 UPDATE, 3 TERMINATION, 4 EVENT |
| CC-Request-Number | 415 | ordering within a session |
| Subscription-Id | 443 | grouped: type + data |
| ↳ Subscription-Id-Type | 450 | 0 = E.164/MSISDN, 1 = IMSI |
| ↳ Subscription-Id-Data | 444 | the identity itself, as decimal digits |
| Multiple-Services-Credit-Control | 456 | grouped, one per rating group |
| ↳ Rating-Group | 432 | the accounting bucket |
| ↳ Used-Service-Unit | 446 | grouped: what the client reports it used |
| ↳ ↳ CC-Input/Output/Total-Octets | 412/414/421 | the octet counts to cross-check |
| ↳ Granted-Service-Unit | 431 | the quota the OCS granted |
| Result-Code | 268 | 2001 = success |

CC-Total-Octets is optional when input and output are both present, so the
parser falls back to their sum. Octet counters are Unsigned64 per the RFC, but
implementations exist that encode them as Unsigned32; the accessor accepts both
rather than dropping the value.

The pipeline emits one control event **per MSCC block**, not per message, so
per-rating-group reports stay separable. It uses these messages for two things:
learning the IMSI ↔ session ↔ rating-group association, and cross-checking its
own byte counts against what the client reported. A persistent divergence
between the two is the single most useful health signal a metering component
has.
