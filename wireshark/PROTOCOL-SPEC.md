# Dawn synthetic binary protocol: version 1

This is **invented synthetic traffic**, not a known C2 protocol and not actual malware.
The protocol is carried over TCP destination ports 1177 or 8443 in the generated PCAPs. A TCP segment is *not* necessarily a message.

| Byte offset | Width | Encoding | Meaning |
|---|---:|---|---|
| 0 | 4 | ASCII | `DNC2` magic |
| 4 | 1 | unsigned | version (must equal 1) |
| 5 | 1 | unsigned | message type: 1 HELLO, 2 CHECKIN, 3 COMMAND, 4 RESULT, 5 KEEPALIVE |
| 6 | 2 | big endian | flags (currently 0) |
| 8 | 2 | big endian | payload byte count (maximum 512) |
| 10 | 4 | big endian | session ID |
| 14 | 4 | big endian | message ordinal |
| 18 | variable | bytes | payload of declared length |

The total *message length* is `18 + payload length`; do not confuse with TCP payload byte count. TCP stream reassembly must accommodate split fixed headers and split message bodies; the decoder must iterate when multiple messages are coalesced. Unsupported types, versions and impossible lengths must be rejected or marked malformed rather than silently treated as valid.

### Acceptance targets (ground truth supplied with fixtures)
- For *each* malicious protocol capture: 46 well-formed expected messages (40 from eight 5-message sessions, plus 6 from edge cases); nine deliberately invalid candidates (five malformed scenarios plus four benign lookalikes) must not be counted as valid.
- For the protocol benign reference: 0 valid messages; four magic-prefix lookalikes should not be promoted to positive detection.
- Preserve original captures; record discrepancies and per-case evidence with frame/stream references.

These are synthetic functional acceptance targets, **not** real-world malware detection quality estimates or throughput benchmarks. Note that capture 1 and 2 intentionally share the same protocol framing, but use different hosts and destination ports; this validates parser generalization, not arbitrary new malware families.
