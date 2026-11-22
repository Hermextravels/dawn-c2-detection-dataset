# Original Synthetic C2 Detection Dataset (CC0)

## Provenance and scope
Original **synthetically constructed packets**, generated using Python standard-library code. These are **not captures of real malware**, not third-party captures, and not an independently observed compromise. Packet timestamps are simulated. IPs use private and RFC 5737 documentation ranges. Domain names use the reserved `.test` TLD. No malicious servers are contacted.

## Scenarios
- `pcap/malware-scenario-1.pcap`: DNS answer for `control-alpha.test` to `198.51.100.77`, then 48 attempted TCP connections from `10.44.0.10` to port 1177, with two retransmissions per attempt; concurrent benign HTTP and failed HTTPS.
- `pcap/malware-scenario-2.pcap`: DNS answer for `relay-beta.test` to `203.0.113.117`, then 38 attempted connections from `10.44.0.11` to port 8443, with a mix of failed and successful sessions; benign HTTP and failed TCP connections.
- `pcap/benign-reference.pcap`: benign HTTP and deliberately challenging legitimate TCP connection failures on ports 443 and 8443.

The ground-truth CSVs label *synthetic scenario intent*, not a real-world security verdict. Every CSV row corresponds to a generated packet ID (`generation_id`) rather than Wireshark display frame numbers; packet ID order can differ from displayed frame order due to timestamp sorting. For comparison, correlate timestamp and 5-tuple, not generation ID.

## Detection challenge
The `detection/baseline-rules.csv` is intentionally incomplete. Compare destination indicators, distinct failed TCP attempts (not raw SYN retransmissions), and DNS-correlated behavioral detection. Do not infer beaconing or successful compromise from failed SYNs. Test false positives on benign-reference and generalization on scenario-2 without retuning.

## Limitations
Traffic is generated, not recorded from a live network. TCP is intentionally simplified (e.g., no teardown, minimal application content); there is no true malicious payload or endpoint infection. DNS-to-connection timing is constructed. No IPv6 or multicast. Not a replacement for independent, real-world validation. Dataset size is intentionally modest.

## License
All original files in this dataset are dedicated under CC0 1.0 Universal. See `LICENSE`. This license applies only to these original files and does not change the license of CTU-IDSEVAL-6 or any third-party dataset.
