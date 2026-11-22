# Wireshark-focused implementation rehearsal (not a recording script)

1. **Baseline:** load `protocol-malware-scenario-1.pcap` and `dawn_c2_starter.lua` using Wireshark Lua plugin autoloading (personal plugin folder, or `-X lua_script:<path>` if supported). Check what fields are currently missing from decoded trees and test `dawnc2.type` filter.
2. **Build first candidate:** extend starting Lua decoder to parse and validate the entire 18-byte header, length and fields. Reload or restart Wireshark; test invalid version, type, length and benign magic lookalikes.
3. **Handle TCP framing:** implement and debug stream reassembly for split header / split body. Check stream sequence and packet positions, not merely TCP segment counts.
4. **Handle coalescing:** parse multiple PDUs within one TCP payload. Compare naive one-message and correct multi-message behavior; save actual observed counts.
5. **Cross-capture and negative tests:** test same code with `protocol-malware-scenario-2.pcap` and `protocol-benign-reference.pcap` without hard-coded malicious addresses. Report valid and invalid matches against ground-truth CSVs.
6. **Output:** save updated dissector and validation CSV, export selected packet evidence with references, and document decision trade-offs (strict reject vs partial decode / false positives / malformed traffic). Keep majority of recording interactions in Wireshark; substantial code editing will occur in an editor, and Dawn may still judge the app dominance requirement strictly.

**Do not claim** this work has been implemented or benchmarked before it is done on camera. If Wireshark's Lua engine is not installed or disabled, this task cannot be recorded as written. Verify with `Help > About Wireshark > Plugins` or the console / plugin folder on the actual recording machine.
