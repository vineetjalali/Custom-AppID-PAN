# Custom AppID generator

This Python3 script parses a PCAP file and looks for recurring data patterns in TCP or UDP payloads.
These can then be used as signatures while building a custom App-ID.
It works for captures with multiple sessions/segments of the same unknown-tcp or udp traffic.
Intended to be used with context unknown-<req|rsp>-tcp-payload and unknown-<req|rsp>-udp-payload, but strings can be converted to ASCII and used in other contexts.
Requires the library dpkt (https://dpkt.readthedocs.io/en/latest/)

**Caveats:**
* Only the first client or server payload in each TCP flow is considered for matching.
* The higher the number of conversations in the PCAP, the more accurate the results will be.
* TCP or UDP traffic in the PCAP must belong exclusively to the application being analysed.
* The script works with TCP-only or UDP-only PCAPs. Mixed protocols will result in unreliable output.
* The script finds repetitions in payloads. It does not verify that the strings found are specific enough not to overlap with
 other unknown TCP/UDP traffic. Always validate your findings.
