# IPv6 TCP packet dereferences a null header pointer

Same root cause as `ipv6-udp-null-deref`, on the TCP branch: `tcp_pkt = ip4_pkt + ip_hl` with `ip4_pkt == NULL`, then `tcp_pkt->th_off` (socket_pcap.c:667) faults at 0x34.

- Reproduce: `fuzz_socket_pcap-standalone input`: SEGV at socket_pcap.c:667.
- Impact: remote DoS with one IPv6 TCP packet.
- Fix: as for `ipv6-udp-null-deref`.
