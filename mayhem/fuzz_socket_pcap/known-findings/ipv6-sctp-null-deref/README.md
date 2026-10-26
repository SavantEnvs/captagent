# IPv6 SCTP packet dereferences a null header pointer

Same root cause as `ipv6-udp-null-deref`, on the SCTP branch: `sctp_hdr = ip4_pkt + ip_hl` with `ip4_pkt == NULL`
(socket_pcap.c:950), then `sctp_parse_common()` reads `sctp_hdr->source` at address 0x28 (`sctp_support.c:42`).

- Reproduce: `fuzz_socket_pcap-standalone input`: SEGV at sctp_support.c:42.
- Fix: as for `ipv6-udp-null-deref`.
