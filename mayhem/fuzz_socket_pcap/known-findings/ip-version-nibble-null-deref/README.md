# IPv4 ethertype with an IP version nibble of 6 dereferences a null `ip6_pkt`

The header pointer is chosen by the ethertype (`type_ip == ETHERTYPE_IP` sets `ip4_pkt` and leaves `ip6_pkt` NULL),
but `ip_ver` is then taken from the version nibble of the packet itself. A 0x0800 frame whose IP header starts
with `0x6?` takes `case 6:` and reads `ip6_pkt->ip6_nxt` (socket_pcap.c:632) through the NULL `ip6_pkt`.

- Reproduce: `fuzz_socket_pcap-standalone input`: UBSan "member access within null pointer of type 'struct ip6_hdr'" at socket_pcap.c:632.
- Impact: one crafted packet kills the capture thread.
- Fix: derive `ip_ver` from the ethertype (or reject a nibble that disagrees with it).
