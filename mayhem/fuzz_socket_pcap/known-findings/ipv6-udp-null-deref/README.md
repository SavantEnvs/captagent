# IPv6 UDP packet dereferences a null header pointer

`callback_proto()` (`src/modules/socket/pcap/socket_pcap.c`) builds the UDP/TCP header pointer from `ip4_pkt`, which is NULL for every IPv6 packet (only `ip6_pkt` is set), so `udp_pkt->uh_sport` (line 899) and `tcp_pkt->th_off` (line 667) read address 0x28 / 0x34.

- Reproduce: `fuzz_socket_pcap-standalone input` (config byte 0 = Ethernet, one Ethernet/IPv6/UDP frame): SEGV at socket_pcap.c:899.
- Impact: one IPv6 UDP packet on the capture interface kills the daemon (remote DoS); IPv6 capture of UDP or TCP never works.
- Fix: compute the transport header from `(unsigned char *)(ip_ver == 6 ? (void *)ip6_pkt : (void *)ip4_pkt) + ip_hl`.
