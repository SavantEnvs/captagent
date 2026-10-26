# IP-in-IP packet whose inner header is also IP-in-IP spins forever

When `ip_proto == 4`, `callback_proto()` sets `ipip_offset = IPV4_SIZE` and does `goto ip_hdr_parse`. The offset is assigned, not accumulated, so a packet whose header at that offset again says protocol 4 re-parses the same bytes forever (socket_pcap.c, "check IP-to-IP tunnel").

- Reproduce: `timeout 10 fuzz_socket_pcap-standalone input`: never returns (libFuzzer reports a timeout).
- Impact: one crafted packet pins the capture thread at 100% CPU and stops all capture (remote DoS).
- Fix: `ipip_offset += IPV4_SIZE` and reject after one level of nesting.
