# Heap over-read at socket_pcap.c:646

ASan: heap-buffer-overflow read in `inet_ntop` called from socket_pcap.c:646 (the IPv6 source address), reached through the ERSPAN/GRE unwrap that rewrites `packet`, `caplen` and `len` from unchecked header fields. Root cause not narrowed further.

- Reproduce: `fuzz_socket_pcap-standalone input` (`input-647` is the same bug at line 647: the `ip6_dst` read past a 32-byte reassembly copy, group 3 of the README table).
- Impact: out-of-bounds read of capture memory driven by attacker-controlled GRE/IP header lengths.
