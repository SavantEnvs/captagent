# Heap over-read at socket_pcap.c:843

ASan: heap-buffer-overflow read of `tcp_pkt->th_sport` (socket_pcap.c:843). The TCP header pointer is computed from header lengths (`ip_hl`, ERSPAN/GRE offsets) that are not checked against `caplen`. Root cause not narrowed further.

- Reproduce: `fuzz_socket_pcap-standalone input`.
- Impact: out-of-bounds read of capture memory.
