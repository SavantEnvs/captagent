# TCP/UDP header read past the end of the IP packet

With IP reassembly on, `callback_proto()` copies the IP packet into `malloc(len - link_offset - hdr_offset)`
(socket_pcap.c:574) and reads the TCP/UDP header at `ip4_pkt + ip_hl` without checking `len >= ip_hl + sizeof(header)`.
`input` is an Ethernet frame holding only a 20-byte IPv4 header with protocol TCP (a capture truncated to the
header, snaplen 34): `tcp_pkt->th_off` (line 667) is read 12 bytes past the 20-byte copy. `input-udp` is the UDP
variant (line 899, `uh_sport`).

- Reproduce: `fuzz_socket_pcap-standalone input` (config byte 0x08: Ethernet, IP reassembly on): heap-buffer-overflow READ at socket_pcap.c:667. Still reports the same site with `CAPTURE_SLACK=0` and full UBSan, because the buffer is the decoder's own copy.
- Impact: out-of-bounds read of heap memory driven by the packet's IHL and truncation.
- Fix: reject packets with `len < ip_hl + sizeof(struct tcphdr/udphdr)` before reading the transport header.
