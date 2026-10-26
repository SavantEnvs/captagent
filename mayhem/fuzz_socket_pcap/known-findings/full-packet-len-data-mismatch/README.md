# `full_packet` delivers a length that does not match the data pointer

On the plain TCP branch the "not full packet" arm (taken when `profile_socket[profile_size].full_packet` is set)
sets `_msg.len = pkthdr->caplen - link_offset - hdr_offset` (the whole IP packet, line 826) but leaves `_msg.data = data` (line 835),
which points past the IP and TCP headers. A consumer reading `msg->len` bytes from `msg->data` runs
`ip_hl + th_off*4` bytes past the end of the packet (socket_pcap.c:860 passes it to `run_actions()`).

- Reproduce: `fuzz_socket_pcap-readpayload-standalone input` (config byte 0x88: Ethernet, IP reassembly on, `full_packet` on): heap-buffer-overflow READ of byte 140 of the 140-byte reassembly copy, in `run_actions`. `fuzz_socket_pcap-standalone` does not read the message and so reports nothing.
- Impact: the capture plan's next stage (SIP parser, HEP sender) reads heap memory past the packet.
- Fix: `_msg.len` must describe `_msg.data`: `len` (payload length) or point `data` at the IP header.
