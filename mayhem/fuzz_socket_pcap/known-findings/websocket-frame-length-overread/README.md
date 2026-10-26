# websocket frame length is trusted when decoding

With TCP reassembly and websocket detection on, `websocket_decode()` (socket_pcap.c:278) XORs `len` bytes
taken from the websocket header with the mask; `len` is not checked against the reassembled TCP data, so it reads
past the end of the 70-byte buffer.

- Reproduce: `fuzz_socket_pcap-standalone input` (config byte 0x50): heap-buffer-overflow READ at socket_pcap.c:278. Same site with `CAPTURE_SLACK=0` and full UBSan: the buffer is the reassembly buffer, not the harness's.
- Impact: out-of-bounds read of heap memory, reflected into the decoded message.
- Fix: bound the frame length by the data length in `websocket_header_detection()`/`websocket_pre_decode()`.
