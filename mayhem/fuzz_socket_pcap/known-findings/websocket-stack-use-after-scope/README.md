# Message delivered to the capture plan points into an out-of-scope stack buffer

The websocket-detection branches declare `unsigned char decoded[3000]` inside a block (socket_pcap.c lines 750,
763, 814 and 829), `websocket_pre_decode(p_websock, decoded, &_msg)` points `_msg.data` into it, and the block has
ended when `run_actions()` runs (lines 794 and 860). Whatever the next stage reads from `msg->data` is stale stack.

- Reproduce: `fuzz_socket_pcap-readpayload-standalone input` (config byte 0x61: Linux cooked capture, GRE/ERSPAN unwrapping and websocket detection on): ASan stack-use-after-scope READ in `run_actions`, variable `decoded`. The plain fuzz target does not read `msg->data`, so it does not report this.
- Impact: downstream parsers read stale stack memory (information leak or crash) for websocket-framed traffic.
- Fix: hoist `decoded` out of the block so it outlives `run_actions()`.
