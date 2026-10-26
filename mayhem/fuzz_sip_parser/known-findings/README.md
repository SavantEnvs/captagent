# fuzz_sip_parser notes

## Buffer contract

The harness gives the parser the message in one of two buffer shapes, chosen by mode bit 1 of the
first input byte (bit 0 picks parse_message's `type`). Each shape is a real production path:

| mode bit 1 | shape | production path |
| --- | --- | --- |
| 0 | padded: message + NUL + 64 spare bytes (`TAIL_PAD`) | SIP over UDP. The message is a slice inside the larger libpcap capture buffer, so a probe past the message end stays inside the allocation. |
| 1 | exact: `malloc(size)`, no NUL, no pad | SIP over TCP. `tcpreasm.c:421` `assemble_tcp()` returns an exact-size malloc (`entry->len + offset0`) and `socket_pcap.c:753` passes it on as `_msg.data`. |

The harness also applies `parse_sip()`'s precondition: anything whose first byte is not a letter
(`isalpha`) is rejected before parsing. Without it `parse_message()` reads one byte before the buffer at
parser_sip.c:696 for a message starting with `\n` (reproducer bytes `01 0a 10 04`).

## Findings

The harness calls only `parse_message()` and `light_parse_message()`, the two entry points
`protocol_sip.c` uses after its `isalpha(data[0])` check. It does not call `check_sip_message()` or
`check_len_message()`: nothing in captagent calls them (they are only defined in `parser_sip.c` and
declared in `parser_sip.h`), so a defect in them is not a finding.

Note, not a finding. An earlier round of this harness called those two helpers directly, and with an exact-size
buffer (no NUL, no pad) they over-read: `check_len_message` at parser_sip.c:1069 (the loop tests `*c`
before the `c - message < new_len` bound), `check_sip_message` at parser_sip.c:1093 (`memcmp(.., "SIP/2.0 ", 8)`
for any `blen >= 3`) and at :1111 (fixed-length method comparisons such as `SUBSCRIBE_LEN`). They are
over-reads in uncalled helper functions and have no production path. They would matter only if a
future module started to call them on a TCP-reassembled message.

### What the exact shape finds in `parse_message()`

With the helpers dropped, the 1200s runs find heap-buffer-overflow reads on exact-size buffers, all with the
first app frame inside `parser_sip.c` and none in the harness. The frames of the latest run (the exact
lines move a little between runs):

| first app frame | kind |
| --- | --- |
| `parse_message` :695, :792, :795, :971 | the loops `for (; *c && c - message < new_len; c++)` test `*c` before the bound, so a message with no NUL reads `message[len]` |
| `parse_message` :712, :772, :777, :816, :831 | header and method matching reads fixed or strlen-style lengths past the message end (:971 is the `P-Asserted-Identity` check at `tmp + 13`) |
| `getMethodType` :608, :620, :636 | fixed-length method `memcmp` on a short message |
| `splitCSeq` :660 | string function on the CSeq value that runs past the end of a message with no NUL |
| `parseSdp` :522, `parseVQRtcpXR` :283 | string functions on the body that run past the end of a message with no NUL |

One root cause: the parser assumes the message buffer is NUL-terminated, which holds for SIP over UDP
(a slice of the capture buffer) and not for a TCP-reassembled message (`assemble_tcp()` returns an
exact-size malloc). Each crashing input has mode bit 1 set; none reproduces in the padded shape.

Reproduce a crash with `/mayhem/fuzz_sip_parser-standalone <file>`.
