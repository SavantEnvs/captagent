# fuzz_socket_pcap findings

Reproducers are inputs for `/mayhem/fuzz_socket_pcap-standalone` (or the fuzzer with `-runs=1`). They are kept
out of `testsuite/` because seeds are replayed on every run. Each directory holds `input` (and a README for the
older ones); the table below is the triage of the 11 defects the first 5-minute confirmation run reported (run 2) and of the 10 the next one reported with the stub change below (run 3).

## Triage: 6 root causes

| # | Root cause (upstream `src/modules/socket/pcap/`) | Run 2 defects | Crash sites | Reproducer |
|---|---|---|---|---|
| 1 | The transport header is computed from `ip4_pkt` (`socket_pcap.c` 667, 700 and 843 TCP, 899 UDP, 951 SCTP; 700 is the first access when the packet is a fragment), which is NULL for every IPv6 packet. Separately, `ip_ver` comes from the IP header's version nibble while the header pointer (`ip4_pkt`/`ip6_pkt`) is chosen by the ethertype, so an IPv4 ethertype with version nibble 6 dereferences a NULL `ip6_pkt` at 632. | #3488473, #3488478, #3488476, #3488483 | 667, 700, 843, 899, 632, `sctp_support.c:42` | `ipv6-tcp-null-deref`, `ipv6-udp-null-deref`, `ipv6-sctp-null-deref`, `ip-version-nibble-null-deref` |
| 2 | The IPv4 header length (`ip_hl`, from IHL, up to 60 bytes) and the TCP/UDP header are read without checking them against the length of the IP packet: a header-only IPv4 packet (snaplen-truncated capture) read 12 bytes past its 20-byte buffer. | #3488556, #3488535 | 667 (`th_off`), 700 and 849 (`th_flags`), 899 (`uh_sport`) | `transport-header-past-end` (`input`: TCP, `input-udp`: UDP) |
| 3 | After IP reassembly the packet is a `malloc(len - link_offset - hdr_offset)` copy; an IP header taken as IPv6 (version nibble 6 under an IPv4 ethertype, only the 20-byte IPv4 header size was checked) reads `ip6_dst` past a 32-byte copy. | #3489517 | 647 (`inet_ntop`) | `heap-overflow-ipv6-address-646` (`input-647`) |
| 4 | The websocket frame length is trusted: `websocket_decode()` XORs `len` bytes from the TCP-reassembled data without checking the frame length against the data (70-byte region, read at +70). | #3489513 | 278 | `websocket-frame-length-overread` |
| 5 | With `full_packet` on, `_msg.len` is the whole L3 length (`caplen - link_offset - hdr_offset`, line 826, plain-TCP branch) while `_msg.data` is `data` (line 835) which points past the IP and TCP headers, so a consumer reading `len` bytes runs `ip_hl + th_off*4` bytes past the buffer (here byte 140 of a 140-byte reassembly copy). | #3489516 | read of `msg->data[len]` by the next stage | `full-packet-len-data-mismatch` |
| 6 | `websocket_pre_decode(p_websock, decoded, &_msg)` makes `_msg.data` point into `unsigned char decoded[3000]`, declared inside the `if (websocket_detection == 1)` block (lines 750, 763, 814, 829), which is out of scope when `run_actions()` runs (lines 794, 860). | #3489509, #3488477 | read of `msg->data` by the next stage (stack-use-after-scope) | `websocket-stack-use-after-scope` |

Run 3 (shipped harness, stub no longer reading `msg->data`) had 10 defects, none with a harness frame: group 1 five
(667, 700, 899, 632, sctp), group 2 three (667, 849, 899), group 3 one (647), group 4 one (278). All 39 crashing
inputs of that run reproduce on the shipped standalone at those sites; with `CAPTURE_SLACK=0` and full UBSan 38 still
fault at the same sites or in `inet_ntop` for line 647, and one stops at the truncated-packet read at line 499.

Run 4 (12 defects) added only line 843 to group 1 and line 700 (OOB) to group 2: every further `tcp_pkt->` / `udp_pkt->`
access in `callback_proto` is another crash signature of group 1 (NULL pointer) or group 2 (past the end), not a new
root cause, so the defect count grows with the run length while the root causes stay at four.

Groups 5 and 6 are bugs in what the decoder hands to the next stage. The harness's action stub used to read
`msg->len` bytes at `msg->data` itself, which put their crash site in harness code (`pcap_env.h`), so the
fuzz target no longer reads the message and only groups 1 to 4 can show up in its runs. To reproduce 5 and 6
use `/mayhem/fuzz_socket_pcap-readpayload-standalone <input>`: the same harness with the stub reading all
`msg->len` bytes (a downstream parser reads exactly that), ASan reports the read in `run_actions`.

## Not harness artifacts

The harness environment is the same for all of them, and none of the groups depends on it:

- **Zero-filled buffer with `CAPTURE_SLACK` (256) spare bytes after `caplen`.** libpcap's snaplen-sized read
  buffer provides the same, and the decoder probes fixed header offsets without checking `caplen` (an exact-size
  5-byte packet overreads at socket_pcap.c:499). Groups 2, 3, 4 and 5 are reads of the decoder's own
  `malloc`ed reassembly copies (socket_pcap.c:574, `tcpreasm`), which have no slack in production either;
  group 1 is a NULL pointer. Rebuilding the harness with `-DCAPTURE_SLACK=0` (exact-size packets) reports
  the same site for every reproducer here (groups 5 and 6 with the `readpayload` build), except
  `websocket-stack-use-after-scope`, which then stops at the websocket overread of group 4 first.
- **UBSan `alignment` and `pointer-overflow` are relaxed for this target only**: header casts at odd offsets
  are the norm for packet code and the null-based header arithmetic already faults when dereferenced.
  Rebuilding with them enabled (and recovering, so the first real error is the one that halts) reports the same
  site for every reproducer here.

Triage runs: the 43 crashing inputs of run 2 plus the reproducers here, under the shipped harness, under the
previous stub, and with `CAPTURE_SLACK=0` and full UBSan. Each input reproduces one of the six groups; a few
inputs with `CAPTURE_SLACK=0` stop earlier at a truncated-packet read (socket_pcap.c:499, the
reassembly `memcpy`), which is the overread the slack exists to absorb and is not counted as a finding.
