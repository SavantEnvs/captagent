/*
 * libFuzzer harness for captagent's SIP parser (protocol/sip/parser_sip.c): the full parser
 * parse_message() in both capture modes and the light parser light_parse_message(), the two
 * entry points protocol_sip.c parse_sip() calls after its isalpha(data[0]) check.
 * (check_sip_message() and check_len_message() are not called by any module, so they are not fuzzed.)
 *
 * Input: [mode byte][message bytes]. mode bit 0 selects parse_message's `type` argument (1 or 2).
 * mode bit 1 selects the shape of the buffer the message lives in, i.e. the production path:
 *   bit 1 = 0  padded: NUL-terminated plus TAIL_PAD spare bytes. SIP over UDP, where the message is a
 *              slice inside the larger libpcap capture buffer, so short header lines can be probed
 *              past the message end without leaving the allocation.
 *   bit 1 = 1  exact: malloc(size), no NUL, no pad. SIP over TCP, where tcpreasm.c assemble_tcp()
 *              returns an exact-size malloc (entry->len + offset0) that socket_pcap.c passes on as
 *              _msg.data. Any over-read of the message end is a real defect on this path.
 */
#include <ctype.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <captagent/api.h>
#include <captagent/log.h>
#include <captagent/proto_sip.h>

#include "parser_sip.h"

#define TAIL_PAD 64

static char *copy_message(const uint8_t *data, size_t size, int exact) {
  char *m = exact ? malloc(size) : calloc(size + 1 + TAIL_PAD, 1);
  memcpy(m, data, size);
  return m;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  static int once;
  if (!once) {
    once = 1;
    set_log_level(LOG_EMERG);
  }
  if (size < 4) return -1;

  unsigned type = 1 + (data[0] & 1);
  int exact = (data[0] >> 1) & 1;
  data++; size--;

  /* protocol_sip.c's parse_sip() drops anything whose first byte is not a letter before parsing. */
  if (!isalpha(data[0])) return -1;

  unsigned bytes_parsed = 0;
  sip_msg_t sip;

  char *m = copy_message(data, size, exact);
  memset(&sip, 0, sizeof sip);
  parse_message(m, (unsigned)size, &bytes_parsed, &sip, type);
  free(m);

  m = copy_message(data, size, exact);
  memset(&sip, 0, sizeof sip);
  light_parse_message(m, (unsigned)size, &bytes_parsed, &sip);
  free(m);
  return 0;
}
