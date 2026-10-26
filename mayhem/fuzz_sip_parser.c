/*
 * libFuzzer harness for captagent's SIP parser (protocol/sip/parser_sip.c): the full parser
 * parse_message() in both capture modes, the light parser, and the cheap pre-checks, as
 * protocol_sip.c calls them for every packet a capture plan routes to the SIP module.
 *
 * Input: [mode byte][message bytes]. mode bit 0 selects parse_message's `type` argument (1 or 2).
 * The parser treats the message as a C string and probes a few bytes past short header lines, as it
 * can because a capture buffer is larger than the message: each copy is NUL-terminated and padded.
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

static char *copy_message(const uint8_t *data, size_t size) {
  char *m = calloc(size + 1 + TAIL_PAD, 1);
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
  data++; size--;

  /* protocol_sip.c's parse_sip() drops anything whose first byte is not a letter before parsing. */
  if (!isalpha(data[0])) return -1;

  char *m = copy_message(data, size);
  check_sip_message((unsigned char *)m, (unsigned)size);
  check_len_message((unsigned char *)m, (unsigned)size);
  free(m);

  unsigned bytes_parsed = 0;
  sip_msg_t sip;

  m = copy_message(data, size);
  memset(&sip, 0, sizeof sip);
  parse_message(m, (unsigned)size, &bytes_parsed, &sip, type);
  free(m);

  m = copy_message(data, size);
  memset(&sip, 0, sizeof sip);
  light_parse_message(m, (unsigned)size, &bytes_parsed, &sip);
  free(m);
  return 0;
}
