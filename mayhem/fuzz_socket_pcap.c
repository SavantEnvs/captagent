/*
 * libFuzzer harness for captagent's pcap decoder, callback_proto() in socket_pcap.c, including the IP
 * and TCP reassembly it drives (ipreasm.c, tcpreasm.c).
 *
 * Input: [config byte][packet]...  where packet = [u16 little-endian length][that many bytes].
 *   config bits 0-2  link type: EN10MB, LINUX_SLL, LINUX_SLL2, RAW, MTP2, NULL, PPP, IEEE802_11
 *          bit 3     IP reassembly on        bit 4  TCP reassembly on     bit 5  GRE/ERSPAN unwrapping on
 *          bit 6     websocket detection     bit 7  full_packet delivery
 * Every packet is handed to the decoder inside a zero-filled buffer with CAPTURE_SLACK spare bytes after
 * caplen, as libpcap's snaplen-sized read buffer provides: callback_proto() probes fixed header offsets
 * (IP protocol byte, GRE/ERSPAN fields) without checking caplen, and those probes stay inside the buffer
 * in production. Reads further past the packet than the slack are still reported.
 */
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "pcap_env.h"

#define MAX_PACKETS 12
#ifndef CAPTURE_SLACK
#define CAPTURE_SLACK 256
#endif

static const struct { int dlt; uint16_t off; } link_types[8] = {
  { DLT_EN10MB, ETHER_HDR_LEN }, { DLT_LINUX_SLL, SLL_HDR_LEN }, { DLT_LINUX_SLL2, SLL2_HDR_LEN },
  { DLT_RAW, RAWHDR_SIZE },      { DLT_MTP2, RAWHDR_SIZE },      { DLT_NULL, LOOPHDR_SIZE },
  { DLT_PPP, PPPHDR_SIZE },      { DLT_IEEE802_11, IEEE80211HDR_SIZE },
};

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  static int once;
  if (!once) {
    once = 1;
    set_log_level(LOG_EMERG);
  }
  if (size < 4) return -1;

  uint8_t cfg = data[0];
  data++; size--;

  /* Walk the packet list first; an input with no complete packet is rejected, not repaired. */
  size_t pos = 0, count = 0;
  while (count < MAX_PACKETS && pos + 2 <= size) {
    size_t n = data[pos] | (data[pos + 1] << 8);
    if (n == 0 || pos + 2 + n > size) break;
    pos += 2 + n;
    count++;
  }
  if (count == 0) return -1;

  type_datalink = link_types[cfg & 7].dlt;
  link_offset = link_types[cfg & 7].off;
  websocket_detection = (cfg >> 6) & 1;
  profile_size = 0;
  memset(&profile_socket[0], 0, sizeof profile_socket[0]);
  profile_socket[0].reasm = (cfg >> 3) & 1;
  profile_socket[0].erspan = (cfg >> 5) & 1;
  profile_socket[0].full_packet = (cfg >> 7) & 1;
  reasm[0] = (cfg & 8) ? reasm_ip_new() : NULL;
  tcpreasm[0] = (cfg & 16) ? tcpreasm_ip_new() : NULL;

  unsigned char loc_index = 0;
  pos = 0;
  for (size_t i = 0; i < count; i++) {
    size_t n = data[pos] | (data[pos + 1] << 8);
    unsigned char *pkt = calloc(n + CAPTURE_SLACK, 1);
    memcpy(pkt, data + pos + 2, n);
    struct pcap_pkthdr hdr;
    memset(&hdr, 0, sizeof hdr);
    hdr.ts.tv_sec = (time_t)i;
    hdr.caplen = hdr.len = (bpf_u_int32)n;
    callback_proto(&loc_index, &hdr, pkt);
    free(pkt);
    pos += 2 + n;
  }

  if (reasm[0]) reasm_ip_free(reasm[0]);
  if (tcpreasm[0]) tcpreasm_ip_free(tcpreasm[0]);
  reasm[0] = NULL;
  tcpreasm[0] = NULL;
  return 0;
}
