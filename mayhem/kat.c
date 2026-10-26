/*
 * Known-answer probe for mayhem/test.sh. Built with normal flags and linked dynamically, it drives two
 * real captagent code paths with fixed inputs and prints what they computed:
 *   - socket_pcap.c callback_proto(): a hand-built Ethernet/IPv4/UDP frame (and the same payload behind
 *     an 802.1Q tag) -> addresses, ports, protocol, header length and payload length
 *     handed to the capture plan.
 *   - parser_sip.c parse_message(): a SIP INVITE and a 200 OK -> method, response code, Call-ID, CSeq,
 *     From/To users, content length, SDP presence.
 * test.sh compares the output line by line against golden values.
 */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "pcap_env.h"

#include <captagent/proto_sip.h>
#include "parser_sip.h"

static const char MSG_INVITE[] =
  "INVITE sip:bob@biloxi.example.com SIP/2.0\r\n"
  "Via: SIP/2.0/UDP pc33.atlanta.example.com;branch=z9hG4bK776asdhds\r\n"
  "To: Bob <sip:bob@biloxi.example.com>\r\n"
  "From: Alice <sip:alice@atlanta.example.com>;tag=1928301774\r\n"
  "Call-ID: a84b4c76e66710@pc33.atlanta.example.com\r\n"
  "CSeq: 314159 INVITE\r\n"
  "Contact: <sip:alice@pc33.atlanta.example.com>\r\n"
  "Content-Length: 0\r\n\r\n";

static const char MSG_OK200[] =
  "SIP/2.0 200 OK\r\n"
  "Via: SIP/2.0/UDP pc33.atlanta.example.com;branch=z9hG4bK776asdhds\r\n"
  "To: Bob <sip:bob@biloxi.example.com>;tag=a6c85cf\r\n"
  "From: Alice <sip:alice@atlanta.example.com>;tag=1928301774\r\n"
  "Call-ID: a84b4c76e66710@pc33.atlanta.example.com\r\n"
  "CSeq: 314159 INVITE\r\n"
  "Content-Length: 0\r\n\r\n";

static void put16(uint8_t *p, unsigned v) { p[0] = v >> 8; p[1] = v & 0xff; }

static size_t frame_udp4(uint8_t *f, int vlan, const char *payload, size_t plen) {
  size_t o = 0;
  const uint8_t macs[12] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb};
  memcpy(f, macs, 12); o = 12;
  if (vlan) { put16(f + o, 0x8100); put16(f + o + 2, 0x0064); o += 4; }
  put16(f + o, 0x0800); o += 2;
  uint8_t *ip = f + o;
  memset(ip, 0, 20);
  ip[0] = 0x45; put16(ip + 2, 20 + 8 + plen); ip[8] = 64; ip[9] = 17;
  ip[12] = 10; ip[13] = 0; ip[14] = 0; ip[15] = 1;
  ip[16] = 10; ip[17] = 0; ip[18] = 0; ip[19] = 2;
  uint8_t *udp = ip + 20;
  put16(udp, 5060); put16(udp + 2, 5080); put16(udp + 4, 8 + plen); put16(udp + 6, 0);
  memcpy(udp + 8, payload, plen);
  return o + 20 + 8 + plen;
}

static void deliver(const char *tag, uint8_t *frame, size_t n) {
  struct pcap_pkthdr hdr;
  memset(&hdr, 0, sizeof hdr);
  hdr.caplen = hdr.len = (bpf_u_int32)n;
  unsigned char idx = 0;
  type_datalink = DLT_EN10MB;
  link_offset = ETHER_HDR_LEN;
  memset(&profile_socket[0], 0, sizeof profile_socket[0]);
  env_deliveries = 0;
  callback_proto(&idx, &hdr, frame);
  printf("pcap.%s.deliveries=%u\n", tag, env_deliveries);
  printf("pcap.%s.src=%s:%u\n", tag, env_src_ip, env_src_port);
  printf("pcap.%s.dst=%s:%u\n", tag, env_dst_ip, env_dst_port);
  printf("pcap.%s.proto=%u\n", tag, env_ip_proto);
  printf("pcap.%s.mac=%s\n", tag, env_src_mac);
  printf("pcap.%s.hdr_len=%u\n", tag, env_last_hdr_len);
  printf("pcap.%s.payload_len=%u\n", tag, env_last_len);
  printf("pcap.%s.payload_head=%.8s\n", tag, (const char *)env_last_data);
}

static void sip(const char *tag, const char *msg) {
  size_t n = strlen(msg);
  char *copy = calloc(n + 1, 1);
  memcpy(copy, msg, n);
  sip_msg_t m;
  unsigned parsed = 0;
  memset(&m, 0, sizeof m);
  int ok = parse_message(copy, (unsigned)n, &parsed, &m, 1);
  printf("sip.%s.ok=%d\n", tag, ok);
  printf("sip.%s.is_request=%d\n", tag, m.isRequest);
  printf("sip.%s.method=%.*s\n", tag, m.methodString.len, m.methodString.s ? m.methodString.s : "");
  printf("sip.%s.response_code=%u\n", tag, m.responseCode);
  printf("sip.%s.callid=%.*s\n", tag, m.callId.len, m.callId.s ? m.callId.s : "");
  printf("sip.%s.cseq=%u %.*s\n", tag, m.cSeqNumber, m.cSeqMethodString.len, m.cSeqMethodString.s ? m.cSeqMethodString.s : "");
  printf("sip.%s.from_user=%.*s\n", tag, m.fromUser.len, m.fromUser.s ? m.fromUser.s : "");
  printf("sip.%s.to_user=%.*s\n", tag, m.toUser.len, m.toUser.s ? m.toUser.s : "");
  printf("sip.%s.content_length=%u\n", tag, m.contentLength);
  printf("sip.%s.has_sdp=%d\n", tag, m.hasSdp);
  free(copy);
}

int main(void) {
  uint8_t frame[512];
  size_t n;

  n = frame_udp4(frame, 0, MSG_INVITE, sizeof MSG_INVITE - 1);
  deliver("udp4", frame, n);
  n = frame_udp4(frame, 1, MSG_INVITE, sizeof MSG_INVITE - 1);
  deliver("vlan", frame, n);

  sip("invite", MSG_INVITE);
  sip("ok", MSG_OK200);
  return 0;
}
