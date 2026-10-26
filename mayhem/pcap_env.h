/*
 * The pieces of captagent that src/modules/socket/pcap/socket_pcap.c expects from the rest of the
 * daemon (config parser, action engine, globals), supplied so callback_proto() — the pcap packet
 * decoder — can be driven in-process. The upstream .c is #included (not linked) so the harness can set
 * its file-static link-layer state (type_datalink / link_offset) the way proto_collect() does.
 */
#ifndef MAYHEM_PCAP_ENV_H
#define MAYHEM_PCAP_ENV_H

#include "socket_pcap.c"

char *global_config_path = NULL;
char *global_scripts_path = NULL;
char *global_capture_plan_path = NULL;
int cfg_errors = 0;
int use_current_timestamp = 0;
char *usefile = NULL;
struct capture_list main_ct;
FILE *yyin = NULL;
int yyparse(void) { return 0; }
xml_node *xml_parse(const char *filename) { (void)filename; return NULL; }
int xml_parse_with_report(const char *filename, char *erbuf, int erlen) { (void)filename; (void)erbuf; (void)erlen; return -1; }
xml_node *xml_get(const char *key, xml_node *ref, int recurs) { (void)key; (void)ref; (void)recurs; return NULL; }
xml_node *xml_node_str(char *s, int len) { (void)s; (void)len; return NULL; }
void xml_free(xml_node *node) { (void)node; }

/* What the capture plan's actions would receive from the decoder. */
#ifdef PCAP_ENV_READ_PAYLOAD
static unsigned long env_sink;
#endif
static unsigned env_deliveries;
static uint32_t env_last_len;
static uint32_t env_last_hdr_len;
static unsigned char env_last_data[64];
static char env_src_ip[INET6_ADDRSTRLEN + 1], env_dst_ip[INET6_ADDRSTRLEN + 1], env_src_mac[24];
static uint16_t env_src_port, env_dst_port;
static uint8_t env_ip_proto;

/* The action engine: remember what the decoder delivered. The stub never reads msg->data in the fuzz
 * builds: a read here would put the crash site in harness code, and a bad msg->len/msg->data is the
 * decoder's defect, not the stub's. Only the KAT probe (PCAP_ENV_RECORD_PAYLOAD) copies the payload head, and
 * only the repro binary fuzz_socket_pcap-readpayload-standalone (PCAP_ENV_READ_PAYLOAD) reads all msg->len
 * bytes, as a downstream parser would; known-findings/ uses it for the two findings that need a reader. */
int run_actions(struct run_act_ctx *c, struct action *a, msg_t *m) {
  (void)c; (void)a;
#ifdef PCAP_ENV_READ_PAYLOAD
  {
    const volatile unsigned char *p = (const volatile unsigned char *)m->data;
    unsigned long sum = 0;
    for (uint32_t i = 0; i < m->len; i++) sum += p[i];
    env_sink += sum;
  }
#endif
  env_deliveries++;
  env_last_len = m->len;
  env_last_hdr_len = m->hdr_len;
  env_src_port = m->rcinfo.src_port;
  env_dst_port = m->rcinfo.dst_port;
  env_ip_proto = m->rcinfo.ip_proto;
  snprintf(env_src_ip, sizeof env_src_ip, "%s", m->rcinfo.src_ip ? m->rcinfo.src_ip : "");
  snprintf(env_dst_ip, sizeof env_dst_ip, "%s", m->rcinfo.dst_ip ? m->rcinfo.dst_ip : "");
  snprintf(env_src_mac, sizeof env_src_mac, "%s", m->rcinfo.src_mac ? m->rcinfo.src_mac : "");
#ifdef PCAP_ENV_RECORD_PAYLOAD
  memset(env_last_data, 0, sizeof env_last_data);
  memcpy(env_last_data, m->data, m->len < sizeof env_last_data ? m->len : sizeof env_last_data);
#endif
  return 1;
}

#endif
