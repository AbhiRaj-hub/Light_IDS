#define _GNU_SOURCE
#include "packet_processor.h"
#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>


#define ETHERTYPE_IPV4 0x0800

/* ----------------------------- Utilities ---------------------------------- */

static double now_seconds(void) {
  struct timeval tv;
  gettimeofday(&tv, NULL);
  return (double)tv.tv_sec + (double)tv.tv_usec / 1e6;
}

static void build_tcp_flags(uint8_t flags_byte, char *out, size_t outsize) {
  static const struct {
    uint8_t bit;
    char c;
  } table[] = {{0x01, 'F'}, {0x02, 'S'}, {0x04, 'R'}, {0x08, 'P'},
               {0x10, 'A'}, {0x20, 'U'}, {0x40, 'E'}, {0x80, 'C'}};
  size_t oi = 0;
  for (size_t i = 0; i < 8 && oi + 1 < outsize; i++) {
    if (flags_byte & table[i].bit)
      out[oi++] = table[i].c;
  }
  out[oi] = '\0';
}

/* ------------------------- Alert Dispatching ------------------------------ */

static void raise_alert(packet_processor_t *pp, const char *rule_id,
                        const char *rule_name, severity_t sev,
                        const char *src_ip, const char *dst_ip,
                        const char *proto, const char *description,
                        const char *mitre_attack) {
  logger_alert(pp->logger, rule_id, rule_name, sev, src_ip, dst_ip, proto,
               description, mitre_attack);

  alert_t a;
  memset(&a, 0, sizeof(a));
  strncpy(a.rule_id, rule_id, sizeof(a.rule_id) - 1);
  strncpy(a.rule_name, rule_name, sizeof(a.rule_name) - 1);
  a.severity = sev;

  if (src_ip)
    strncpy(a.src_ip, src_ip, sizeof(a.src_ip) - 1);
  if (dst_ip)
    strncpy(a.dst_ip, dst_ip, sizeof(a.dst_ip) - 1);
  if (mitre_attack)
    strncpy(a.mitre_attack, mitre_attack, sizeof(a.mitre_attack) - 1);

  strncpy(a.protocol, proto, sizeof(a.protocol) - 1);
  strncpy(a.description, description, sizeof(a.description) - 1);
  a.timestamp = now_seconds();

  alertsender_dispatch(pp->alertsender, &a);
}

static void analyze_signatures(packet_processor_t *pp,
                               const parsed_packet_t *pkt) {
  const sig_rule_t *matches[SIG_MAX_RULES];
  size_t nmatches = sigdet_inspect(pp->sigdet, pkt, matches, SIG_MAX_RULES);

  for (size_t i = 0; i < nmatches; i++) {
    const sig_rule_t *rule = matches[i];
    raise_alert(pp, rule->id, rule->name, rule->severity, pkt->src_ip,
                pkt->dst_ip, pkt->protocol, rule->description,
                rule->mitre_attack);
  }
}

static void analyze_anomalies(packet_processor_t *pp,
                              const parsed_packet_t *pkt) {
  anomaly_finding_t findings[8];
  size_t nfindings = anomdet_analyze(pp->anomdet, pkt, findings, 8);

  for (size_t i = 0; i < nfindings; i++) {
    anomaly_finding_t *f = &findings[i];
    char rule_id[48], rule_name[64];

    snprintf(rule_id, sizeof(rule_id), "ANOM-%s", f->type);
    snprintf(rule_name, sizeof(rule_name), "%s", f->type);
    for (char *p = rule_name; *p; p++)
      if (*p == '_')
        *p = ' ';

    const char *mitre = (strcmp(f->type, "port_scan") == 0) ? "T1046" : NULL;
    const char *use_src = f->src_ip[0] ? f->src_ip : pkt->src_ip;
    const char *use_dst = f->dst_ip[0] ? f->dst_ip : pkt->dst_ip;

    raise_alert(pp, rule_id, rule_name, f->severity, use_src, use_dst,
                pkt->protocol, f->detail, mitre);
  }
}

static void analyze(packet_processor_t *pp, const parsed_packet_t *pkt) {
  analyze_signatures(pp, pkt);
  analyze_anomalies(pp, pkt);
}

/* ----------------------------- Packet Parsing ----------------------------- */

static size_t get_l2_offset(int dlt) {
  switch (dlt) {
  case DLT_EN10MB:
    return 14; /* Ethernet */
  case DLT_LINUX_SLL:
    return 16; /* Linux "any" cooked capture */
  case DLT_NULL:
  case DLT_LOOP:
    return 4; /* Loopback */
  default:
    return 0; /* Unsupported */
  }
}

static void parse_tcp(const uint8_t *bytes, size_t l4_offset, uint32_t caplen,
                      parsed_packet_t *pkt) {
  if (caplen < l4_offset + 20)
    return;

  const uint8_t *tcp_hdr = bytes + l4_offset;
  strncpy(pkt->protocol, "tcp", sizeof(pkt->protocol) - 1);
  pkt->src_port = (tcp_hdr[0] << 8) | tcp_hdr[1];
  pkt->dst_port = (tcp_hdr[2] << 8) | tcp_hdr[3];

  uint8_t data_offset = (uint8_t)(((tcp_hdr[12] >> 4) & 0x0F) * 4);
  if (data_offset < 20)
    data_offset = 20;

  build_tcp_flags(tcp_hdr[13], pkt->flags, sizeof(pkt->flags));

  size_t payload_offset = l4_offset + data_offset;
  if (caplen > payload_offset) {
    pkt->payload = bytes + payload_offset;
    pkt->payload_len = caplen - payload_offset;
  }
}

static void parse_udp(const uint8_t *bytes, size_t l4_offset, uint32_t caplen,
                      parsed_packet_t *pkt) {
  if (caplen < l4_offset + 8)
    return;

  const uint8_t *udp_hdr = bytes + l4_offset;
  strncpy(pkt->protocol, "udp", sizeof(pkt->protocol) - 1);
  pkt->src_port = (udp_hdr[0] << 8) | udp_hdr[1];
  pkt->dst_port = (udp_hdr[2] << 8) | udp_hdr[3];

  size_t payload_offset = l4_offset + 8;
  if (caplen > payload_offset) {
    pkt->payload = bytes + payload_offset;
    pkt->payload_len = caplen - payload_offset;
  }
}

static void pkt_handler(u_char *user, const struct pcap_pkthdr *hdr,
                        const u_char *bytes) {
  packet_processor_t *pp = (packet_processor_t *)user;
  if (pp->stop_flag)
    return;

  int dlt = pcap_datalink(pp->pcap_handle);
  size_t l2_offset = get_l2_offset(dlt);
  if (l2_offset == 0 || hdr->caplen < l2_offset + 20)
    return;

  /* Check EtherType for Ethernet frames (ensure it's IPv4) */
  if (dlt == DLT_EN10MB) {
    uint16_t ethertype = (uint16_t)((bytes[12] << 8) | bytes[13]);
    if (ethertype != ETHERTYPE_IPV4)
      return;
  }

  const uint8_t *ip_hdr = bytes + l2_offset;
  uint8_t version_ihl = ip_hdr[0];
  uint8_t version = version_ihl >> 4;
  if (version != 4)
    return;

  uint8_t ihl = (uint8_t)((version_ihl & 0x0F) * 4);
  if (ihl < 20 || hdr->caplen < l2_offset + ihl)
    return;

  /* Populate Base Packet Data */
  parsed_packet_t pkt;
  memset(&pkt, 0, sizeof(pkt));
  pkt.timestamp = (double)hdr->ts.tv_sec + (double)hdr->ts.tv_usec / 1e6;
  pkt.src_port = -1;
  pkt.dst_port = -1;
  pkt.length = hdr->len;

  struct in_addr src_addr, dst_addr;
  memcpy(&src_addr, ip_hdr + 12, 4);
  memcpy(&dst_addr, ip_hdr + 16, 4);
  inet_ntop(AF_INET, &src_addr, pkt.src_ip, sizeof(pkt.src_ip));
  inet_ntop(AF_INET, &dst_addr, pkt.dst_ip, sizeof(pkt.dst_ip));

  if (pp->ignore_local && strncmp(pkt.src_ip, "127.", 4) == 0 &&
      strncmp(pkt.dst_ip, "127.", 4) == 0) {
    return;
  }

  /* Parse Transport Layer */
  uint8_t ip_proto = ip_hdr[9];
  size_t l4_offset = l2_offset + ihl;

  switch (ip_proto) {
  case IPPROTO_TCP:
    parse_tcp(bytes, l4_offset, hdr->caplen, &pkt);
    break;
  case IPPROTO_UDP:
    parse_udp(bytes, l4_offset, hdr->caplen, &pkt);
    break;
  case IPPROTO_ICMP:
    strncpy(pkt.protocol, "icmp", sizeof(pkt.protocol) - 1);
    break;
  default:
    strncpy(pkt.protocol, "other", sizeof(pkt.protocol) - 1);
    break;
  }

  pp->packet_count++;
  analyze(pp, &pkt);
}

/* ----------------------------- Public API --------------------------------- */

void pp_init(packet_processor_t *pp, signature_detector_t *sigdet,
             anomaly_detector_t *anomdet, alert_sender_t *alertsender,
             event_logger_t *logger, const char *interface,
             const char *bpf_filter, int ignore_local) {
  memset(pp, 0, sizeof(*pp));
  pp->sigdet = sigdet;
  pp->anomdet = anomdet;
  pp->alertsender = alertsender;
  pp->logger = logger;
  if (interface)
    strncpy(pp->interface, interface, sizeof(pp->interface) - 1);
  if (bpf_filter)
    strncpy(pp->bpf_filter, bpf_filter, sizeof(pp->bpf_filter) - 1);
  pp->ignore_local = ignore_local;
  pp->stop_flag = 0;
}

int pp_start_live_capture(packet_processor_t *pp) {
  char errbuf[PCAP_ERRBUF_SIZE];
  pp->pcap_handle = pcap_open_live(pp->interface[0] ? pp->interface : NULL,
                                   65535, 1, 1000, errbuf);
  if (!pp->pcap_handle) {
    logger_log(pp->logger, SEV_HIGH, "packet_processor",
               "pcap_open_live failed: %s", errbuf);
    return -1;
  }

  if (pp->bpf_filter[0]) {
    struct bpf_program fp;
    if (pcap_compile(pp->pcap_handle, &fp, pp->bpf_filter, 1,
                     PCAP_NETMASK_UNKNOWN) == -1) {
      logger_log(pp->logger, SEV_HIGH, "packet_processor",
                 "Failed to compile BPF filter '%s': %s", pp->bpf_filter,
                 pcap_geterr(pp->pcap_handle));
    } else {
      if (pcap_setfilter(pp->pcap_handle, &fp) == -1) {
        logger_log(pp->logger, SEV_HIGH, "packet_processor",
                   "Failed to set BPF filter: %s",
                   pcap_geterr(pp->pcap_handle));
      }
      pcap_freecode(&fp);
    }
  }

  logger_log(pp->logger, SEV_INFO, "packet_processor",
             "Starting live capture on interface=%s filter='%s'",
             pp->interface[0] ? pp->interface : "default",
             pp->bpf_filter[0] ? pp->bpf_filter : "none");

  pp->start_time = now_seconds();
  pp->stop_flag = 0;
  int rc = pcap_loop(pp->pcap_handle, -1, pkt_handler, (u_char *)pp);
  pcap_close(pp->pcap_handle);
  pp->pcap_handle = NULL;
  return (rc == -1) ? -1 : 0;
}

int pp_process_pcap_file(packet_processor_t *pp, const char *pcap_path) {
  char errbuf[PCAP_ERRBUF_SIZE];
  pp->pcap_handle = pcap_open_offline(pcap_path, errbuf);
  if (!pp->pcap_handle) {
    logger_log(pp->logger, SEV_HIGH, "packet_processor",
               "Failed to open pcap file %s: %s", pcap_path, errbuf);
    return -1;
  }

  logger_log(pp->logger, SEV_INFO, "packet_processor",
             "Replaying pcap file: %s", pcap_path);
  pp->start_time = now_seconds();
  int rc = pcap_loop(pp->pcap_handle, -1, pkt_handler, (u_char *)pp);
  pcap_close(pp->pcap_handle);
  pp->pcap_handle = NULL;

  logger_log(pp->logger, SEV_INFO, "packet_processor",
             "Finished replaying %lu packets from %s", pp->packet_count,
             pcap_path);
  return (rc == -1) ? -1 : 0;
}

void pp_stop(packet_processor_t *pp) {
  pp->stop_flag = 1;
  if (pp->pcap_handle)
    pcap_breakloop(pp->pcap_handle);
}

void pp_get_stats(packet_processor_t *pp, unsigned long *packets,
                  double *elapsed, double *pps) {
  double now = now_seconds();
  double e = now - pp->start_time;
  if (e < 1e-6)
    e = 1e-6;
  if (packets)
    *packets = pp->packet_count;
  if (elapsed)
    *elapsed = e;
  if (pps)
    *pps = (double)pp->packet_count / e;
}
