#ifndef IDS_PACKET_TYPES_H
#define IDS_PACKET_TYPES_H

#include <cstddef>
#include <netinet/in.h>
#include <stddef.h>

#define MAX_FLAGS_LEN 10

// PAcket Structure that is planned to be created by packet processor(Will write
// in this week)
typedef struct {
  double timestamp;
  char protocol[8]; // TCP,UDP,ICMP,DHCP
  char src_ip[INET_ADDRSTRLEN];
  char dst_ip[INET_ADDRSTRLEN];
  int src_port;
  int dst_port;
  char flags[MAX_FLAGS_LEN];    // TCP flags
  const unsigned char *payload; // points to pcap packet capture
  size_t payload_len;
  size_t length;
} parsed_packet_t;

#endif
