#pragma once

#include <inttypes.h>
#include <linux/if_ether.h>

#include "pcktseq.h"

#define MAXINCLUDES 64
#define MAXSEQUENCES 256

struct eth_opt
{
    char *smac;
    char *dmac;
};

struct ip_opt
{
    // Protocol (Required).
    char *protocol;

    // Source and destination addresses (Required).
    char *srcip;
    char *dstip;

    // Type of Service.
    uint8_t tos;

    // Time to Live.
    uint8_t minttl;
    uint8_t maxttl;
    uint8_t ttl;

    // Do checksum.
    unsigned int csum : 1;
};

struct tcp_opt
{
    // TCP flags.
    unsigned int syn : 1;
    unsigned int psh : 1;
    unsigned int fin : 1;
    unsigned int ack : 1;
    unsigned int rst : 1;
    unsigned int urg : 1;

    unsigned int usetcpsocket : 1;
};

struct udp_opt
{
    uint16_t srcport;
    uint16_t dstport;
};

struct icmp_opt
{
    uint8_t code;
    uint8_t type;
};

struct payload_opt
{
    uint16_t minlen;
    uint16_t maxlen;
    uint16_t len;

    char *exact;
};

struct sequence
{
    // General options.
    unsigned int send : 1;
    unsigned int block : 1;
    uint64_t count;
    uint16_t threads;
    char *includes[MAXINCLUDES];

    // Ethernet options.
    struct eth_opt eth;

    // IP options.
    struct ip_opt ip;

    // Layer 4 options.
    struct tcp_opt tcp;
    struct udp_opt udp;
    struct icmp_opt icmp;
    unsigned int l4csum : 1;

    // Payload options.
    struct payload_opt payload;
};

struct config
{
    // Device options.
    char *interface;

    struct sequence seq[MAXSEQUENCES];
};

int parseconfig(const char filename[], struct config *cfg, int onlyseq, int *seqnum);