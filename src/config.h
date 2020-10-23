#include <inttypes.h>
#include <linux/if_ether.h>

#pragma once

#define MAXINCLUDES 64

struct eth_opts
{
    uint8_t smac[ETH_ALEN];
    uint8_t dmac[ETH_ALEN];
};

struct ip_opts
{
    // Protocol (Required).
    uint8_t protocol;

    // Source and destination addresses (Required).
    const char *srcip;
    const char *dstip;

    // Type of Service.
    uint8_t tos;

    // Time to Live.
    uint8_t minttl;
    uint8_t maxttl;
    uint8_t ttl;

    // Do checksum.
    unsigned int csum : 1;
};

struct tcp_opts
{
    // TCP flags.
    unsigned int syn : 1;
    unsigned int psh : 1;
    unsigned int fin : 1;
    unsigned int ack : 1;
    unsigned int rst : 1;
    unsigned int urg : 1;
};

struct udp_opts
{
    uint16_t srcport;
    uint16_t dstport;
};

struct icmp_opts
{
    uint8_t code;
    uint8_t type;
};

struct payload_opts
{
    uint16_t minlen;
    uint16_t maxlen;
    uint16_t len;

    const char *exact;
};

struct config
{
    // Device options.
    char *interface;
};

struct sequence
{
    // General options.
    unsigned int type : 1;
    unsigned int block : 1;
    uint64_t count;
    uint16_t threads;
    const char *includes[MAXINCLUDES];

    // Ethernet options.
    struct eth_opts eth;

    // IP options.
    struct ip_opts ip;

    // Layer 4 options.
    struct tcp_opts tcp;
    struct udp_opts udp;
    struct icmp_opts icmp;
    unsigned int l4csum : 1;

    // Payload options.
    struct payload_opts payload;
};