#pragma once

#include  <inttypes.h>

#include "pcktseq.h"
#include "config.h"

#define MAXPCKTLEN 0xFFFF
#define MAXTHREADS 4096

struct threadinfo
{
    const char device[MAXNAMELEN];
    struct sequence seq;
    uint16_t seqcount;
};

void seqsend(const char *interface, struct sequence seq, uint16_t seqc);
void seqrecv(const char interface, struct sequence seq);