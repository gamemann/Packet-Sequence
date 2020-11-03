#pragma once

#include  <inttypes.h>

#include "pcktseq.h"
#include "config.h"
#include "cmdline.h"

#define MAXPCKTLEN 0xFFFF
#define MAXTHREADS 4096

struct threadinfo
{
    const char device[MAXNAMELEN];
    struct sequence seq;
    uint16_t seqcount;
    struct cmdline cmd;
};

void seqsend(const char *interface, struct sequence seq, uint16_t seqc, struct cmdline cmd);
void seqrecv(const char interface, struct sequence seq);