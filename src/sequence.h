#include "pcktseq.h"
#include "config.h"

#pragma once

#define MAXPCKTLEN 0xFFFF

struct threadinfo
{
    const char device[MAXNAMELEN];
    struct sequence seq;
};

void seqsend(const char interface, struct sequence seq);
void seqrecv(const char interface, struct sequence seq);