#pragma once

#include <inttypes.h>
#include "config.h"

struct cmdline
{
    const char *config;
    unsigned int list : 1;
    unsigned int verbose : 1;
    unsigned int help : 1;
    unsigned int cli : 1;

    /* Sequence options. */
    char *clinterface;
    unsigned int clsend : 1;
    unsigned int clblock : 1;
    uint64_t clcount;
    uint64_t cltime;
    uint64_t cldelay;
    uint64_t cldata;
    unsigned int cltrackcount : 1;
    uint16_t clthreads;
    unsigned int cll4csum : 1;

    char *clsmac;
    char *cldmac;

    uint16_t clttlmin;
    uint16_t clttlmax;
    uint16_t clidmin;
    uint16_t clidmax;
    char *clsrcip;
    char *cldstip;
    char *clprotocol;
    uint8_t cltos;
    unsigned int cll3csum : 1;

    uint16_t cludpsport;
    uint16_t cludpdport;

    uint16_t cltcpsport;
    uint16_t cltcpdport;
    unsigned int cltcpsyn : 1;
    unsigned int cltcpack : 1;
    unsigned int cltcppsh : 1;
    unsigned int cltcprst : 1;
    unsigned int cltcpfin : 1;
    unsigned int cltcpurg : 1;
    unsigned int cltcpusecooked : 1;

    uint8_t clicmpcode : 1;
    uint8_t clicmptype : 1;

    uint16_t clplmin;
    uint16_t clplmax;
    unsigned int clplstatic : 1;
    char *clplexact;
    unsigned int clplfile : 1;
    unsigned int clplstring : 1;
};

void parsecmdline(int argc, char *argv[], struct cmdline *cmd);
void parsecli(struct cmdline *cmd, struct config *cfg);