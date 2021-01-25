#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <string.h>

#include "cmdline.h"
#include "config.h"

static struct option longopts[] =
{
    {"cfg", required_argument, NULL, 'c'},
    {"cli", no_argument, NULL, 'z'},

    /* CLI options. */
    {"interface", required_argument, NULL, 0},
    {"send", required_argument, NULL, 1},
    {"block", required_argument, NULL, 2},
    {"count", required_argument, NULL, 3},
    {"time", required_argument, NULL, 4},
    {"delay", required_argument, NULL, 5},
    {"trackcount", required_argument, NULL, 6},
    {"data", required_argument, NULL, 7},
    {"threads", required_argument, NULL, 8},
    {"l4csum", required_argument, NULL, 9},

    {"smac", required_argument, NULL, 10},
    {"dmac", required_argument, NULL, 11},

    {"minttl", required_argument, NULL, 12},
    {"maxttl", required_argument, NULL, 13},
    {"minid", required_argument, NULL, 14},
    {"maxid", required_argument, NULL, 15},
    {"srcip", required_argument, NULL, 16},
    {"dstip", required_argument, NULL, 17},
    {"protocol", required_argument, NULL, 18},
    {"tos", required_argument, NULL, 19},
    {"l3csum", required_argument, NULL, 20},

    {"usport", required_argument, NULL, 21},
    {"udport", required_argument, NULL, 22},

    {"tsport", required_argument, NULL, 23},
    {"tdport", required_argument, NULL, 24},
    {"tsyn", required_argument, NULL, 25},
    {"tack", required_argument, NULL, 26},
    {"tpsh", required_argument, NULL, 27},
    {"trst", required_argument, NULL, 28},
    {"tfin", required_argument, NULL, 29},
    {"turg", required_argument, NULL, 30},
    {"tusecooked", required_argument, NULL, 31},

    {"pmin", required_argument, NULL, 32},
    {"pmax", required_argument, NULL, 33},
    {"pstatic", required_argument, NULL, 34},
    {"pexact", required_argument, NULL, 35},
    {"pfile", required_argument, NULL, 36},
    {"pstring", required_argument, NULL, 37},

    {"list", no_argument, NULL, 'l'},
    {"verbose", no_argument, NULL, 'v'},
    {"help", no_argument, NULL, 'h'},
    {NULL, 0, NULL, 0}
};

/**
 * Parses CLI options if --cli is passed.
 * 
 * @param cmd The cmdline structure to grab the command line values from.
 * @param cfg The config structure to save the command line values to.
 * @param sequence
 * 
 * @return void
 */
void parsecli(struct cmdline *cmd, struct config *cfg)
{
    /* Parse main options. */
    if (cmd->clinterface != NULL)
    {
        cfg->interface = cmd->clinterface;
    }

    cfg->seq[0].send = cmd->clsend;
    cfg->seq[0].block = cmd->clblock;
    cfg->seq[0].count = cmd->clcount;
    cfg->seq[0].time = cmd->cltime;
    cfg->seq[0].delay = cmd->cldelay;
    cfg->seq[0].trackcount = cmd->cltrackcount;
    cfg->seq[0].maxdata = cmd->cldata;
    cfg->seq[0].threads = cmd->clthreads;
    cfg->seq[0].l4csum = cmd->cll4csum;

    cfg->seq[0].eth.smac = cmd->clsmac;
    cfg->seq[0].eth.dmac = cmd->cldmac;

    cfg->seq[0].ip.minttl = cmd->clttlmin;
    cfg->seq[0].ip.maxttl = cmd->clttlmax;
    cfg->seq[0].ip.minid = cmd->clidmin;
    cfg->seq[0].ip.maxid = cmd->clidmax;

    if (cmd->clsrcip != NULL)
    {
        // Check for range.
        if (strstr(cmd->clsrcip, "/") != NULL)
        {
            cfg->seq[0].ip.srcip = 0;
            cfg->seq[0].ip.ranges[0] = cmd->clsrcip;
        }
        else
        {
            cfg->seq[0].ip.srcip = cmd->clsrcip;
        }
    }

    if (cmd->cldstip != NULL)
    {
        cfg->seq[0].ip.dstip = cmd->cldstip;
    }

    cfg->seq[0].ip.protocol = cmd->clprotocol;
    cfg->seq[0].ip.tos = cmd->cltos;
    cfg->seq[0].ip.csum = cmd->cll3csum;

    cfg->seq[0].udp.srcport = cmd->cludpsport;
    cfg->seq[0].udp.dstport = cmd->cludpdport;

    cfg->seq[0].tcp.srcport = cmd->cltcpsport;
    cfg->seq[0].tcp.dstport = cmd->cltcpdport;
    cfg->seq[0].tcp.syn = cmd->cltcpsyn;
    cfg->seq[0].tcp.ack = cmd->cltcpack;
    cfg->seq[0].tcp.psh = cmd->cltcppsh;
    cfg->seq[0].tcp.rst = cmd->cltcprst;
    cfg->seq[0].tcp.fin = cmd->cltcpfin;
    cfg->seq[0].tcp.urg = cmd->cltcpurg;
    cfg->seq[0].tcp.usetcpsocket = cmd->cltcpusecooked;

    cfg->seq[0].icmp.code = cmd->clicmpcode;
    cfg->seq[0].icmp.type = cmd->clicmptype;

    cfg->seq[0].payload.minlen = cmd->clplmin;
    cfg->seq[0].payload.maxlen = cmd->clplmax;
    cfg->seq[0].payload.staticdata = cmd->clplstatic;

    if (cmd->clplexact != NULL)
    {
        cfg->seq[0].payload.exact = cmd->clplexact;
    }

    cfg->seq[0].payload.isfile = cmd->clplfile;
    cfg->seq[0].payload.isstring = cmd->clplstring;
}

/**
 * Parses the command line options using getopt.
 * 
 * @param argc The argument counter passed in the `int main()` function.
 * @param argv The argument array pointer passed in the `int main()` function.
 * @param cmd A pointer to the `cmdline` structure that stores all command line values.
 * @return void
 */
void parsecmdline(int argc, char *argv[], struct cmdline *cmd)
{
    int c = -1;

    while (optind < argc)
    {
        if ((c = getopt_long(argc, argv, "c:zhvl", longopts, NULL)) != -1)
        {
            switch (c)
            {
                case 'c':
                    cmd->config = optarg;

                    break;

                case 'z':
                    cmd->cli = 1;

                    break;

                /* CLI options. */
                case 0:
                    cmd->clinterface = optarg;

                    break;

                case 1:
                    cmd->clsend = atoi(optarg);

                    break;

                case 2:
                    cmd->clblock = atoi(optarg);

                    break;

                case 3:
                {
                    char *val = strdup(optarg);
                    cmd->clcount = strtoull((const char *)val, (char **)val, 0);

                    break;
                }

                case 4:
                {
                    char *val = strdup(optarg);
                    cmd->cltime = strtoull((const char *)val, (char **)val, 0);

                    break;
                }

                case 5:
                {
                    char *val = strdup(optarg);
                    cmd->cldelay = strtoull((const char *)val, (char **)val, 0);

                    break;
                }

                case 6:
                    cmd->cltrackcount = atoi(optarg);

                    break;

                case 7:
                {
                    char *val = strdup(optarg);
                    cmd->cldata = strtoull((const char *)val, (char **)val, 0);

                    break;
                }

                case 8:
                    cmd->clthreads = atoi(optarg);

                    break;

                case 9:
                    cmd->cll4csum = atoi(optarg);

                    break;

                case 10:
                    cmd->clsmac = optarg;

                    break;

                case 11:
                    cmd->cldmac = optarg;

                    break;

                case 12:
                    cmd->clttlmin = atoi(optarg);

                    break;

                case 13:
                    cmd->clttlmax = atoi(optarg);

                    break;

                case 14:
                    cmd->clidmin = atoi(optarg);

                    break;

                case 15:
                    cmd->clidmax = atoi(optarg);

                    break;

                case 16:
                    cmd->clsrcip = optarg;

                    break;

                case 17:
                    cmd->cldstip = optarg;

                    break;

                case 18:
                    cmd->clprotocol = optarg;

                    break;

                case 19:
                    cmd->cltos = atoi(optarg);

                    break;

                case 20:
                    cmd->cll3csum = atoi(optarg);

                    break;

                case 21:
                    cmd->cludpsport = atoi(optarg);

                    break;

                case 22:
                    cmd->cludpdport = atoi(optarg);

                    break;

                case 23:
                    cmd->cltcpsport = atoi(optarg);

                    break;

                case 24:
                    cmd->cltcpdport = atoi(optarg);

                    break;

                case 25:
                    cmd->cltcpsyn = atoi(optarg);

                    break;

                case 26:
                    cmd->cltcpack = atoi(optarg);

                    break;

                case 27:
                    cmd->cltcppsh = atoi(optarg);

                    break;

                case 28:
                    cmd->cltcprst = atoi(optarg);

                    break;

                case 29:
                    cmd->cltcpfin = atoi(optarg);

                    break;

                case 30:
                    cmd->cltcpurg = atoi(optarg);

                    break;

                case 31:
                    cmd->cltcpusecooked = atoi(optarg);

                    break;

                case 32:
                    cmd->clplmin = atoi(optarg);

                    break;

                case 33:
                    cmd->clplmax = atoi(optarg);

                    break;

                case 34:
                    cmd->clplstatic = atoi(optarg);

                    break;

                case 35:
                    cmd->clplexact = optarg;

                    break;

                case 36:
                    cmd->clplfile = atoi(optarg);

                    break;

                case 37:
                    cmd->clplstring = atoi(optarg);

                    break;

                case 'l':
                    cmd->list = 1;

                    break;

                case 'v':
                    cmd->verbose = 1;

                    break;

                case 'h':
                    cmd->help = 1;

                    break;

                case '?':
                    fprintf(stderr, "Missing argument.\n");

                    break;
            }
        }
        else
        {
            optind++;
        }
    }
}