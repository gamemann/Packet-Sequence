#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>

#include "cmdline.h"

static struct option longopts[] =
{
    {"cfg", required_argument, NULL, 'c'},
    {"global", no_argument, NULL, 'g'},
    {"verbose", no_argument, NULL, 'v'},
    {"help", no_argument, NULL, 'h'},
    {NULL, 0, NULL, 0}
};

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
        if ((c = getopt_long(argc, argv, "c:gh", longopts, NULL)) != -1)
        {
            switch (c)
            {
                case 'c':
                    cmd->config = optarg;

                    break;

                case 'g':
                    cmd->global = atoi(optarg);

                    break;

                case 'v':
                    cmd->verbose = atoi(optarg);

                    break;

                case 'h':
                    cmd->help = atoi(optarg);

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