#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "pcktseq.h"
#include "config.h"
#include "cmdline.h"
#include "sequence.h"
#include "utils.h"

int main(int argc, char *argv[])
{
    // Create command line structure.
    struct cmdline cmd = {0};

    // Parse command line and store values into cmd.
    parsecmdline(argc, argv, &cmd);

    // Check if config is specified.
    if (cmd.config == NULL)
    {
        // Copy default values.
        cmd.config = "/etc/pcktseq/config.yml";

        // Let us know if we're using the default config when the verbose flag is specified.
        if (cmd.verbose)
        {
            fprintf(stdout, "No config specified. Using default: %s.\n", cmd.config);
        }
    }

    // Create config structure.
    struct config cfg = {0};
    int seqc = 0;

    // Attempt to parse config.
    parseconfig(cmd.config, &cfg, 0, &seqc);

    // Loop through each sequence found.
    for (int i = 0; i < seqc; i++)
    {
        // If this is for sending, execute sendseq().
        if (cfg.seq[i].send)
        {
            seqsend(cfg.interface, cfg.seq[i]);
        }
    }

    /*
    fprintf(stdout, "Found %d sequences.\n", seqc);

    fprintf(stdout, "Got interface => %s.\n", cfg.interface);

    fprintf(stdout, "Sequences:\n\n--------------------------\n");

    for (int i = 0; i < seqc; i++)
    {
        fprintf(stdout, "Sequence #%d:\n\n", i);

        fprintf(stdout, "Includes =>\n");

        if (cfg.seq[i].includecount > 0)
        {
            for (int j = 0; j < cfg.seq[i].includecount; j++)
            {
                fprintf(stdout, "\t- %s\n", cfg.seq[i].includes[j]);
            }
        }

        fprintf(stdout, "Send => %s\n", (cfg.seq[i].send) ? "True" : "False");
        fprintf(stdout, "Block => %s\n", (cfg.seq[i].block) ? "True" : "False");
        fprintf(stdout, "Count => %" PRIu64 "\n", cfg.seq[i].count);
        fprintf(stdout, "Threads => %" PRIu16 "\n", cfg.seq[i].threads);

        fprintf(stdout, "\n\n");
    }
    */

    // Close program successfully.
    return EXIT_SUCCESS;
}