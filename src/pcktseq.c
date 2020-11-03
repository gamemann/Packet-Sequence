#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

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

    // Help menu.
    if (cmd.help)
    {
        fprintf(stdout, "Usage: pcktseq -c <configfile> [-v -g -h]\n\n" \
            "-c --cfg => Path to YAML file to parse.\n" \
            "-g --global => ...\n" \
            "-l --list => Print basic information about sequences.\n"
            "-v --verbose => Provide verbose output.\n" \
            "-h --help => Print out help menu and exit program.\n");

        return EXIT_SUCCESS;
    }

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

    // Check for list option.
    if (cmd.list)
    {
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
            fprintf(stdout, "Time => %" PRIu64 "\n", cfg.seq[i].time);
            fprintf(stdout, "Delay => %" PRIu64 "\n", cfg.seq[i].delay);
            fprintf(stdout, "Threads => %" PRIu16 "\n", cfg.seq[i].threads);

            fprintf(stdout, "\n\n");
        }

        return EXIT_SUCCESS;
    }

    // Loop through each sequence found.
    for (int i = 0; i < seqc; i++)
    {
        // If this is for sending, execute sendseq().
        if (cfg.seq[i].send)
        {
            seqsend(cfg.interface, cfg.seq[i], seqc);
        }
    }

   fprintf(stdout, "Completed %d sequences!\n", seqc);

    // Close program successfully.
    return EXIT_SUCCESS;
}