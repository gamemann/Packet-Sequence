#pragma once

struct cmdline
{
    const char *config;
    unsigned int global : 1;
    unsigned int list : 1;
    unsigned int verbose : 1;
    unsigned int help : 1;
};

void parsecmdline(int argc, char *argv[], struct cmdline *cmd);