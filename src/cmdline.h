#pragma once

struct cmdline
{
    const char *config;
    unsigned int global : 1;
    unsigned int verbose : 1;
    unsigned int help : 1;
};