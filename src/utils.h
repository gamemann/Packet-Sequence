#pragma once

#include <inttypes.h>

void getgwmac(uint8_t *mac);
uint16_t randnum(uint16_t min, uint16_t max, unsigned int seed);
char *lowerstr(char *str);
char *randomip(char *range, uint64_t *pcktcount);