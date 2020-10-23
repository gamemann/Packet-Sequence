#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>

#pragma once

/**
 * Retrieves the Ethernet MAC of the host's default gateway and stores it in `mac` (uint8_t *).
 * 
 * @param mac The variable to store the MAC address in. Must be an uint8_t * array with the length of ETH_ALEN (6).
 * @return void
 */
void getgwmac(uint8_t *mac)
{
    char cmd[] = "ip neigh | grep \"$(ip -4 route list 0/0|cut -d' ' -f3) \"|cut -d' ' -f5|tr '[a-f]' '[A-F]'";

    FILE *fp =  popen(cmd, "r");

    if (fp != NULL)
    {
        char line[18];

        if (fgets(line, sizeof(line), fp) != NULL)
        {
            sscanf(line, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", &mac[0], &mac[1], &mac[2], &mac[3], &mac[4], &mac[5]);
        }

        pclose(fp);
    }
}

/**
 * Returns a random integer between min and max using rand_r(), a thread-safe function. 
 * 
 * @param min The minimum number to choose from.
 * @param max The maximum number to choose from.
 * @param seed The seed to pass to the rand_r() function.
 * @return A 16-bit integer (uint16_t).
 * @note If you're trying to return an integer within the 8-bit range, I'd recommend casting as uint8_t or similar.
 */
uint16_t randnum(uint16_t min, uint16_t max, unsigned int seed)
{
    return (rand_r(&seed) % (max - min + 1)) + min;
}