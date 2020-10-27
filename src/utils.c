#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>
#include <ctype.h>
#include <time.h>
#include <string.h>

#include <arpa/inet.h>

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

/**
 * Simply lower-cases a string.
 * 
 * @param str Pointer to the full string we want to lower-case.
 * @return A character pointer to the lower-cased string.
 */
char *lowerstr(char *str) 
{
    for (char *p = str; *p; p++) 
    {
        *p = tolower(*p);
    }

    return str;
}

/**
 * Chooses a random IP from a specific CIDR range.
 * 
 * @param range The range in IP/CIDR format.
 * @return The pointer to a string with the random IP within the CIDR range.
 * @note Thanks for the help on https://stackoverflow.com/questions/64542446/choosing-a-random-ip-from-any-specific-cidr-range-in-c.
 */
char *randomip(char *range, uint64_t *pcktcount)
{
    // Split the <ip>/<cidr> and assign both values.
    char *split;

    char *sip = NULL;    
    char *cidrstr = NULL;

    char *str = malloc(sizeof(char) * (strlen(range) + 1));
    strcpy(str, range);

    split = strtok(str, "/");

    for (int i = 0; i < 2; i++)
    {
        if (split == NULL)
        {
            break;
        }

        if (i == 0)
        {
            sip = strdup(split);
        }
        else
        {
            cidrstr = strdup(split);
        }
        
        split = strtok(NULL, "/");
    }

    // Free the temporary string (str).
    free(str);

    uint8_t cidr = (uint8_t) atoi(cidrstr);

    // Randomize the rand_r() seed.
    unsigned int seed = time(NULL) + (unsigned long)*pcktcount;

    // Create in_addr and convert the IP string to a 32-bit integer.
    struct in_addr inaddr;
    inet_aton(sip, &inaddr);
    uint32_t ipaddr = ntohl(inaddr.s_addr);

    // Get the mask (the complement of 2 to the power of the CIDR minus one).
    uint32_t mask = (1 << (32 - cidr)) - 1;

    // Generate a random number using rand_r(&seed).
    uint32_t randnum = rand_r(&seed);

    // Attempt to pick a random IP from the CIDR range. We shift left by the CIDR range since it's big endian. 
    uint32_t randip = (ipaddr & ~mask) | (mask & randnum);

    // Convert the new IP to a string and print it.
    struct in_addr randipstr;
    randipstr.s_addr = htonl(randip);

    return inet_ntoa(randipstr);
}